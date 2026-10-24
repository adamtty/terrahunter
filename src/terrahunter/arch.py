"""Stage 3b, the architecture model: what the diagram draws, from the connection graph.

The graph has every resource and every reference; a diagram that drew them all would be unreadable. So:

- **containers**: per cloud (an AWS region, an Azure subscription, a Google Cloud project), its networks and subnets
  (AWS subnets are public when routed to an internet gateway or mapping public IPs on launch), plus areas for services
  outside any network and for identities;
- **components**: the things an architect would draw (compute, load balancers, data stores, identities), each placed
  in the container its own references put it in;
- **badges**: plumbing folded into what it affects: what the internet reaches on it (a security group, a network
  security group, a firewall rule, a database firewall rule, a public container or bucket binding: see `clouds`), a
  role's policies on the role, an access key on its user, settings worth knowing (public IP, IMDSv1, no encryption);
- **connections**: the references that mean something between components, with plumbing collapsed into them
  (instance → instance profile → role is *runs as*; load balancer → listener → target group → attachment → target is
  *routes to*);
- **unknown**: modules the analysis couldn't see (stage 2), drawn as dashed placeholders so the holes show;
- **findings** (stage 4): each scanner finding on the component it's about. One on plumbing (a security group, a
  bucket's public access block, a group's rule) goes to the components that use it, that it belongs to, or that use
  what it belongs to; one with no component (a provider block, a VPC) stays in the list not on the diagram.

What each type is, where it sits, how it connects, when it's exposed and what's risky comes from the knowledge base's
catalogue (`kb`). The built-in rules that remain compute what the catalogue leaves to terrahunter (the ports a
security group opens, the collapsed connections) or judge exposure more finely (`JUDGED`).
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from terrahunter import clouds, conditions, deps, graph, kb, policies, scanners

# how terrahunter draws the types it has its own rules for: type → (glyph, category, short name); the catalogue's
# components are drawn too, named after their service
COMPONENTS = {
    "aws_instance": ("EC2", "compute", "EC2 instance"),
    "aws_launch_template": ("LT", "compute", "launch template"),
    "aws_autoscaling_group": ("ASG", "compute", "auto scaling group"),
    "aws_lambda_function": ("λ", "compute", "Lambda function"),
    "aws_eks_cluster": ("EKS", "containers", "EKS cluster"),
    "aws_eks_node_group": ("NG", "containers", "EKS node group"),
    "aws_ecs_cluster": ("ECS", "containers", "ECS cluster"),
    "aws_ecs_service": ("SVC", "containers", "ECS service"),
    "aws_ecr_repository": ("ECR", "containers", "ECR repository"),
    "aws_elb": ("ELB", "network", "classic load balancer"),
    "aws_lb": ("ALB", "network", "load balancer"),
    "aws_alb": ("ALB", "network", "load balancer"),
    "aws_cloudfront_distribution": ("CF", "network", "CloudFront distribution"),
    "aws_api_gateway_rest_api": ("API", "integration", "API Gateway"),
    "aws_apigatewayv2_api": ("API", "integration", "API Gateway"),
    "aws_lambda_function_url": ("URL", "integration", "function URL"),
    "aws_internet_gateway": ("IGW", "network", "internet gateway"),
    "aws_nat_gateway": ("NAT", "network", "NAT gateway"),
    "aws_db_instance": ("RDS", "database", "RDS instance"),
    "aws_rds_cluster": ("RDS", "database", "Aurora cluster"),
    "aws_neptune_cluster": ("NEP", "database", "Neptune cluster"),
    "aws_dynamodb_table": ("DDB", "database", "DynamoDB table"),
    "aws_elasticache_replication_group": ("EC", "database", "ElastiCache"),
    "aws_redshift_cluster": ("RS", "analytics", "Redshift cluster"),
    "aws_elasticsearch_domain": ("ES", "analytics", "Elasticsearch domain"),
    "aws_opensearch_domain": ("OS", "analytics", "OpenSearch domain"),
    "aws_msk_cluster": ("MSK", "analytics", "MSK (Kafka) cluster"),
    "aws_kinesis_stream": ("KIN", "analytics", "Kinesis stream"),
    "aws_s3_bucket": ("S3", "storage", "S3 bucket"),
    "aws_ebs_volume": ("EBS", "storage", "EBS volume"),
    "aws_efs_file_system": ("EFS", "storage", "EFS file system"),
    "aws_sqs_queue": ("SQS", "integration", "SQS queue"),
    "aws_sns_topic": ("SNS", "integration", "SNS topic"),
    "aws_kms_key": ("KMS", "security", "KMS key"),
    "aws_secretsmanager_secret": ("SM", "security", "secret"),
    "aws_ssm_parameter": ("SSM", "security", "SSM parameter"),
    "aws_iam_role": ("ROLE", "security", "IAM role"),
    "aws_iam_user": ("USER", "security", "IAM user"),
    "aws_iam_group": ("GRP", "security", "IAM group"),
    "aws_cognito_user_pool": ("COG", "security", "Cognito user pool"),
    "aws_cognito_identity_pool": ("CID", "security", "Cognito identity pool"),
}
COMPONENTS.update(clouds.COMPONENTS)
# reference attribute → what the connection means (first match wins)
MEANING = [
    (r"user_data|(^|\.)environment|container_definitions", "configured with"),
    (r"(^|\.)subnet", "runs in"),
    (r"security_group", "guarded by"),
    (
        r"iam_instance_profile|(^|\.)role(_arn)?$|execution_role|task_role|iam_role|identity_ids|service_account",
        "runs as",
    ),
    (r"target_group|load_balancer|(^|\.)instances$|backend_address_pool|backend_http", "routes to"),
    (r"origin", "fronts"),
    (r"kms|encryption", "encrypted with"),
    (r"log(ging|_destination)", "logs to"),
    (r"volume_id|(^|\.)bucket$", "stores in"),
    (r"function_name|lambda_function_arn|(^|\.)function|lambda_config", "invokes"),
]
NOT_CONNECTIONS = re.compile(r"(^|\.)(tags(_all)?|name|description|identifier|bucket_prefix)(\.|$)")
# what the meaning of a connection says, when it isn't worth drawing all the time
QUIET = {"encrypted with", "logs to"}


@dataclass
class Badge:
    text: str
    risk: bool = False


@dataclass
class Container:
    id: str
    label: str
    kind: str  # region | area | vpc | subnet
    parent: str | None
    public: bool = False
    az: str = ""


@dataclass
class Component:
    id: str  # the resource address (module.x.aws_y.z)
    type: str
    name: str
    glyph: str
    cat: str
    tname: str
    parent: str
    file: str
    line: int
    module: str
    badges: list[Badge] = field(default_factory=list)
    unknown: bool = False
    findings: list[dict] = field(default_factory=list)


@dataclass
class Connection:
    id: str
    source: str
    target: str
    label: str
    quiet: bool = False  # drawn faint until something is selected (encryption, logging)


@dataclass
class Model:
    root: str
    containers: list[Container]
    components: list[Component]
    connections: list[Connection]
    loose: list[dict] = field(default_factory=list)  # findings not on any component
    # component → [(port or reason, the resource that opens it to the internet)], for the fixes
    exposed: dict[str, list[tuple[str, str]]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "containers": [asdict(c) for c in self.containers],
            "comps": [asdict(c) for c in self.components],
            "edges": [asdict(e) for e in self.connections],
            "loose": self.loose,
        }


def _s(v) -> str:
    u = deps.unquote(v)
    return u if u is not None else (str(v) if v is not None else "")


def _bool(v) -> bool:
    return _s(v).lower() == "true"


def _list(v) -> list:
    return v if isinstance(v, list) else ([] if v is None else [v])


def _ports(rule: dict) -> str:
    f, t = _s(rule.get("from_port")), _s(rule.get("to_port"))
    if f in ("0", "-1") and t in ("0", "65535", "-1"):
        return "all"
    return f if f == t else f"{f}-{t}"


# attributes that are a resource's own name on that type, not a link to another resource
OWN_NAME = {
    "aws_s3_bucket": "bucket",
    "aws_sqs_queue": "name",
    "aws_sns_topic": "name",
    "aws_lambda_function": "function_name",
}


def _meaning(attr: str, source_type: str = "") -> str | None:
    if NOT_CONNECTIONS.search(attr) or OWN_NAME.get(source_type) == attr:
        return None
    for rx, label in MEANING:
        if re.search(rx, attr):
            return label
    return "uses"


# --- the knowledge base's catalogue: what a type it has curated is, how it's drawn and connected, when it's exposed
# the catalogue's connection meanings, in the words the diagram and the attack paths use
KB_MEANING = {
    "runs-in": "runs in",
    "guarded-by": "guarded by",
    "runs-as": "runs as",
    "grants": "grants",
    "grants-to": "grants",
    "attached-to": "attached",
    "routes-to": "routes to",
    "fronts": "fronts",
    "encrypted-with": "encrypted with",
    "stores-in": "stores in",
    "triggers": "invokes",
    "reads": "reads",
    "writes": "writes",
    "peers-with": "peers with",
    "contains": "contains",
    "monitors": "logs to",
    "restricts": "restricts",
    "registered-in": "registered in",
    "other": "uses",
}
# meanings a connection through a hidden resource keeps (an instance → its instance profile → a role: runs as)
CARRIED = {"runs as", "routes to", "invokes", "fronts", "stores in", "reads", "writes"}
KB_CAT = {"entry": "network", "identity": "security", "management": "integration", "plumbing": "network"}
_STORAGE = re.compile(r"bucket|volume|file_system|disk|storage|vault|share|snapshot|backup|archive|glacier")
# words in a badge that make it a risk, not just worth knowing
_RISK = re.compile(
    r"internet|public|anonymous|anyone|admin|full access|any role|IMDSv1|unauthenticated|wildcard", re.IGNORECASE
)


# types whose exposure terrahunter's own rules judge, with ports, routes or the policies themselves: the catalogue's
# test for these is coarser (an RDS instance's publicly_accessible, without its security groups), so it doesn't add
JUDGED = {
    "aws_db_instance", "aws_rds_cluster", "aws_neptune_cluster", "aws_elasticsearch_domain", "aws_opensearch_domain",
    "aws_eks_cluster", "aws_lambda_function", "aws_lambda_function_url", "aws_lb", "aws_alb", "aws_elb",
    "aws_instance", "aws_launch_template", "aws_autoscaling_group", "aws_ecs_service", "aws_s3_bucket",
    "aws_sns_topic", "aws_sqs_queue", "aws_secretsmanager_secret", "aws_ecr_repository", "aws_api_gateway_rest_api",
    "aws_apigatewayv2_api", "aws_cognito_user_pool", "aws_cognito_identity_pool",
    *clouds.VMS, *clouds.WEB_APPS, *clouds.SERVERLESS, "azurerm_kubernetes_cluster", "google_container_cluster",
    "azurerm_application_gateway", "azurerm_lb", "azurerm_storage_account", "azurerm_storage_container",
    "google_storage_bucket", "google_bigquery_dataset", "google_sql_database_instance", *clouds.DB_FIREWALLS,
}  # fmt: skip


def _kb(rtype: str) -> dict:
    return kb.entry(rtype) or {}


def kb_drawn(rtype: str) -> bool:
    return _kb(rtype).get("draw") == "component"


def _kb_look(rtype: str) -> tuple[str, str, str]:
    """(glyph, category, short name) for a type the built-in table doesn't have, from its catalogue entry."""
    e = _kb(rtype)
    service = e.get("service") or rtype.split("_", 1)[-1].replace("_", " ")
    cat = e.get("category") or "unknown"
    cat = ("storage" if _STORAGE.search(rtype) else "database") if cat == "data" else KB_CAT.get(cat, cat)
    words = [w for w in re.split(r"[^A-Za-z0-9]+", service) if w]
    glyph = "".join(w[0] for w in words if w[0].isupper() or w[0].isdigit())[:3] or service[:3].upper()
    known = {w.lower() for w in words} | {"aws", "azurerm", "google", "amazon", "azure"}
    tail = [w for w in rtype.split("_")[1:] if w.lower() not in known]
    return glyph, cat, f"{service} {' '.join(tail)}".strip()


def _kb_label(e: graph.Edge, R: dict, ix: conditions.Index) -> str | None:
    """What a reference means by the source type's catalogue entry; None when the entry doesn't say."""
    for c in _kb(R[e.source].type).get("connections") or []:
        to = set(c.get("to") or [])
        if not (e.attr == c.get("attr") or e.attr.startswith(f"{c.get('attr')}.")):
            continue
        if R[e.target].type not in to and kb.canonical(R[e.target].type) not in to:
            continue
        if c.get("when") and conditions.evaluate(c["when"], e.source, ix) is False:
            continue
        return KB_MEANING.get(c.get("meaning", "other"), "uses")
    return None


def _short(when: str) -> str:
    """An exposure's prose, cut to a badge's length."""
    s = re.split(r"[:;(]", when, maxsplit=1)[0].strip().rstrip(",.")
    return s if len(s) <= 70 else s[:69].rstrip() + "…"


# an exposure that lets anyone in without credentials of the service's own (an anonymous principal, allUsers, no
# authorisation, self sign-up), as opposed to an endpoint every network can reach that still asks who's calling
_ANONYMOUS = re.compile(
    r'Principal|anonymous|anyone|allUsers|allAuthenticatedUsers|unauthenticated|"\*"|= NONE|without (auth|sign)'
    r"|public[- ](read|ACL|bucket|blob|container)|every identity|any (AWS )?account|self[- ]sign",
    re.IGNORECASE,
)


def kb_exposures(rtype: str) -> list[tuple[dict, str, bool]]:
    """(exposure, a short reason, anonymous) for each exposure the catalogue has a test for that the internet, or
    any signed-in account (an attacker's own), reaches. The reason is the badge of the risky setting with the same
    test, when there is one, else the start of the prose. Identities are left out: a long-lived key is a badge."""
    e = _kb(rtype)
    if e.get("category") == "identity":
        return []
    badges = {repr(r.get("test")): r.get("badge", "") for r in e.get("risky_settings") or [] if r.get("test")}
    out = []
    for x in e.get("exposure") or []:
        if x.get("test") and x.get("reach", "internet") in ("internet", "any-authenticated"):
            b = badges.get(repr(x["test"]), "")
            reason = b if b and "<" not in b else _short(x.get("when", ""))
            condition = x.get("when", "").split(": ", 1)[0]  # the condition, not the explanation after it
            out.append((x, reason, bool(_ANONYMOUS.search(condition))))
    return out


def kb_badges(rtype: str, addr: str, ix: conditions.Index) -> list[Badge]:
    """A badge for each of the catalogue's risky settings whose test holds (unknown ones aren't shown). Badges whose
    text terrahunter fills in itself (`open to internet: <ports>`) are left to the built-in rules."""
    out = []
    for x in _kb(rtype).get("risky_settings") or []:
        text = x.get("badge") or ""
        if text and "<" not in text and x.get("test") and conditions.evaluate(x["test"], addr, ix) is True:
            out.append(Badge(text, bool(_RISK.search(text))))
    return out


def _said(text: str, badges: list[Badge]) -> bool:
    t = text.lower()
    return any(t in b.text.lower() or b.text.lower() in t for b in badges)


def build(g: graph.Graph, findings: list[scanners.Finding] = ()) -> Model:
    R = g.resources
    ix = conditions.Index.of(g)
    out_edges: dict[str, list[graph.Edge]] = {}
    in_edges: dict[str, list[graph.Edge]] = {}
    for e in g.edges:
        out_edges.setdefault(e.source, []).append(e)
        in_edges.setdefault(e.target, []).append(e)

    def targets(addr, *types, attr=None):
        return [
            e.target
            for e in out_edges.get(addr, [])
            if e.target in R and (not types or R[e.target].type in types) and (attr is None or re.search(attr, e.attr))
        ]

    def sources(addr, *types):
        return [e.source for e in in_edges.get(addr, []) if R[e.source].type in types]

    def of(*types):
        return [a for a, r in R.items() if r.type in types and r.mode == "managed"]

    # --- containers: VPCs and subnets, public when routed to an internet gateway
    igw_tables = {
        t for rt in of("aws_route") for t in targets(rt, "aws_route_table") if targets(rt, "aws_internet_gateway")
    }
    igw_tables |= {
        t
        for t in of("aws_route_table")
        for blk in _list(R[t].body.get("route"))
        if isinstance(blk, dict) and re.search(r"aws_internet_gateway\.", str(blk.get("gateway_id", "")))
    }
    public = {
        s
        for a in of("aws_route_table_association")
        if set(targets(a, "aws_route_table")) & igw_tables
        for s in targets(a, "aws_subnet")
    }
    public |= {s for s in of("aws_subnet") if _bool(R[s].body.get("map_public_ip_on_launch"))}

    present = sorted({clouds.cloud(r.type) for r in R.values()} - {""}) or ["aws"]
    containers = []
    area = {}  # cloud → (its container, services area, identities area)
    for c in present:
        (root, root_label), (svc, svc_label), (ids, ids_label) = clouds.AREAS[c]
        containers += [
            Container(root, root_label, "region", None),
            Container(svc, svc_label, "area", root),
            Container(ids, ids_label, "area", None),
        ]
        area[c] = (root, svc, ids)

    def home(rtype: str, i: int) -> str:
        return area.get(clouds.cloud(rtype), area[present[0]])[i]

    for v in sorted(of(*clouds.NETWORKS)):
        t = R[v].type
        cidr = ", ".join(_s(x) for x in _list(R[v].body.get(clouds.NETWORK_CIDR.get(t, ""))))
        containers.append(
            Container(v, f"{clouds.NETWORKS[t]} {R[v].name}" + (f" · {cidr}" if cidr else ""), "vpc", home(t, 0))
        )
    subnet_vpc = {}
    for sn in sorted(of(*clouds.SUBNETS)):
        t = R[sn].type
        vpc = (targets(sn, *clouds.NETWORKS) or [home(t, 0)])[0]
        subnet_vpc[sn] = vpc
        az = _s(R[sn].body.get("availability_zone")).strip('"')
        if "${" in az:
            tail = re.sub(r"\$\{[^}]*\}", "", az)
            az = f"AZ {tail}" if tail else ""
        cidr = ", ".join(_s(x) for x in _list(R[sn].body.get(clouds.SUBNETS[t])))
        kind = ("Public subnet" if sn in public else "Private subnet") if t == "aws_subnet" else "Subnet"
        containers.append(
            Container(
                sn,
                f"{kind} {R[sn].name}" + (f" · {cidr}" if cidr and "${" not in cidr else ""),
                "subnet",
                vpc,
                sn in public,
                az,
            )
        )

    # --- security groups → what they open (badges on what uses them)
    sg_rules: dict[str, list[tuple[str, str, str]]] = {sg: [] for sg in of("aws_security_group")}
    for sg, rules in sg_rules.items():
        for rule in _list(R[sg].body.get("ingress")):
            if isinstance(rule, dict):
                for c in _list(rule.get("cidr_blocks")) or ["sg"]:
                    rules.append((_ports(rule), _s(c), sg))
    for r in of("aws_security_group_rule", "aws_vpc_security_group_ingress_rule"):
        b = R[r].body
        if R[r].type == "aws_security_group_rule" and _s(b.get("type")) != "ingress":
            continue
        cidrs = (
            _list(b.get("cidr_blocks")) or [b.get("cidr_ipv4")]
            if b.get("cidr_ipv4") or b.get("cidr_blocks")
            else ["sg"]
        )
        for sg in targets(r, "aws_security_group"):
            for c in cidrs:
                sg_rules[sg].append((_ports(b), _s(c), r))
    exposed, public_ips = clouds.exposure(R, targets, sources, of)
    maybe: dict[str, list[tuple[str, str]]] = {}  # possibly exposed: a test or a condition terrahunter can't settle
    for a, why in policies.aws_exposure(R, targets, sources, of, maybe).items():
        exposed.setdefault(a, []).extend(why)

    # --- the catalogue's exposures, where the built-in rules found none: on the component itself, or (for plumbing,
    # such as a listener or a bucket policy) on the components it's about. An unknown test is a possible exposure.
    drawn = {a for a, r in R.items() if r.mode == "managed" and (r.type in COMPONENTS or kb_drawn(r.type))}

    def onto(a: str) -> list[str]:
        if a in drawn:
            return [a]
        to = {t for b in _kb(R[a].type).get("badge_on") or [] for t in b.get("to") or []}
        near = [x for x in targets(a) + [e.source for e in in_edges.get(a, [])] if x in drawn]
        return sorted({x for x in near if not to or R[x].type in to or kb.canonical(R[x].type) in to})

    reachable: dict[str, set[str]] = {}  # endpoints every network reaches, that still ask who's calling
    reasoned = {c for c, v in exposed.items() if any(not (w == "all" or w[:1].isdigit()) for w, _ in v)}
    for a, r in R.items():
        if r.mode != "managed":
            continue
        for x, reason, anonymous in kb_exposures(r.type):
            v = conditions.evaluate(x["test"], a, ix)
            if v is False:
                continue
            for c in onto(a):
                if R[c].type in JUDGED:
                    continue
                if not anonymous:
                    reachable.setdefault(c, set()).add(reason)
                elif v is None:
                    maybe.setdefault(c, []).append((reason, a))
                elif c not in reasoned:
                    exposed.setdefault(c, []).append((reason, a))

    # --- components, placed by their own references
    comps: dict[str, Component] = {}
    for a, r in R.items():
        if a not in drawn:
            continue
        glyph, cat, tname = COMPONENTS.get(r.type) or _kb_look(r.type)
        subs = targets(a, *clouds.SUBNETS) + [
            s
            for via in targets(a, "aws_db_subnet_group", "azurerm_network_interface")
            for s in targets(via, *clouds.SUBNETS)
        ]
        e = _kb(r.type)  # the catalogue's placement; the built-in sets only for types it hasn't curated
        where, placement = e.get("sits_in"), e.get("placement") or []
        for pw in e.get("placement_when") or []:
            if conditions.evaluate(pw.get("test"), a, ix):
                where, placement = pw.get("sits_in", where), pw.get("placement", placement)
                break
        nets = []
        for attr in placement:  # the subnets (or networks) its placement attributes name, directly or through one
            for t in targets(a, attr=rf"^{re.escape(attr)}(\.|$)"):
                subs += [t] if R[t].type in clouds.SUBNETS else targets(t, *clouds.SUBNETS)
                nets += [t] if R[t].type in clouds.NETWORKS else []
        # subnets its placement names win over a regional default (a search domain in a VPC)
        regional = where in ("global", "account", "region") or e and where != "vpc"
        if e.get("category") == "identity" and r.type not in ("aws_cognito_user_pool", "aws_cognito_identity_pool"):
            parent = home(r.type, 2)
        elif not subs and nets and where in ("vpc", "subnet"):
            parent = nets[0]
        elif not subs and regional:
            parent = home(r.type, 1)
        elif len(set(subs)) == 1:
            parent = subs[0]
        elif subs:
            parent = subnet_vpc.get(subs[0], home(r.type, 0))
        else:
            vpc = targets(a, *clouds.NETWORKS) or [
                v for sg in targets(a, "aws_security_group") for v in targets(sg, "aws_vpc")
            ]
            parent = vpc[0] if vpc else home(r.type, 1)
        badges = []
        for sg in targets(a, "aws_security_group"):
            rules = sg_rules.get(sg, [])
            opened = sorted({(p, o) for p, c, o in rules if c in ("0.0.0.0/0", "::/0")})
            if opened:
                exposed.setdefault(a, []).extend(opened)
            elif rules:
                badges.append(Badge(f"SG {R[sg].name}: {', '.join(sorted({p for p, _, _ in rules}))}"))
        # what the internet reaches on it: ports through a firewall, or a reason (a public container, every address)
        ports = sorted({w for w, _ in exposed.get(a, []) if w == "all" or w[:1].isdigit()})
        reasons = sorted({w for w, _ in exposed.get(a, []) if w not in ports})
        if ports:
            badges.append(Badge(f"open to internet: {', '.join(ports)}", True))
        if reasons:
            badges.append(Badge(f"public: {'; '.join(reasons)}", True))
        if maybe.get(a) and not reasons:
            badges.append(Badge(f"possibly public: {'; '.join(sorted({w for w, _ in maybe[a]}))}", True))
        if reachable.get(a) and not reasons:
            badges.append(Badge("reachable from any network"))
        b = r.body
        nics = [n for n in _list(b.get("network_interfaces")) if isinstance(n, dict)]  # a launch template's
        if (
            _bool(b.get("associate_public_ip_address"))
            or a in public_ips
            or any(_bool(n.get("associate_public_ip_address")) for n in nics)
        ):
            badges.append(Badge("public IP", True))
        badges += [Badge(text, risky) for text, risky in clouds.badges(r.type, b)]
        if _bool(b.get("publicly_accessible")):
            badges.append(Badge("publicly accessible", True))
        if r.type == "aws_instance":
            mo = _list(b.get("metadata_options"))
            if not mo or not isinstance(mo[0], dict) or _s(mo[0].get("http_tokens")) != "required":
                badges.append(Badge("IMDSv1 allowed", True))
        if r.type in ("aws_db_instance", "aws_rds_cluster", "aws_neptune_cluster") and not _bool(
            b.get("storage_encrypted")
        ):
            badges.append(Badge("unencrypted"))
        if r.type == "aws_s3_bucket" and _s(b.get("acl")) in ("public-read", "public-read-write"):
            badges.append(Badge(f"ACL {_s(b.get('acl'))}", True))
        badges += [b for b in kb_badges(r.type, a, ix) if not _said(b.text, badges)]
        comps[a] = Component(a, r.type, r.name, glyph, cat, tname, parent, r.file, r.line, r.module, badges)

    # IAM plumbing as badges
    for a in of("aws_iam_access_key", "google_service_account_key"):
        for u in targets(a, "aws_iam_user", "google_service_account"):
            if u in comps:
                comps[u].badges.append(Badge("long-lived access key", True))
    for a in of(
        "aws_iam_role_policy",
        "aws_iam_user_policy",
        "aws_iam_group_policy",
        "aws_iam_role_policy_attachment",
        "aws_iam_user_policy_attachment",
        "aws_iam_group_policy_attachment",
        "aws_iam_policy_attachment",
    ):
        b = R[a].body
        arn = _s(b.get("policy_arn"))
        name = arn.rsplit("/", 1)[-1] if arn and "${" not in arn else ""
        pols = targets(a, "aws_iam_policy")
        label = name or (R[pols[0]].name if pols else R[a].name)
        doc = str(b.get("policy", "")) + "".join(str(R[p].body.get("policy", "")) for p in pols)
        risky = name == "AdministratorAccess" or bool(re.search(r'"Action"\s*:\s*"\*"|Action\s*=\s*"\*"', doc))
        for p in targets(a, "aws_iam_role", "aws_iam_user", "aws_iam_group"):
            comps[p].badges.append(Badge(label, risky))

    # the catalogue's plumbing drawn as badges (a public access block, a bucket's encryption configuration): its risky
    # settings on the components it's about, or on every one of its targets in the account for an account-wide one
    for a, r in R.items():
        if r.mode != "managed" or a in comps or _kb(r.type).get("draw") != "badge":
            continue
        found = kb_badges(r.type, a, ix)
        if not found:
            continue
        on: set[str] = set()
        for item in _kb(r.type).get("badge_on") or []:
            to = set(item.get("to") or [])
            if item.get("scope"):
                on |= {c for c in comps if comps[c].type in to}
            else:
                near = targets(a) + [e.source for e in in_edges.get(a, [])]
                on |= {c for c in near if c in comps and (comps[c].type in to or kb.canonical(comps[c].type) in to)}
        for c in sorted(on):
            comps[c].badges += [b for b in found if not _said(b.text, comps[c].badges)]

    # --- connections: meaningful references between components, with plumbing collapsed into them
    conns: dict[tuple[str, str], Connection] = {}

    def connect(s, t, label):
        if s in comps and t in comps and s != t and (s, t) not in conns:
            conns[(s, t)] = Connection(f"e{len(conns)}", s, t, label, label in QUIET)

    for e in g.edges:
        if e.source in comps and e.target in comps:
            m = _kb_label(e, R, ix) or _meaning(e.attr, R[e.source].type)
            if m:
                connect(e.source, e.target, m)
    # through the catalogue's hidden plumbing: a component → a hidden resource → a component keeps the meaning
    for e in g.edges:
        h = e.target
        if e.source not in comps or h in comps or h not in R or _kb(R[h].type).get("draw") != "hidden":
            continue
        first = _kb_label(e, R, ix)
        for e2 in out_edges.get(h, []):
            if e2.target in comps and e2.target != e.source:
                second = _kb_label(e2, R, ix)
                label = second if second in CARRIED else first if first in CARRIED else None
                if label:
                    connect(e.source, e2.target, label)
    for inst in of("aws_instance", "aws_launch_template"):
        for prof in targets(inst, "aws_iam_instance_profile"):
            for role in targets(prof, "aws_iam_role"):
                connect(inst, role, "runs as")
    for lst in of("aws_lb_listener", "aws_alb_listener"):
        for lb in targets(lst, "aws_lb", "aws_alb"):
            for tg in targets(lst, "aws_lb_target_group", "aws_alb_target_group"):
                for att in sources(tg, "aws_lb_target_group_attachment", "aws_alb_target_group_attachment"):
                    for t in targets(att, *COMPONENTS):
                        connect(lb, t, "routes to")
                for svc in sources(tg, "aws_ecs_service"):
                    connect(lb, svc, "routes to")
                for asg in sources(tg, "aws_autoscaling_group"):
                    connect(lb, asg, "routes to")
    # API Gateway: the integration is the edge from the API to what it calls
    for integ in of("aws_api_gateway_integration", "aws_apigatewayv2_integration"):
        for api in targets(integ, "aws_api_gateway_rest_api", "aws_apigatewayv2_api"):
            for t in targets(integ, *COMPONENTS):
                if t != api:
                    # an integration with credentials calls AWS as that role: the API runs as it
                    label = {"aws_lambda_function": "invokes", "aws_iam_role": "runs as"}.get(R[t].type, "routes to")
                    connect(api, t, label)
    # Cognito: a user pool signs in to the identity pools that trust it, which hand out their roles (the guest role
    # too, when unauthenticated identities are allowed)
    for idp in of("aws_cognito_identity_pool"):
        pools = targets(idp, "aws_cognito_user_pool") + [
            p for cl in targets(idp, "aws_cognito_user_pool_client") for p in targets(cl, "aws_cognito_user_pool")
        ]
        for pool in dict.fromkeys(pools):
            connect(pool, idp, "signs in to")
        for att in sources(idp, "aws_cognito_identity_pool_roles_attachment"):
            for role in targets(att, "aws_iam_role", attr=r"(^|\.)authenticated$"):
                connect(idp, role, "assumes")
            if _bool(R[idp].body.get("allow_unauthenticated_identities")):  # guests only when it lets them in
                for role in targets(att, "aws_iam_role", attr=r"unauthenticated$"):
                    connect(idp, role, "assumes as guest")
    # ECS: a service runs as its task definition's task role, and (on EC2) on the hosts of its cluster: instances or
    # launch templates whose user data joins it, or the auto scaling groups of its capacity providers
    for svc in of("aws_ecs_service"):
        for td in targets(svc, "aws_ecs_task_definition"):
            for role in targets(td, "aws_iam_role", attr=r"^task_role_arn$"):
                connect(svc, role, "runs as")
        if _s(R[svc].body.get("launch_type")) == "FARGATE":
            continue
        for cl in targets(svc, "aws_ecs_cluster"):
            hosts = sources(cl, "aws_instance", "aws_launch_template")
            for ccp in sources(cl, "aws_ecs_cluster_capacity_providers"):
                for cp in targets(ccp, "aws_ecs_capacity_provider"):
                    hosts += targets(cp, "aws_autoscaling_group")
            hosts += [asg for lt in list(hosts) for asg in sources(lt, "aws_autoscaling_group")]
            for h in dict.fromkeys(hosts):
                connect(svc, h, "runs on")
    for va in of("aws_volume_attachment"):
        for i in targets(va, "aws_instance"):
            for v in targets(va, "aws_ebs_volume"):
                connect(i, v, "attached")

    # --- unknown modules: dashed placeholders, with the references that run into them
    for addr, u in g.unknown.items():
        comps[addr] = Component(
            addr,
            "module",
            addr.rsplit(".", 1)[-1],
            "?",
            "unknown",
            f"module ({u.status})",
            "unknown",
            "",
            0,
            "",
            [Badge(u.detail[:60])],
            unknown=True,
        )
    if g.unknown:
        containers.append(Container("unknown", "Not available (see what's missing)", "area", None))
    for e in g.edges:
        if e.target in g.unknown and e.source in comps:
            connect(e.source, e.target, _meaning(e.attr) or "uses")

    # --- findings: on the component, else what uses the resource, else what it belongs to, else what uses that
    # (a security group rule → its group → the instances in the group)
    def users(x):
        return {e.source for e in in_edges.get(x, []) if e.source in comps}

    loose = []
    for f in findings:
        a = f.address
        owners = (
            [a]
            if a in comps
            else sorted(users(a))
            or sorted({t for t in targets(a) if t in comps})
            # through plumbing only: a data source or a network (everything references those) says nothing about owners
            or sorted(
                {
                    u
                    for t in targets(a)
                    if R[t].mode == "managed"
                    and R[t].type not in {*clouds.NETWORKS, *clouds.SUBNETS, "azurerm_resource_group"}
                    for u in users(t)
                }
            )
        )
        item = {k: getattr(f, k) for k in ("id", "title", "severity", "source", "file", "line", "url", "address")}
        for o in owners:
            comps[o].findings.append(item)
        if not owners:
            loose.append(item)
    for c in comps.values():
        if c.findings:
            worst = min(c.findings, key=lambda x: scanners.rank(x["severity"]))["severity"]
            n = len(c.findings)
            text = f"{n} finding{'s' if n != 1 else ''}" + (f", worst {worst.lower()}" if worst else "")
            c.badges.insert(0, Badge(text, worst in ("CRITICAL", "HIGH")))

    used = {c.parent for c in comps.values()} | {c.parent for c in containers if c.parent}
    containers = [c for c in containers if c.id in used or c.kind in ("vpc", "subnet")]
    exposed = {a: sorted(set(v)) for a, v in exposed.items() if a in comps}
    return Model(g.root, containers, list(comps.values()), list(conns.values()), loose, exposed)
