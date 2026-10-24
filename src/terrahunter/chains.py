"""Stage 5, attack paths: from the internet to the edge, and from the edge inwards, with what's wrong at each hop.

Deterministic, from the architecture model (stage 3) and its findings (stage 4):

- **entry points**: what the internet reaches directly: an internet-facing load balancer or application gateway, a
  VM with a public IP behind a security group, network security group or firewall rule open to the internet, a web
  app, a function anyone may invoke, a publicly accessible database or one whose firewall admits every address, a
  public bucket or container, a function URL with no auth, a search domain outside a VPC, and a public Kubernetes API.
  A long-lived access key or service account key is a badge, not an entry: a key that exists only in Terraform state
  isn't something an attacker can reach;
- **hops**: traffic goes where the entry *routes to*, *fronts* or *invokes*; compute it reaches can be compromised
  (how is the weakness at that hop: SSH open, IMDSv1 behind a web port, or the app itself); a compromised workload
  hands over what it *runs as* (an IAM role, a managed identity, a service account, or GCP's default compute service
  account); an identity reaches what its policies, role assignments or IAM bindings grant, by service and scope;
- **where it ends**: the data stores reachable at the end, sensitive ones marked.

A chain is kept when it reaches data, or when it compromises something exposed. Severity follows what it reaches
and how sure the hops are: `direct` (nothing to break), `likely` (a concrete weakness at every hop) or `possible`
(one hop needs a flaw in the application). Deny statements, conditions and permission boundaries aren't evaluated
yet, so a grant may be narrower than it reads.
"""

from __future__ import annotations

import itertools
import re
from dataclasses import asdict, dataclass, field

from terrahunter import arch, clouds, deps, graph

COMPUTE = (
    {
        "aws_instance",
        "aws_launch_template",
        "aws_autoscaling_group",
        "aws_lambda_function",
        "aws_ecs_service",
        "aws_eks_node_group",
    }
    | {t for t, (_, cat, _) in clouds.COMPONENTS.items() if cat == "compute"}
    | {"azurerm_container_group"}
)
# service prefix in an IAM action → the data stores it reaches
SERVICE_SINKS = {
    "s3": {"aws_s3_bucket"},
    "dynamodb": {"aws_dynamodb_table"},
    "rds": {"aws_db_instance", "aws_rds_cluster"},
    "neptune-db": {"aws_neptune_cluster"},
    "secretsmanager": {"aws_secretsmanager_secret"},
    "ssm": {"aws_ssm_parameter"},
    "es": {"aws_elasticsearch_domain", "aws_opensearch_domain"},
    "redshift": {"aws_redshift_cluster"},
    "elasticache": {"aws_elasticache_replication_group"},
    "kinesis": {"aws_kinesis_stream"},
    "sqs": {"aws_sqs_queue"},
    "ecr": {"aws_ecr_repository"},
    "sns": {"aws_sns_topic"},
    "elasticfilesystem": {"aws_efs_file_system"},
}
SERVICE_SINKS.update(clouds.SERVICE_SINKS)
SINKS = set().union(*SERVICE_SINKS.values()) | {"aws_ebs_volume"}
SECRET_STORES = {"aws_secretsmanager_secret", "aws_ssm_parameter", "azurerm_key_vault", "google_secret_manager_secret"}
FIREWALL = {  # the resource that opens a port → what to call it
    "aws_security_group": "security group",
    "aws_security_group_rule": "security group",
    "aws_vpc_security_group_ingress_rule": "security group",
    "azurerm_network_security_group": "network security group",
    "azurerm_network_security_rule": "network security group",
    "google_compute_firewall": "firewall rule",
}
# AWS managed policies by name → the services they reach ("*": everything)
MANAGED = {
    "AdministratorAccess": {"*"},
    "PowerUserAccess": {"*"},
    "ReadOnlyAccess": {"*"},
    "AmazonS3FullAccess": {"s3"},
    "AmazonS3ReadOnlyAccess": {"s3"},
    "AmazonDynamoDBFullAccess": {"dynamodb"},
    "AmazonRDSFullAccess": {"rds"},
    "SecretsManagerReadWrite": {"secretsmanager"},
    "AmazonSSMFullAccess": {"ssm"},
    "AmazonSSMReadOnlyAccess": {"ssm"},
}
SENSITIVE = re.compile(
    r"financ|customer|pii|secret|cred|passw|backup|payment|card|personal|patient|payroll|billing|invoice", re.IGNORECASE
)
_ACTION = re.compile(r'"([a-z0-9-]+):([A-Za-z0-9*]+)"')
_ANY_ACTION = re.compile(r'[Aa]ctions?\\?["\']?\s*[:=]\s*\[?\s*(?:\\?["\']){1,2}\*(?:\\?["\']){1,2}')
_ANY_RESOURCE = re.compile(r'[Rr]esources?\\?["\']?\s*[:=]\s*\[?\s*(?:\\?["\']){1,2}\*(?:\\?["\']){1,2}')
_OPEN = re.compile(r"^open to internet: (.+)$")
WEB_PORTS = {"80", "443", "8080", "8443", "all"}
ADMIN_PORTS = {"22": "SSH", "3389": "RDP", "all": "every port"}
POLICY_TYPES = (
    "aws_iam_role_policy",
    "aws_iam_user_policy",
    "aws_iam_group_policy",
    "aws_iam_role_policy_attachment",
    "aws_iam_user_policy_attachment",
    "aws_iam_group_policy_attachment",
    "aws_iam_policy_attachment",
)


@dataclass
class Chain:
    severity: str  # critical | high | medium
    kind: str
    confidence: str  # direct | likely | possible
    entry: str  # one line: how it starts
    steps: list[str]  # "internet", then component ids, in order
    sinks: list[str] = field(default_factory=list)  # the data stores it ends at
    hops: list[str] = field(default_factory=list)  # what's wrong, a line per hop (each names the ids it's about)
    drawn: bool = True
    fixes: list[str] = field(default_factory=list)  # ids of the fixes that break or weaken it


@dataclass
class Grant:
    services: set[str]  # service prefixes, or {"*"}
    actions: list[str]  # for the text: "s3:*", "AdministratorAccess"
    targets: set[str]  # resources the policies name (empty: by service, resource "*" or literal ARNs)
    wide: list[str] = field(default_factory=list)  # the policies granting on every resource (or a broad managed one)
    # Azure / GCP: (services, scope) per role assignment or binding; scope None = the whole subscription or project
    pairs: list[tuple[set[str], set[str] | None]] = field(default_factory=list)


@dataclass
class Fix:
    id: str
    action: str  # what to change, one line
    effect: str  # breaks (the path goes) | narrows (it reaches less) | hardens (a hop gets harder)
    where: list[dict]  # [{address, file, line}]: the resources to change
    chains: list[int] = field(default_factory=list)  # indexes into Result.chains
    severity: str = ""  # the worst path it affects


@dataclass
class Result:
    chains: list[Chain]
    edges: list[dict]  # extra drawn edges: internet → entry, identity → what it can access
    fixes: list[Fix] = field(default_factory=list)  # most valuable first

    def to_dict(self) -> dict:
        return {
            "chains": [asdict(c) for c in self.chains],
            "edges": self.edges,
            "fixes": [asdict(f) for f in self.fixes],
        }


def _ports(comp: arch.Component) -> list[str]:
    for b in comp.badges:
        m = _OPEN.match(b.text)
        if m:
            return [p.strip() for p in m.group(1).split(",")]
    return []


def _has(comp: arch.Component, text: str) -> bool:
    return any(b.text == text for b in comp.badges)


def _edges(g: graph.Graph) -> tuple[dict[str, list[str]], dict[str, list[str]], dict[tuple[str, str], list[str]]]:
    out_e: dict[str, list[str]] = {}
    in_e: dict[str, list[str]] = {}
    attrs: dict[tuple[str, str], list[str]] = {}
    for e in g.edges:
        out_e.setdefault(e.source, []).append(e.target)
        in_e.setdefault(e.target, []).append(e.source)
        attrs.setdefault((e.source, e.target), []).append(e.attr)
    return out_e, in_e, attrs


def grants(g: graph.Graph, identity: str) -> Grant:
    """What an identity reaches. AWS: an IAM role, user or group's policies (the services in their actions, the
    resources they name). Azure: the role assignments (and key vault access policies) of a managed identity, or of a
    workload's system-assigned one. GCP: a service account's IAM bindings, or the default compute service account."""
    R = g.resources
    kind = clouds.cloud(R[identity].type) if identity in R else ""
    if kind == "azure":
        return _azure_grants(g, identity)
    if kind == "gcp":
        return _gcp_grants(g, identity)
    out_e, in_e, _ = _edges(g)
    policies = [p for p in in_e.get(identity, []) if R[p].type in POLICY_TYPES]
    # a user's or role's groups: their policies count too
    groups = [t for t in out_e.get(identity, []) if R.get(t) and R[t].type == "aws_iam_group"]
    groups += [
        t
        for m in in_e.get(identity, [])
        if R[m].type in ("aws_iam_user_group_membership", "aws_iam_group_membership")
        for t in out_e.get(m, [])
        if R[t].type == "aws_iam_group"
    ]
    for grp in groups:
        policies += [p for p in in_e.get(grp, []) if R[p].type in POLICY_TYPES]
    services: set[str] = set()
    actions: list[str] = []
    targets: set[str] = set()
    wide: list[str] = []
    for p in policies:
        docs = [p] + [t for t in out_e.get(p, []) if R[t].type in ("aws_iam_policy", "aws_iam_policy_document")]
        docs += [t for d in docs[1:] for t in out_e.get(d, []) if R[t].type == "aws_iam_policy_document"]
        arn = deps.unquote(R[p].body.get("policy_arn")) or ""
        name = arn.rsplit("/", 1)[-1] if arn.startswith("arn:") else ""
        if name in MANAGED:
            services |= MANAGED[name]
            actions.append(name)
            wide.append(p)
        for d in docs:
            text = str(R[d].body)
            if _ANY_ACTION.search(text):
                services.add("*")
                actions.append("*")
            if (_ANY_ACTION.search(text) or _ANY_RESOURCE.search(text)) and p not in wide:
                wide.append(p)
            for svc, act in _ACTION.findall(text):
                if svc in ("sts", "iam") or svc in SERVICE_SINKS or svc in ("ec2", "lambda"):
                    services.add(svc)
                if f"{svc}:{act}" not in actions:
                    actions.append(f"{svc}:{act}")
            if not _ANY_RESOURCE.search(text):
                targets |= {t for t in out_e.get(d, []) if R.get(t) and R[t].type in SINKS}
    return Grant(services, actions, targets, wide)


def _azure_grants(g: graph.Graph, principal: str) -> Grant:
    R = g.resources
    out_e, in_e, attrs = _edges(g)
    gr = Grant(set(), [], set())
    for a in in_e.get(principal, []):
        if R[a].type == "azurerm_role_assignment":
            b = R[a].body
            role = deps.unquote(b.get("role_definition_name")) or ""
            services = set(clouds.AZURE_ROLES.get(role, set()))
            for d in out_e.get(a, []):  # a custom role: its actions
                if R[d].type == "azurerm_role_definition":
                    role = role or R[d].name
                    for perm in arch._list(R[d].body.get("permissions")):
                        for act in arch._list(perm.get("actions") if isinstance(perm, dict) else None):
                            act = deps.unquote(act) or ""
                            services |= {svc for rx, svc in clouds.AZURE_ACTIONS if rx.search(act)}
            if not services:
                continue
            scope: set[str] | None = None
            for t in out_e.get(a, []):
                if "scope" not in attrs.get((a, t), []) or R[t].mode != "managed":
                    continue  # a data source (the subscription) or no reference: the whole subscription
                if R[t].type == "azurerm_resource_group":  # what lives in the group
                    scope = {x for x in R if t in out_e.get(x, []) and "resource_group_name" in attrs.get((x, t), [])}
                else:
                    scope = {t}
            gr.pairs.append((services, scope))
            gr.services |= services
            gr.actions.append(role or "a role")
            if "*" in services:
                gr.wide.append(a)
        elif R[a].type == "azurerm_key_vault_access_policy":
            vaults = {t for t in out_e.get(a, []) if R[t].type == "azurerm_key_vault"}
            gr.pairs.append(({"azure-keyvault"}, vaults))
            gr.services.add("azure-keyvault")
            gr.actions.append("key vault access policy")
        elif R[a].type == "azurerm_key_vault" and any("access_policy" in x for x in attrs.get((a, principal), [])):
            gr.pairs.append(({"azure-keyvault"}, {a}))
            gr.services.add("azure-keyvault")
            gr.actions.append("key vault access policy")
    return gr


def _gcp_grants(g: graph.Graph, identity: str) -> Grant:
    R = g.resources
    out_e, in_e, attrs = _edges(g)
    r = R[identity]
    if r.type != "google_service_account":  # a workload on the default compute service account
        services, text = clouds.default_sa_services(r.type, r.body)
        return Grant(services, text, set(), [identity] if "*" in services else [], [(services, None)])
    gr = Grant(set(), [], set())
    for b in in_e.get(identity, []):
        on = clouds.GCP_IAM.get(R[b].type)
        if on is None:
            continue
        role = deps.unquote(R[b].body.get("role")) or ""
        services = {svc for prefix, svc in clouds.GCP_ROLES if role.startswith(prefix)}
        if not services:
            continue
        scope = None if on == "" else {t for t in out_e.get(b, []) if on in attrs.get((b, t), [])}
        gr.pairs.append((services, scope))
        gr.services |= services
        gr.actions.append(role)
        if "*" in services:
            gr.wide.append(b)
    return gr


def build(g: graph.Graph, model: arch.Model) -> Result:
    comps = {c.id: c for c in model.components}
    R = g.resources
    out: dict[str, list[arch.Connection]] = {}
    for e in model.connections:
        out.setdefault(e.source, []).append(e)
    stores = [c for c in model.components if c.type in SINKS]

    def reach(identity: str) -> tuple[list[str], Grant]:
        gr = grants(g, identity)
        if gr.pairs:
            hit = [
                c.id
                for c in stores
                if any(
                    ("*" in svcs or any(c.type in SERVICE_SINKS.get(x, ()) for x in svcs))
                    and (scope is None or c.id in scope)
                    for svcs, scope in gr.pairs
                )
            ]
        elif "*" in gr.services:
            hit = [c.id for c in stores]
        else:
            hit = [c.id for c in stores if any(c.type in SERVICE_SINKS.get(s, ()) for s in gr.services)]
            if gr.targets:  # the policies name their resources: those, where they're drawn
                named = [t for t in gr.targets if t in comps]
                hit = [t for t in hit if t in named] or named
        return hit, gr

    def sensitive(cid: str) -> bool:
        c = comps[cid]
        return c.type in SECRET_STORES or bool(SENSITIVE.search(c.name))

    def public_ip(c: arch.Component) -> bool:
        if _has(c, "public IP"):
            return True
        sub = R.get(c.parent)  # launched into a subnet that hands out public IPs
        return bool(sub and arch._bool(sub.body.get("map_public_ip_on_launch")))

    def firewall(cid: str) -> str:
        kinds = sorted({FIREWALL[R[o].type] for _, o in model.exposed.get(cid, []) if o in R and R[o].type in FIREWALL})
        return " and ".join(kinds) or "firewall"

    # --- entry points: (component, why the internet reaches it, the ports)
    entries: list[tuple[str, str]] = []
    for c in model.components:
        b = R[c.id].body if c.id in R else {}
        ports = _ports(c)
        reasons = next((x.text.removeprefix("public: ") for x in c.badges if x.text.startswith("public: ")), "")
        if c.type in ("aws_lb", "aws_alb", "aws_elb") and not arch._bool(b.get("internal")):
            entries.append((c.id, "internet-facing load balancer" + (f", open on {', '.join(ports)}" if ports else "")))
        elif c.type in ("azurerm_application_gateway", "azurerm_lb") and "public_ip_address_id" in str(
            b.get("frontend_ip_configuration")
        ):
            entries.append((c.id, f"internet-facing {c.tname} (a public frontend IP)"))
        elif c.type in clouds.VMS and ports and public_ip(c):
            entries.append((c.id, f"public IP, {firewall(c.id)} open to the internet on {', '.join(ports)}"))
        elif c.type in clouds.WEB_APPS and deps.unquote(b.get("public_network_access_enabled")) != "false":
            entries.append((c.id, f"{c.tname} on the internet" + (", HTTP allowed" if _has(c, "HTTP allowed") else "")))
        elif (c.type in clouds.SERVERLESS or c.type in COMPUTE) and reasons:
            entries.append((c.id, f"{c.tname}: {reasons}"))
        elif c.type in ("aws_api_gateway_rest_api", "aws_apigatewayv2_api") and reasons:
            entries.append((c.id, f"public API: {reasons}"))
        elif c.type in SINKS and reasons:
            entries.append((c.id, f"public {c.tname}: {reasons}"))
        elif c.type in ("azurerm_kubernetes_cluster", "google_container_cluster") and clouds.public_k8s(c.type, b):
            entries.append((c.id, "Kubernetes API endpoint open to the internet"))
        elif c.type in ("aws_db_instance", "aws_rds_cluster") and _has(c, "publicly accessible"):
            entries.append((c.id, "publicly accessible database" + (f", open on {', '.join(ports)}" if ports else "")))
        elif c.type == "aws_s3_bucket" and any(b.text.startswith("ACL public") for b in c.badges):
            entries.append((c.id, "bucket ACL makes it public"))
        elif c.type in ("aws_elasticsearch_domain", "aws_opensearch_domain") and not b.get("vpc_options"):
            entries.append((c.id, "search domain outside a VPC: its endpoint is on the internet"))
        elif c.type == "aws_lambda_function_url" and deps.unquote(b.get("authorization_type")) == "NONE":
            entries.append((c.id, "function URL with no authentication"))
        elif c.type == "aws_eks_cluster":
            vc = arch._list(b.get("vpc_config"))
            pub = not vc or not isinstance(vc[0], dict) or deps.unquote(vc[0].get("endpoint_public_access")) != "false"
            if pub:
                entries.append((c.id, "Kubernetes API endpoint open to the internet"))

    chains: list[Chain] = []
    edges: list[dict] = []

    def add_edge(s, t, label, kind):
        if not any(e["source"] == s and e["target"] == t for e in edges):
            edges.append(
                {"id": f"x{len(edges)}", "source": s, "target": t, "label": label, "kind": kind, "quiet": False}
            )

    def compromise(c: arch.Component, via_lb: bool, has_role: bool) -> tuple[str, str]:
        """How an attacker gets something out of compute they reach: (the hop's text, its confidence)."""
        ports = set(_ports(c))
        web = bool(ports & WEB_PORTS) or via_lb
        admin = [ADMIN_PORTS[p] for p in ("22", "3389", "all") if p in ports]
        if has_role and web and _has(c, "IMDSv1 allowed"):
            return (
                f"{c.id}: serves the web with IMDSv1 allowed: one SSRF in the app hands over its credentials",
                "likely",
            )
        if admin:
            return f"{c.id}: {' and '.join(admin)} open to the internet: a weak or leaked key gets a shell", "possible"
        if c.type == "aws_lambda_function":
            return (
                f"{c.id}: runs what the request sends it: an injection flaw in the function runs as its role",
                "possible",
            )
        return f"{c.id}: reachable by traffic: a flaw in the application gets code running here", "possible"

    def via_identity(identity: str, hops: list[str]) -> list[str]:
        """What an identity reaches, with its grant (and the access edges) added to the chain."""
        sinks, gr = reach(identity)
        if gr.actions:
            if gr.pairs:
                whole = clouds.cloud(R[identity].type) == "azure" and "the subscription" or "the project"
                scope = whole if any(sc is None for _, sc in gr.pairs) else "the resources it's scoped to"
            else:
                scope = "the resources it names" if gr.targets and "*" not in gr.services else "every resource"
            more = " …" if len(gr.actions) > 6 else ""
            hops.append(f"{identity} grants {', '.join(gr.actions[:6])}{more} on {scope}")
        for t in sinks:  # each edge names the actions for that store's service
            own = [x for x in gr.actions if comps[t].type in SERVICE_SINKS.get(x.split(":")[0], ())]
            add_edge(identity, t, ", ".join((own or [x for x in gr.actions if ":" not in x])[:2]) or "access", "access")
        return sinks

    def reached(sinks: list[str]) -> str:
        return "reaches: " + ", ".join(t + (" ⚠sensitive" if sensitive(t) else "") for t in sinks)

    found: dict[tuple, Chain] = {}  # one chain per (workload, identity, data): the shortest way in wins
    for eid, why in entries:
        c = comps[eid]
        add_edge("internet", eid, "reaches", "traffic")
        base = [f"Internet → {eid}: {why}"]
        if c.type in SINKS:  # the data store itself is on the internet
            hops = [*base, reached([eid])]
            chains.append(
                Chain("critical", "exposed data store", "direct", f"{c.name}: {why}", ["internet"], [eid], hops)
            )
            continue
        # where the traffic goes: the entry itself, and what it routes to / fronts / invokes (two hops)
        paths = [[eid]]
        for e in out.get(eid, []):
            if e.label in ("routes to", "fronts", "invokes") and e.target in comps:
                paths.append([eid, e.target])
                paths += [[eid, e.target, e2.target] for e2 in out.get(e.target, []) if e2.label == "invokes"]
        for path in paths:
            node = comps.get(path[-1])
            if node is None or node.type not in COMPUTE:
                continue
            roles = [x.target for x in out.get(node.id, []) if x.label == "runs as" and x.target in comps]
            # an Azure workload with a system-assigned identity, or a GCP one on the default service account, is its
            # own identity: no extra step, its grants come from itself
            own = clouds.system_identity(node.type, R[node.id].body) if node.id in R else ""
            text, conf = compromise(node, len(path) > 1, bool(roles or own))
            hops = base + [
                f"{a} {next(x.label for x in out[a] if x.target == b)} {b}" for a, b in itertools.pairwise(path)
            ]
            hops.append(text)
            # what the workload touches directly (a database its configuration names, a volume attached to it)
            direct = [x.target for x in out.get(node.id, []) if x.target in comps and comps[x.target].type in SINKS]
            for d in direct:
                add_edge(node.id, d, next(x.label for x in out[node.id] if x.target == d), "access")
            where = "the instance metadata service" if node.type in clouds.VMS else "its environment"
            for role in roles + ([node.id] if own else []) or [None]:
                h, steps, sinks = list(hops), ["internet", *path], list(direct)
                if role == node.id:
                    h.append(f"{node.id} runs as {own}: its credentials come from {where}")
                    sinks += [t for t in via_identity(role, h) if t not in sinks]
                elif role:
                    steps.append(role)
                    h.append(f"{node.id} runs as {role}: the identity's credentials come from {where}")
                    sinks += [t for t in via_identity(role, h) if t not in sinks]
                if sinks:
                    h.append(reached(sinks))
                elif not (role or "shell" in text):
                    continue  # traffic reaches it, but nothing follows
                kind = " → ".join(
                    ["internet"]
                    + [comps[p].tname for p in path]
                    + (["identity"] if role else [])
                    + (["data"] if sinks else [])
                )
                key = (node.id, role, tuple(sinks))
                ch = Chain("", kind, conf, f"{c.name}: {why}", steps, sinks, h)
                if key not in found or len(steps) < len(found[key].steps):
                    if key in found:
                        ch.hops.insert(1, f"{node.id} is also reachable through {found[key].steps[1]}")
                    found[key] = ch
                elif found[key].steps[1] != eid:
                    found[key].hops.insert(1, f"{node.id} is also reachable through {eid}")
    chains += found.values()

    for ch in chains:
        if ch.severity:
            continue
        admin = any(
            "grants" in h
            and re.search(r"AdministratorAccess|PowerUserAccess|grants \*|Owner|Contributor|roles/(owner|editor)", h)
            for h in ch.hops
        )
        if ch.sinks and (ch.confidence == "likely" or admin or any(sensitive(s) for s in ch.sinks)):
            ch.severity = "critical"
        elif ch.sinks or admin:
            ch.severity = "high"
        else:
            ch.severity = "medium"
        ch.drawn = all(s == "internet" or s in comps for s in ch.steps + ch.sinks)
    rank = {"critical": 0, "high": 1, "medium": 2}
    chains.sort(
        key=lambda ch: (rank[ch.severity], {"direct": 0, "likely": 1, "possible": 2}[ch.confidence], -len(ch.sinks))
    )
    used = {s for ch in chains for s in ch.steps + ch.sinks} | {"internet"}
    edges = [e for e in edges if e["source"] in used and e["target"] in used]
    return Result(chains, edges, fixes(g, model, chains))


EFFECT = {"breaks": 0, "narrows": 1, "hardens": 2}
_PUBLIC_FIX = [  # the resource that makes something public → what to change there
    (clouds.DB_FIREWALLS, "Remove the firewall rule that admits every address (use private endpoints)"),
    ({"azurerm_storage_container"}, 'Set container_access_type = "private"'),
    ({"google_sql_database_instance"}, "Remove 0.0.0.0/0 from authorized_networks (or turn off the public IP)"),
    ({"google_bigquery_dataset"}, "Remove the allUsers / allAuthenticatedUsers access entry"),
    (set(clouds.GCP_IAM), "Remove allUsers / allAuthenticatedUsers from the IAM binding"),
    (
        {"aws_s3_bucket_policy", "aws_s3_bucket"},
        'Remove the statement that allows Principal "*" (or pin it with a condition); turn on S3 Block Public Access',
    ),
    (
        {
            "aws_sns_topic_policy",
            "aws_sqs_queue_policy",
            "aws_secretsmanager_secret_policy",
            "aws_ecr_repository_policy",
            "aws_sns_topic",
            "aws_sqs_queue",
            "aws_secretsmanager_secret",
            "aws_ecr_repository",
        },
        'Remove the statement that allows Principal "*", or pin it to the accounts or sources that need it',
    ),
    ({"aws_lambda_permission"}, 'Give the permission a specific principal and a source_arn / source_account, not "*"'),
    (
        {"aws_api_gateway_method", "aws_apigatewayv2_route"},
        "Put an authorizer on it (IAM, Cognito or a Lambda authorizer)",
    ),
]


def _owner_name(g: graph.Graph, origin: str) -> str:
    """What to call the resource that opens a port: a separate rule goes by the group it belongs to."""
    R = g.resources
    if R[origin].type in (
        "aws_security_group_rule",
        "aws_vpc_security_group_ingress_rule",
        "azurerm_network_security_rule",
    ):
        groups = [
            e.target
            for e in g.edges
            if e.source == origin
            and R.get(e.target)
            and R[e.target].type in ("aws_security_group", "azurerm_network_security_group")
        ]
        if groups:
            return R[groups[0]].name
    return R[origin].name


def _scope_fix(x: arch.Component, own: str) -> str:
    if "default compute service account" in own:
        return f"Give {x.name} its own service account with only the roles it needs (not the default one)"
    if clouds.cloud(x.type) == "azure":
        return f"Scope {x.name}'s role assignments to the roles and resources it needs"
    if clouds.cloud(x.type) == "gcp":
        return f"Grant {x.name} narrower roles than project-wide owner / editor"
    return f"Scope {x.name}'s policies to the actions and resources it needs"


_ENTRY_FIX = {  # entry type → (what to change, the attribute it's about)
    "aws_db_instance": "Set publicly_accessible = false (reach it from inside the VPC)",
    "aws_rds_cluster": "Set publicly_accessible = false on its instances (reach them from inside the VPC)",
    "aws_s3_bucket": "Remove the public ACL and turn on S3 Block Public Access",
    "aws_elasticsearch_domain": "Put the domain in a VPC (vpc_options) and restrict its access policy",
    "aws_opensearch_domain": "Put the domain in a VPC (vpc_options) and restrict its access policy",
    "aws_lambda_function_url": 'Set authorization_type = "AWS_IAM"',
    "aws_eks_cluster": "Turn off endpoint_public_access, or limit public_access_cidrs to known ranges",
}


def fixes(g: graph.Graph, model: arch.Model, chains: list[Chain]) -> list[Fix]:
    """The changes that break or weaken the paths, each with where to make it, most valuable first: the worst path
    it touches, then whether it removes the path, then how many paths."""
    comps = {c.id: c for c in model.components}
    R = g.resources
    found: dict[str, Fix] = {}

    def where(*addrs: str) -> list[dict]:
        return [{"address": a, "file": R[a].file, "line": R[a].line} for a in dict.fromkeys(addrs) if a in R]

    def add(fid: str, action: str, effect: str, addrs: list[str], i: int) -> None:
        f = found.setdefault(fid, Fix(fid, action, effect, where(*addrs)))
        if i not in f.chains:
            f.chains.append(i)
        if fid not in chains[i].fixes:
            chains[i].fixes.append(fid)

    for i, ch in enumerate(chains):
        entry = ch.steps[1] if len(ch.steps) > 1 else ch.sinks[0]
        c = comps.get(entry)
        if c is None:
            continue
        exposed = model.exposed.get(entry, [])
        opened = [(p, o) for p, o in exposed if o in R and R[o].type in FIREWALL]
        public = [(w, o) for w, o in exposed if o in R and R[o].type not in FIREWALL]
        if c.type in clouds.VMS and opened:  # one fix per set of rules: instances sharing a group share it
            ports = ", ".join(sorted({p for p, _ in opened}))
            ports = "every port" if ports == "all" else ports
            origins = sorted({o for _, o in opened})
            kinds = sorted({FIREWALL[R[o].type] for o in origins})
            names = ", ".join(sorted({_owner_name(g, o) for o in origins}))
            add(
                "close:" + ",".join(origins),
                f"Close {ports} to the internet in {' / '.join(kinds)} {names}",
                "breaks",
                origins,
                i,
            )
        elif public:
            for _, o in public:
                action = next((text for types, text in _PUBLIC_FIX if R[o].type in types), "Make it private")
                add(f"public:{o}", f"{c.name}: {action}", "breaks", [o], i)
        elif c.type in _ENTRY_FIX:
            add(f"public:{entry}", f"{c.name}: {_ENTRY_FIX[c.type]}", "breaks", [entry], i)
        for s in ch.steps[1:]:
            x = comps.get(s)
            if x is None:
                continue
            if x.type in COMPUTE and _has(x, "IMDSv1 allowed") and ch.confidence == "likely":
                add(
                    f"imds:{s}",
                    f'Require IMDSv2 on {x.name}: metadata_options {{ http_tokens = "required" }}',
                    "hardens",
                    [s],
                    i,
                )
            own = clouds.system_identity(x.type, R[s].body) if s in R else ""
            if (x.cat == "security" or own) and ch.sinks:
                wide = grants(g, s).wide
                if wide:
                    add(f"scope:{s}", _scope_fix(x, own), "narrows", wide, i)
    rank = {"critical": 0, "high": 1, "medium": 2}
    for f in found.values():
        f.severity = min((chains[i].severity for i in f.chains), key=rank.__getitem__)
    return sorted(found.values(), key=lambda f: (rank[f.severity], EFFECT[f.effect], -len(f.chains), f.id))
