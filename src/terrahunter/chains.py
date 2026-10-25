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

from terrahunter import arch, clouds, deps, graph, kb, policies

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
    | {"azurerm_container_group", "google_container_node_pool"}
)
# service prefix in an IAM action → the data stores it reaches
SERVICE_SINKS = {
    "s3": {"aws_s3_bucket"},
    "dynamodb": {"aws_dynamodb_table"},
    # rds: is also the control plane of Neptune and DocumentDB (snapshots, restores, a new master password)
    "rds": {
        "aws_db_instance",
        "aws_rds_cluster",
        "aws_db_snapshot",
        "aws_db_cluster_snapshot",
        "aws_neptune_cluster",
        "aws_neptune_cluster_snapshot",
        "aws_docdb_cluster",
        "aws_docdb_cluster_snapshot",
    },
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
SENSITIVE = re.compile(
    r"financ|customer|pii|secret|cred|passw|backup|payment|card|personal|patient|payroll|billing|invoice", re.IGNORECASE
)
_ACTION = re.compile(r'"([a-z0-9-]+):([A-Za-z0-9*]+)"')
_ANY_ACTION = re.compile(r'[Aa]ctions?\\?["\']?\s*[:=]\s*\[?\s*(?:\\?["\']){1,2}\*(?:\\?["\']){1,2}')
_ANY_RESOURCE = re.compile(r'[Rr]esources?\\?["\']?\s*[:=]\s*\[?\s*(?:\\?["\']){1,2}\*(?:\\?["\']){1,2}')
_OPEN = re.compile(r"^open to internet: (.+)$")
_KEY_FILE = re.compile(r"\.pem$|(^|/)id_(rsa|ed25519|ecdsa|dsa)$|\.key$|private[-_]?key", re.IGNORECASE)
_FILESET = re.compile(r'fileset\(\s*"([^"]*)"\s*,\s*"([^"]*)"\s*\)')
_PASSWORD_LOGIN = re.compile(r"chpasswd|\bpasswd\b|PasswordAuthentication\s+yes", re.IGNORECASE)
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
    "aws_iam_role_policy_attachments_exclusive",
    "aws_iam_user_policy_attachments_exclusive",
    "aws_iam_group_policy_attachments_exclusive",
)
# an identity's own attributes that hold or name its policies (not its trust policy)
OWN_POLICIES = re.compile(r"^(inline_policy|managed_policy_arns)(\.|$)")


# --- the knowledge base: data stores beyond the built-in table, managed policies and roles by their permissions
def kb_store(rtype: str) -> bool:
    e = kb.entry(rtype)
    return rtype in SINKS or bool(e and e.get("data_store") and e.get("draw") == "component")


def kb_service(rtype: str) -> str:
    """The IAM service prefix of an AWS type, when its name starts with one the IAM data knows (aws_glacier_vault →
    glacier, aws_kms_key → kms) or its catalogue service is one (aws_instance → ec2)."""
    words = rtype.split("_")[1:]
    known = kb._actions() if rtype.startswith("aws_") else {}
    by_name = next((p for n in (2, 1) if (p := "".join(words[:n])) in known), "")
    # or the catalogue's service, when it's an IAM prefix (aws_instance's EC2 → ec2)
    svc = str((kb.entry(rtype) or {}).get("service") or "").lower().replace(" ", "")
    return by_name or (svc if svc in known else "")


def stores_of(svc: str, store_types: set[str]) -> set[str]:
    """The data store types an IAM service prefix reaches: the built-in table's, and the knowledge base's by name."""
    return SERVICE_SINKS.get(svc, set()) | {t for t in store_types if t.startswith("aws_") and kb_service(t) == svc}


def managed_services(name: str) -> set[str]:
    """The services an AWS managed policy the built-in table doesn't know reaches, from its document."""
    doc = kb.managed_policy(name)
    out: set[str] = set()
    for st in arch._list(doc.get("Statement")) if isinstance(doc, dict) else []:
        if not isinstance(st, dict) or st.get("Effect") != "Allow":
            continue
        for act in arch._list(st.get("Action")):
            out.add("*" if act == "*" else str(act).split(":")[0].lower())
        if st.get("NotAction"):  # everything but some actions (PowerUserAccess)
            out.add("*")
    return out


def role_services(perms: list[dict]) -> set[str]:
    """An Azure built-in role's data services, from its actions and data actions."""
    return {
        svc
        for p in perms
        for act in [*(p.get("actions") or []), *(p.get("data_actions") or [])]
        for rx, svc in clouds.AZURE_ACTIONS
        if rx.search(act)
    }


def gcp_services(role: str) -> set[str]:
    return {
        svc for perm in kb.gcp_role(role) or [] for prefix, svc in clouds.GCP_PERMISSIONS if perm.startswith(prefix)
    }


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
    also: list[str] = field(default_factory=list)  # other entry points into the same workload, identity and data
    within: list[str] = field(default_factory=list)  # what's stored in the data stores it reaches (objects, documents)
    controls: list[str] = field(default_factory=list)  # identities and compute it takes over beyond its steps


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
    leaks: list[Chain] = field(default_factory=list)  # if these credentials leak: one per identity, worst first

    def to_dict(self) -> dict:
        return {
            "chains": [asdict(c) for c in self.chains],
            "edges": self.edges,
            "fixes": [asdict(f) for f in self.fixes],
            "leaks": [asdict(c) for c in self.leaks],
        }


def _ports(comp: arch.Component) -> list[str]:
    for b in comp.badges:
        m = _OPEN.match(b.text)
        if m:
            return [p.strip() for p in m.group(1).split(",")]
    return []


def _port_in(port: int, rule: str) -> bool:
    """Whether a port number falls in a rule's port text ('22', '8000-8100', 'all')."""
    if rule == "all":
        return True
    lo, _, hi = rule.partition("-")
    try:
        return int(lo) <= port <= int(hi or lo)
    except ValueError:
        return False


def _host_ports(g: graph.Graph, svc: str) -> list[int] | None:
    """The host ports an ECS service's containers publish (hostPort, or containerPort in host network mode); None
    when the task definition can't be read, so nothing is ruled out."""
    out: list[int] = []
    read = False
    for e in g.edges:
        if (
            e.source != svc
            or g.resources.get(e.target) is None
            or g.resources[e.target].type != "aws_ecs_task_definition"
        ):
            continue
        td = g.resources[e.target].body
        defs = policies.document(td.get("container_definitions"), any_json=True)
        if not isinstance(defs, list):
            return None
        read = True
        host_mode = deps.unquote(td.get("network_mode")) in ("host", "awsvpc")
        for c in defs:
            for m in (c.get("portMappings") or []) if isinstance(c, dict) else []:
                hp = m.get("hostPort") if isinstance(m, dict) else None
                hp = (
                    hp
                    if hp not in (None, 0)
                    else (m.get("containerPort") if host_mode and isinstance(m, dict) else None)
                )
                if isinstance(hp, (int, float)) or str(hp).isdigit():
                    out.append(int(hp))
    return out if read else None  # read and publishing nothing: [] (no host port to reach it on)


def _has(comp: arch.Component, text: str) -> bool:
    return any(b.text == text for b in comp.badges)


def _uploaded_files(g: graph.Graph, addr: str, limit: int = 2000) -> list[str]:
    """The files a stored object uploads, by name: its `source`, or every file a `for_each = fileset(dir, pattern)`
    lists. Read from the folder the module is in, never outside the folders under analysis."""
    r = g.resources.get(addr)
    if r is None:
        return []
    base = g.module_dirs.get(r.module)
    if base is None:
        return []
    out = []
    m = _FILESET.search(str(r.body.get("for_each", "")))
    if m:
        d = (base / m.group(1).replace("${path.module}", ".").replace("${path.root}", ".")).resolve()
        allowed = [p.resolve() for p in g.dirs]
        if any(d == a or a in d.parents for a in allowed) and d.is_dir():
            pattern = m.group(2) if m.group(2) != "**" else "**/*"  # Terraform's ** is every file, pathlib's dirs
            for f in sorted(d.glob(pattern)):
                if f.is_file() and not f.is_symlink():
                    out.append(f.relative_to(d).as_posix())
                if len(out) >= limit:
                    break
    src = deps.unquote(r.body.get("source"))
    if src and "${" not in src:
        out.append(src)
    return out


_DOCKER_SOCKET = re.compile(r"/var/run/docker\.sock")
_PRIVILEGED = re.compile(r"""['"]?privileged['"]?\s*[:=]\s*true""", re.IGNORECASE)


def _host_access(g: graph.Graph, svc: str) -> str:
    """How an ECS service's containers reach their host, from its task definition: the Docker socket, a privileged
    container, or the host's process namespace; "" when they don't."""
    R = g.resources
    for e in g.edges:
        if e.source == svc and R.get(e.target) and R[e.target].type == "aws_ecs_task_definition":
            b = R[e.target].body
            text = str(b.get("container_definitions", "")) + str(b.get("volume", ""))
            if _DOCKER_SOCKET.search(text):
                return "the Docker socket is mounted into it"
            if _PRIVILEGED.search(text):
                return "a container runs privileged"
            if deps.unquote(b.get("pid_mode")) == "host":
                return "it shares the host's process namespace"
    return ""


def _stores_in(e: graph.Edge, R: dict) -> bool:
    """Whether a reference is a resource kept in the one it names (the catalogue's stores-in: an object's bucket).
    Older providers named the parent where the catalogue's (current) one takes its id: `storage_container_name` for
    `storage_container_id`."""
    for c in (kb.entry(R[e.source].type) or {}).get("connections") or []:
        attr = c.get("attr", "")
        legacy = attr.removesuffix("_id") + "_name" if attr.endswith("_id") else ""
        if c.get("meaning") == "stores-in" and (e.attr in (attr, legacy) or e.attr.startswith(f"{attr}.")):
            return R[e.target].type in (c.get("to") or [])
    return False


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
    out_e, in_e, attrs = _edges(g)
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
    # the identity's (and its groups') own inline_policy blocks and managed_policy_arns count as well
    policies += [x for x in [identity, *groups] if x in R]
    for p in policies:
        b = R[p].body
        own = p == identity or p in groups
        refs = [
            t
            for t in out_e.get(p, [])
            if R[t].type in ("aws_iam_policy", "aws_iam_policy_document")
            and (not own or any(OWN_POLICIES.search(a) for a in attrs.get((p, t), [])))
        ]
        docs = ([] if own else [p]) + refs
        docs += [t for d in refs for t in out_e.get(d, []) if R[t].type == "aws_iam_policy_document"]
        arns = [b.get("policy_arn")] + arch._list(b.get("policy_arns")) + arch._list(b.get("managed_policy_arns"))
        for arn in (deps.unquote(x) or "" for x in arns if x):
            name = arn.rsplit("/", 1)[-1] if arn.startswith("arn:") else ""
            known = managed_services(name) if name else set()
            if known:
                services |= known
                actions.append(name)
                if p not in wide:
                    wide.append(p)
        texts = [(d, str(R[d].body)) for d in docs]
        if own:
            texts += [(p, str(blk)) for blk in arch._list(b.get("inline_policy")) if isinstance(blk, dict)]
        for d, text in texts:
            if _ANY_ACTION.search(text):
                services.add("*")
                actions.append("*")
            if (_ANY_ACTION.search(text) or _ANY_RESOURCE.search(text)) and p not in wide:
                wide.append(p)
            for svc, act in _ACTION.findall(text):
                if svc in ("sts", "iam", "ec2", "lambda") or svc in SERVICE_SINKS or svc in kb._actions():
                    services.add(svc)
                if f"{svc}:{act}" not in actions:
                    actions.append(f"{svc}:{act}")
            if not _ANY_RESOURCE.search(text):
                # the stores a document names (an inline block's references are the identity's, mixed with others)
                named = (
                    out_e.get(d, [])
                    if d != p or not own
                    else [
                        t for t in out_e.get(p, []) if any(a.startswith("inline_policy") for a in attrs.get((p, t), []))
                    ]
                )
                targets |= {t for t in named if R.get(t) and kb_store(R[t].type)}
    return Grant(services, actions, targets, wide)


def _azure_grants(g: graph.Graph, principal: str) -> Grant:
    R = g.resources
    out_e, in_e, attrs = _edges(g)
    gr = Grant(set(), [], set())
    for a in in_e.get(principal, []):
        if R[a].type == "azurerm_role_assignment":
            b = R[a].body
            role = deps.unquote(b.get("role_definition_name")) or ""
            services = role_services(kb.azure_role(role) or [])
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
        services = gcp_services(role)
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
    stores = [c for c in model.components if kb_store(c.type)]
    store_types = {c.type for c in stores}

    def reach(identity: str) -> tuple[list[str], Grant]:
        gr = grants(g, identity)
        if gr.pairs:
            hit = [
                c.id
                for c in stores
                if any(
                    ("*" in svcs or any(c.type in stores_of(x, store_types) for x in svcs))
                    and (scope is None or c.id in scope)
                    for svcs, scope in gr.pairs
                )
            ]
        elif "*" in gr.services:
            hit = [c.id for c in stores]
        else:
            hit = [c.id for c in stores if any(c.type in stores_of(s, store_types) for s in gr.services)]
            if gr.targets:  # the policies name their resources: those, where they're drawn
                named = [t for t in gr.targets if t in comps]
                hit = [t for t in hit if t in named] or named
        return hit, gr

    def sensitive(cid: str) -> bool:
        c = comps[cid]
        e = kb.entry(c.type) or {}
        return c.type in SECRET_STORES or bool(e.get("sensitive_default")) or bool(SENSITIVE.search(c.name))

    def public_ip(c: arch.Component) -> bool:
        if _has(c, "public IP"):
            return True
        sub = R.get(c.parent)  # launched into a subnet that hands out public IPs
        return bool(sub and arch._bool(sub.body.get("map_public_ip_on_launch")))

    def host_exposure(svc: str) -> tuple[str, list[str]]:
        """An ECS service on EC2 is reached through its hosts' ports: (the exposed host, its open ports), or ("", [])."""
        for e in out.get(svc, []):
            if e.label != "runs on" or e.target not in comps:
                continue
            h = comps[e.target]
            lts = [
                comps[x.target]
                for x in out.get(h.id, [])
                if x.target in comps and comps[x.target].type == "aws_launch_template"
            ]
            ports = sorted({p for x in [h, *lts] for p in _ports(x)})
            published = _host_ports(g, svc)
            if published is not None and "all" not in ports:
                ports = [p for p in ports if any(_port_in(hp, p) for hp in published)]
            if ports and (public_ip(h) or any(public_ip(x) for x in lts)):
                return h.id, ports
        return "", []

    def idle_host(c: arch.Component, ports: list[str]) -> bool:
        """An ECS container host whose services publish none of its open ports: nothing listens on them (its other
        ports, such as SSH, aren't web ports here)."""
        services = [e.source for e in model.connections if e.label == "runs on" and e.target == c.id]
        if not services or any(p in ADMIN_PORTS for p in ports):
            return False
        published = [_host_ports(g, s) for s in services]
        if any(p is None for p in published):
            return False  # a task definition that can't be read: nothing is ruled out
        return not any(_port_in(hp, p) for hps in published for hp in hps for p in ports)

    def self_sign_up(pool: str) -> bool:
        """A user pool anyone can join: self sign-up isn't turned off and some client can sign them in."""
        cfg = arch._list(R[pool].body.get("admin_create_user_config"))
        admin_only = any(isinstance(x, dict) and arch._bool(x.get("allow_admin_create_user_only")) for x in cfg)
        clients = [e.source for e in g.edges if e.target == pool and R[e.source].type == "aws_cognito_user_pool_client"]
        return not admin_only and bool(clients)

    def firewall(cid: str) -> str:
        kinds = sorted({FIREWALL[R[o].type] for _, o in model.exposed.get(cid, []) if o in R and R[o].type in FIREWALL})
        return " and ".join(kinds) or "firewall"

    # what's stored in each store: the catalogue's stores-in connections (an object in its bucket, a document in its
    # database, a secret's versions)
    stored: dict[str, list[str]] = {}
    for e in g.edges:
        if e.source in R and e.target in R and e.source not in comps and _stores_in(e, R):
            stored.setdefault(e.target, []).append(e.source)

    def leaked_keys(store: str) -> list[str]:
        """Private SSH keys a public store hands out: files its objects upload (or the objects of what opens it to the
        internet, an Azure container on its account) that are private keys."""
        holders = [store, *(o for _, o in model.exposed.get(store, []))]
        objects = [x for h in holders for x in stored.get(h, [])]
        return sorted({f for x in objects for f in _uploaded_files(g, x) if _KEY_FILE.search(f)})

    def ssh_hosts(keys: list[str]) -> dict[str, list[str]]:
        """Machines that take SSH from the internet (a public IP, 22 open) and trust one of these private keys: their
        setup installs its public half (`justin.pub` for `justin.pem`) or names it as their key pair."""
        out = {}
        for c in model.components:
            if c.type in clouds.VMS and public_ip(c) and any(p in ("22", "all") for p in _ports(c)):
                text = arch.setup_text(g, c.id)
                stems = {k: k.rsplit("/", 1)[-1].rsplit(".", 1)[0] for k in keys}
                key_name = deps.unquote((R[c.id].body if c.id in R else {}).get("key_name"))
                trusted = [k for k, s in stems.items() if s and (f"{s}.pub" in text or s == key_name)]
                if trusted:
                    out[c.id] = trusted
        return out

    # --- entry points: (component, why the internet reaches it, the ports)
    entries: list[tuple[str, str]] = []
    unsure: set[str] = set()  # entries the knowledge base's test couldn't settle (a value terrahunter can't resolve)
    exposed_only: set[str] = set()  # public by the knowledge base, but not data or compute: the exposure is the path
    for c in model.components:
        b = R[c.id].body if c.id in R else {}
        ports = _ports(c)
        reasons = next((x.text.removeprefix("public: ") for x in c.badges if x.text.startswith("public: ")), "")
        maybe = next((x.text.removeprefix("possibly public: ") for x in c.badges if x.text.startswith("possibly ")), "")
        if c.type in ("aws_lb", "aws_alb", "aws_elb") and not arch._bool(b.get("internal")):
            entries.append((c.id, "internet-facing load balancer" + (f", open on {', '.join(ports)}" if ports else "")))
        elif c.type in ("azurerm_application_gateway", "azurerm_lb") and "public_ip_address_id" in str(
            b.get("frontend_ip_configuration")
        ):
            entries.append((c.id, f"internet-facing {c.tname} (a public frontend IP)"))
        elif c.type in clouds.VMS and ports and public_ip(c) and not idle_host(c, ports):
            entries.append((c.id, f"public IP, {firewall(c.id)} open to the internet on {', '.join(ports)}"))
        elif c.type == "aws_ecs_service" and host_exposure(c.id)[0]:
            host, hp = host_exposure(c.id)
            entries.append((c.id, f"runs on {comps[host].name}: public IP, open to the internet on {', '.join(hp)}"))
        elif (
            c.type == "aws_ecs_service"
            and ports
            and any(
                isinstance(n, dict) and arch._bool(n.get("assign_public_ip"))
                for n in arch._list(b.get("network_configuration"))
            )
        ):
            entries.append((c.id, f"public IP (assign_public_ip), open to the internet on {', '.join(ports)}"))
        elif c.type in clouds.WEB_APPS and deps.unquote(b.get("public_network_access_enabled")) != "false":
            entries.append((c.id, f"{c.tname} on the internet" + (", HTTP allowed" if _has(c, "HTTP allowed") else "")))
        elif (c.type in clouds.SERVERLESS or c.type in COMPUTE) and reasons:
            entries.append((c.id, f"{c.tname}: {reasons}"))
        elif c.type in ("aws_api_gateway_rest_api", "aws_apigatewayv2_api") and reasons:
            entries.append((c.id, f"public API: {reasons}"))
        elif kb_store(c.type) and reasons:
            entries.append((c.id, f"public {c.tname}: {reasons}"))
        elif c.type == "aws_cognito_user_pool" and self_sign_up(c.id):
            entries.append((c.id, "anyone can sign up (self sign-up is on, and a client lets them sign in)"))
        elif c.type == "aws_cognito_identity_pool" and arch._bool(b.get("allow_unauthenticated_identities")):
            entries.append((c.id, "anyone gets its guest role (unauthenticated identities are allowed)"))
        elif c.type in ("azurerm_kubernetes_cluster", "google_container_cluster") and clouds.public_k8s(c.type, b):
            entries.append((c.id, "Kubernetes API endpoint open to the internet"))
        elif c.type in ("aws_db_instance", "aws_rds_cluster") and _has(c, "publicly accessible") and ports:
            # publicly_accessible gives it a public address; its security group still decides who connects
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
        elif reasons and kb.curated(c.type):  # anything else the knowledge base says anyone can reach
            entries.append((c.id, f"public {c.tname}: {reasons}"))
            exposed_only.add(c.id)
        elif maybe and kb_store(c.type):  # a test the knowledge base couldn't settle: possibly public
            entries.append((c.id, f"possibly public {c.tname}: {maybe}"))
            unsure.add(c.id)

    chains: list[Chain] = []
    edges: list[dict] = []

    def add_edge(s, t, label, kind):
        if not any(e["source"] == s and e["target"] == t for e in edges):
            edges.append(
                {"id": f"x{len(edges)}", "source": s, "target": t, "label": label, "kind": kind, "quiet": False}
            )

    searched: dict[str, object] = {}
    im = None

    def search(identity: str):
        """The credentials search from an identity (what holding its credentials gives); None outside AWS, Azure and
        Google Cloud."""
        nonlocal im
        if identity not in searched:
            if identity not in R or not R[identity].type.startswith(("aws_", "azurerm_", "google_")):
                searched[identity] = None
            else:
                from terrahunter import escalate, iam

                im = im or iam.Models(g)
                searched[identity] = escalate.search(g, model, identity, im)
        return searched[identity]

    def gives_more(identity: str) -> bool:
        """Whether an identity's credentials give an attacker anything: data, another identity, or the account.
        Non-AWS identities are kept as they are."""
        r = search(identity)
        return r is None or any(a != identity for (_, a) in r.gains)

    def hostless(c: arch.Component) -> bool:
        """Compute with no machine an attacker could also take over: a function, an API, a Fargate task."""
        if c.type in APIS or c.type in clouds.SERVERLESS or c.type == "aws_lambda_function":
            return True
        b = R[c.id].body if c.id in R else {}
        return c.type == "aws_ecs_service" and deps.unquote(b.get("launch_type")) == "FARGATE"

    def can_log_in(c: arch.Component) -> bool:
        """Whether SSH or RDP open to the internet is a way in: an EC2 instance takes a login only with a key pair or
        a password its user data sets (EC2 Instance Connect needs IAM permissions the internet doesn't have)."""
        if c.type not in ("aws_instance", "aws_launch_template") or c.id not in R:
            return True  # other clouds' VMs: an admin login, or project-wide keys, are the default
        b = R[c.id].body
        return bool(b.get("key_name")) or bool(_PASSWORD_LOGIN.search(str(b.get("user_data", ""))))

    def compromise(c: arch.Component, via_lb: bool, has_role: bool) -> tuple[str, str]:
        """How an attacker gets something out of compute they reach: (the hop's text, its confidence)."""
        if c.type in APIS:
            return f"{c.id}: anyone who can call it gets what its integration does, as the role it runs as", "direct"
        ports = set(_ports(c))
        web = bool(ports & WEB_PORTS) or via_lb
        admin = [ADMIN_PORTS[p] for p in ("22", "3389", "all") if p in ports] if can_log_in(c) else []
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

    controls_of: dict[str, list[str]] = {}
    held: dict[str, list[str]] = {}  # data an identity reaches that isn't on the diagram (an administrator's documents)

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
            own = [x for x in gr.actions if comps[t].type in stores_of(x.split(":")[0].lower(), store_types)]
            add_edge(identity, t, ", ".join((own or [x for x in gr.actions if ":" not in x])[:2]) or "access", "access")
        # and what its credentials lead to beyond its own grants: roles it can become, techniques, the account
        r = search(identity)
        if r is not None:
            took = []
            for (kind, a), gn in r.gains.items():
                if kind in ("identity", "control", "admin") and a != identity:
                    took.append(a)
                    if len(took) <= 4:
                        rule = f" [{gn.rule}]" if gn.rule not in ("grant", "credentials") else ""
                        hops.append(f"with {identity}'s credentials: {gn.text}{rule}")
            if len(took) > 4:
                hops.append(f"with {identity}'s credentials: … and {len(took) - 4} more")
            data = r.data()

            # what it takes over: the identities and compute it becomes, and (as the administrator) the rest
            def is_data(a: str) -> bool:
                return kb_store(comps[a].type) if a in comps else (kb.entry(R[a].type) or {}).get("category") == "data"

            others = [a for a, lvl in data.items() if lvl == "admin" and not is_data(a)]
            held[identity] = [a for a in data if a not in comps and is_data(a)]
            controls_of[identity] = list(dict.fromkeys([a for a in took if a != "account"] + others))
            more = [a for a in data if a in comps and kb_store(comps[a].type) and a not in sinks]
            sinks = sinks + sorted(more)
        return sinks

    def drained(svc: str, host: str, role: str, hops: list[str]) -> list[str]:
        """With its host's role able to drain container instances, the cluster's other services can be pushed off
        their own hosts and on to this one, where the attacker already is."""
        if search(role) is None or not R[role].type.startswith("aws_") or im is None:
            return []
        if not any(
            im.aws.allowed(role, a) is True
            for a in ("ecs:UpdateContainerInstancesState", "ecs:DeregisterContainerInstance")
        ):
            return []
        clusters = {
            e.target for e in g.edges if e.source == svc and R.get(e.target) and R[e.target].type == "aws_ecs_cluster"
        }
        others = [
            e.source
            for e in g.edges
            if e.target in clusters
            and e.source != svc
            and e.source in comps
            and comps[e.source].type == "aws_ecs_service"
        ]
        away = [
            o
            for o in dict.fromkeys(others)
            if not any(x.label == "runs on" and x.target == host for x in out.get(o, []))
        ]
        if away:
            hops.append(
                f"{role} may drain or deregister the cluster's other container instances: their tasks "
                f"({', '.join(away)}) are rescheduled, and can land on {host}, if their placement allows it"
            )
        return away

    def reached(sinks: list[str]) -> str:
        return "reaches: " + ", ".join(t + (" ⚠sensitive" if sensitive(t) else "") for t in sinks)

    def also_text(node_id: str, other: str) -> str:
        how = "directly from the internet" if other == node_id else f"through {other}"
        return f"{node_id} is also reachable {how}"

    found: dict[tuple, Chain] = {}  # one chain per (workload, identity, data): the shortest way in wins
    for eid, why in entries:
        c = comps[eid]
        add_edge("internet", eid, "reaches", "traffic")
        base = [f"Internet → {eid}: {why}"]
        if c.type in ("aws_cognito_user_pool", "aws_cognito_identity_pool"):
            # sign up (or come as a guest), get an identity from the identity pool, act as the role it hands out
            idps = (
                [eid]
                if c.type == "aws_cognito_identity_pool"
                else [x.target for x in out.get(eid, []) if x.label == "signs in to"]
            )
            for idp in idps:
                guest = c.type == "aws_cognito_identity_pool"
                for x in out.get(idp, []):
                    if x.label != ("assumes as guest" if guest else "assumes") or x.target not in comps:
                        continue
                    role = x.target
                    steps = ["internet", *dict.fromkeys([eid, idp]), role]
                    h = [*base]
                    if not guest:
                        h.append(f"{eid} signs in to {idp}: a signed-up user gets an identity from it")
                    h.append(f"{idp} assumes {role}: the identity's credentials act as it")
                    sinks = via_identity(role, h)
                    if sinks:
                        h.append(reached(sinks))
                    kind = "internet → " + ("identity pool (guest)" if guest else "sign-up → identity pool") + " → role"
                    chains.append(
                        Chain("", kind + (" → data" if sinks else ""), "direct", f"{c.name}: {why}", steps, sinks, h)
                    )
            continue
        if kb_store(c.type):  # the data store itself is on the internet
            hops = [*base, reached([eid])]
            conf = "possible" if eid in unsure else "direct"
            sev = "critical" if conf == "direct" or sensitive(eid) else "high"
            ch = Chain(sev, "exposed data store", conf, f"{c.name}: {why}", ["internet"], [eid], hops)
            keys = leaked_keys(eid) if conf == "direct" else []
            hosts = ssh_hosts(keys) if keys else {}
            if not hosts:
                chains.append(ch)
                continue
            # it hands out SSH keys: a path to each machine that trusts one and takes SSH from anywhere
            for host, trusted in hosts.items():
                names = ", ".join(k.rsplit("/", 1)[-1] for k in trusted)
                hops = [*base, f"{eid} hands out the private key {names}, which {host} trusts; its SSH is open"]
                ch = Chain(
                    "",
                    "internet → public store → SSH key → VM",
                    "likely",
                    f"{c.name}: {why}",
                    ["internet", eid, host],
                    [eid],
                    hops,
                )
                ids = [x.target for x in out.get(host, []) if x.label == "runs as" and x.target in comps]
                own = clouds.system_identity(comps[host].type, R[host].body) if host in R else ""
                for ident in ids + ([host] if own else []):
                    if ident != host:
                        ch.steps.append(ident)
                    hops.append(
                        f"{host} runs as {own or ident}: its credentials come from the instance metadata service"
                    )
                    ch.sinks += [t for t in via_identity(ident, hops) if t not in ch.sinks]
                    ch.controls += [x for x in controls_of.get(ident, []) if x not in ch.controls and x not in ch.steps]
                hops.append(reached(ch.sinks))
                chains.append(ch)
            continue
        if eid in exposed_only and c.type not in COMPUTE and c.type not in APIS:  # a key anyone may use, a topic
            # anyone may publish to: what the internet gets is the resource itself
            sev = "critical" if sensitive(eid) else "high"
            chains.append(Chain(sev, "exposed resource", "direct", f"{c.name}: {why}", ["internet"], [eid], [*base]))
            continue
        # where the traffic goes: the entry itself, and what it routes to / fronts / invokes (two hops)
        paths = [[eid]]
        for e in out.get(eid, []):
            if e.label in ("routes to", "fronts", "invokes") and e.target in comps:
                paths.append([eid, e.target])
                paths += [[eid, e.target, e2.target] for e2 in out.get(e.target, []) if e2.label == "invokes"]
        for path in paths:
            node = comps.get(path[-1])
            if node is None or node.type not in COMPUTE and node.type not in APIS:
                continue
            roles = [x.target for x in out.get(node.id, []) if x.label == "runs as" and x.target in comps]
            # an ECS task on EC2 can also reach its host's metadata service, so the host's role is one hop further
            host_roles: dict[str, str] = {}
            for e in out.get(node.id, []) if node.type == "aws_ecs_service" else []:
                if e.label == "runs on" and e.target in comps:
                    via = [e.target] + [
                        x.target
                        for x in out.get(e.target, [])
                        if x.target in comps and comps[x.target].type == "aws_launch_template"
                    ]
                    for v in via:
                        for x in out.get(v, []):
                            if x.label == "runs as" and x.target in comps and x.target not in roles:
                                host_roles.setdefault(x.target, e.target)
            # a container that reaches its host (the Docker socket, privileged, the host's processes) has the other
            # tasks on that host too: each is a way on to its own task role
            neighbours: dict[str, tuple[str, str, str]] = {}  # task role → (its service, the host, how)
            escape = _host_access(g, node.id) if host_roles else ""
            for host in dict.fromkeys(host_roles.values()) if escape else []:
                for e in model.connections:
                    if e.label == "runs on" and e.target == host and e.source != node.id and e.source in comps:
                        for x in out.get(e.source, []):
                            if x.label == "runs as" and x.target in comps and x.target not in roles:
                                neighbours.setdefault(x.target, (e.source, host, escape))
            # an Azure workload with a system-assigned identity, or a GCP one on the default service account, is its
            # own identity: no extra step, its grants come from itself
            own = clouds.system_identity(node.type, R[node.id].body) if node.id in R else ""
            text, conf = compromise(node, len(path) > 1, bool(roles or own))
            hops = base + [
                f"{a} {next(x.label for x in out[a] if x.target == b)} {b}" for a, b in itertools.pairwise(path)
            ]
            hops.append(text)
            # what the workload touches directly (a database its configuration names, a volume attached to it)
            direct = [x.target for x in out.get(node.id, []) if x.target in comps and kb_store(comps[x.target].type)]
            for d in direct:
                add_edge(node.id, d, next(x.label for x in out[node.id] if x.target == d), "access")
            where = "the instance metadata service" if node.type in clouds.VMS else "its environment"
            for role in roles + list(host_roles) + list(neighbours) + ([node.id] if own else []) or [None]:
                h, steps, sinks = list(hops), ["internet", *path], list(direct)
                taken: list[str] = []  # services it takes over on the way
                if role in neighbours:
                    other, host, how = neighbours[role]
                    steps += [other, role]
                    h.append(
                        f"{node.id} reaches its host {host} ({how}): the other tasks there are the attacker's too, "
                        f"{other} among them, and its task role {role}"
                    )
                    sinks += [t for t in via_identity(role, h) if t not in sinks]
                elif role in host_roles:
                    steps.append(role)
                    h.append(
                        f"{node.id} runs on {host_roles[role]}: from the container, the host's instance metadata "
                        f"service gives {role} (unless the host blocks it)"
                    )
                    sinks += [t for t in via_identity(role, h) if t not in sinks]
                    if escape:
                        taken = drained(node.id, host_roles[role], role, h)
                elif role == node.id:
                    h.append(f"{node.id} runs as {own}: its credentials come from {where}")
                    sinks += [t for t in via_identity(role, h) if t not in sinks]
                elif role:
                    steps.append(role)
                    h.append(f"{node.id} runs as {role}: the identity's credentials come from {where}")
                    sinks += [t for t in via_identity(role, h) if t not in sinks]
                if sinks:
                    h.append(reached(sinks))
                elif not (role and (gives_more(role) or not hostless(node)) or "shell" in text):
                    # traffic reaches it, but nothing follows: no shell, and an identity that can do nothing that
                    # matters on compute with no host behind it (a function, an API, a Fargate task)
                    continue
                kind = " → ".join(
                    ["internet"]
                    + [comps[p].tname for p in path]
                    + (["identity"] if role else [])
                    + (["data"] if sinks else [])
                )
                key = (node.id, role, tuple(sinks))
                ch = Chain("", kind, conf, f"{c.name}: {why}", steps, sinks, h)
                ch.controls = [x for x in [*taken, *controls_of.get(role, [])] if x not in steps] if role else []
                old = found.get(key)
                if old is None:
                    found[key] = ch
                elif (CONFIDENCE[conf], len(steps)) < (CONFIDENCE[old.confidence], len(old.steps)):
                    # the likelier way in (then the shorter) is the path; the other is kept as an alternative
                    ch.also = [old.steps[1], *[x for x in old.also if x != eid]]
                    ch.hops.insert(1, also_text(node.id, old.steps[1]))
                    found[key] = ch
                elif old.steps[1] != eid and eid not in old.also:
                    old.also.append(eid)
                    old.hops.insert(1, also_text(node.id, eid))
    chains += found.values()
    # a public API with nothing behind it that the paths above follow (a mock integration, an HTTP backend outside
    # the configuration) still answers anyone who calls it: its responses are what the internet gets
    started = {ch.steps[1] for ch in chains if len(ch.steps) > 1} | {s for ch in chains for s in ch.sinks}
    for eid, why in entries:
        backend = any(e.label in ("invokes", "routes to") and e.target in comps for e in out.get(eid, []))
        if comps[eid].type in APIS and eid not in started and not backend:  # a backend was followed: it decided
            keyed = any(
                arch._bool(R[m].body.get("api_key_required"))
                for m in R
                if R[m].type == "aws_api_gateway_method" and eid in [e.target for e in g.edges if e.source == m]
            )
            conf = "possible" if keyed else "direct"
            hops = [f"Internet → {eid}: {why}"]
            if keyed:
                hops.append(f"{eid}: the method needs an API key: a leaked or shared key gets its response")
            chains.append(Chain("", "exposed API", conf, f"{comps[eid].name}: {why}", ["internet", eid], [], hops))

    for ch in chains:
        ch.within = sorted(
            {x for s in ch.sinks for x in stored.get(s, [])} | {x for s in ch.steps for x in held.get(s, [])}
        )
    for ch in chains:
        if ch.severity:
            continue
        admin = any(
            "grants" in h
            and re.search(r"AdministratorAccess|PowerUserAccess|grants \*|Owner|Contributor|roles/(owner|editor)", h)
            for h in ch.hops
        )
        if ch.sinks and (ch.confidence in ("direct", "likely") or admin or any(sensitive(s) for s in ch.sinks)):
            ch.severity = "critical"
        elif ch.sinks or admin:
            ch.severity = "high"
        else:
            ch.severity = "medium"
        ch.drawn = all(s == "internet" or s in comps for s in ch.steps + ch.sinks)
    rank = {"critical": 0, "high": 1, "medium": 2}
    chains.sort(key=lambda ch: (rank[ch.severity], CONFIDENCE[ch.confidence], -len(ch.sinks)))
    used = {s for ch in chains for s in ch.steps + ch.sinks} | {"internet"}
    edges = [e for e in edges if e["source"] in used and e["target"] in used]
    return Result(chains, edges, fixes(g, model, chains))


EFFECT = {"breaks": 0, "narrows": 1, "hardens": 2}
CONFIDENCE = {"direct": 0, "likely": 1, "possible": 2}
APIS = {"aws_api_gateway_rest_api", "aws_apigatewayv2_api"}  # an API whose integration runs as a role
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
    "aws_cognito_user_pool": "Turn off self sign-up (admin_create_user_config.allow_admin_create_user_only = true), "
    "or give signed-up users a role that reaches only what they need",
    "aws_cognito_identity_pool": "Turn off allow_unauthenticated_identities, or give the guest role nothing it doesn't need",
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
            # one fix per change to make, listing every resource it's made on (an API's unauthenticated methods)
            by_action: dict[str, list[str]] = {}
            for _, o in public:
                action = next((text for types, text in _PUBLIC_FIX if R[o].type in types), "Make it private")
                by_action.setdefault(action, []).append(o)
            for action, origins in by_action.items():
                origins = sorted(set(origins))
                add("public:" + ",".join(origins), f"{c.name}: {action}", "breaks", origins, i)
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
