"""Stage 5, attack paths: from the internet to the edge, and from the edge inwards, with what's wrong at each hop.

Deterministic, from the architecture model (stage 3) and its findings (stage 4):

- **entry points**: what the internet reaches directly: an internet-facing load balancer, an instance with a public
  IP behind a security group open to the internet, a publicly accessible database, a public bucket, a function URL
  with no auth, a search domain outside a VPC, a public Kubernetes API, and a long-lived access key (anyone who has
  it can use it from anywhere);
- **hops**: traffic goes where the entry *routes to*, *fronts* or *invokes*; compute it reaches can be compromised
  (how is the weakness at that hop: SSH open, IMDSv1 behind a web port, or the app itself); a compromised workload
  hands over what it *runs as*; an identity reaches what its policies grant;
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

from terrahunter import arch, deps, graph

COMPUTE = {
    "aws_instance",
    "aws_launch_template",
    "aws_autoscaling_group",
    "aws_lambda_function",
    "aws_ecs_service",
    "aws_eks_node_group",
}
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
    "elasticfilesystem": {"aws_efs_file_system"},
}
SINKS = set().union(*SERVICE_SINKS.values()) | {"aws_ebs_volume"}
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


@dataclass
class Grant:
    services: set[str]  # service prefixes, or {"*"}
    actions: list[str]  # for the text: "s3:*", "AdministratorAccess"
    targets: set[str]  # resources the policies name (empty: by service, resource "*" or literal ARNs)


@dataclass
class Result:
    chains: list[Chain]
    edges: list[dict]  # extra drawn edges: internet → entry, identity → what it can access

    def to_dict(self) -> dict:
        return {"chains": [asdict(c) for c in self.chains], "edges": self.edges}


def _ports(comp: arch.Component) -> list[str]:
    for b in comp.badges:
        m = _OPEN.match(b.text)
        if m:
            return [p.strip() for p in m.group(1).split(",")]
    return []


def _has(comp: arch.Component, text: str) -> bool:
    return any(b.text == text for b in comp.badges)


def grants(g: graph.Graph, identity: str) -> Grant:
    """What an IAM role, user or group's policies reach: the services in their actions, and the resources they name."""
    R = g.resources
    out_e: dict[str, list[str]] = {}
    in_e: dict[str, list[str]] = {}
    for e in g.edges:
        out_e.setdefault(e.source, []).append(e.target)
        in_e.setdefault(e.target, []).append(e.source)
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
    for p in policies:
        docs = [p] + [t for t in out_e.get(p, []) if R[t].type in ("aws_iam_policy", "aws_iam_policy_document")]
        docs += [t for d in docs[1:] for t in out_e.get(d, []) if R[t].type == "aws_iam_policy_document"]
        arn = deps.unquote(R[p].body.get("policy_arn")) or ""
        name = arn.rsplit("/", 1)[-1] if arn.startswith("arn:") else ""
        if name in MANAGED:
            services |= MANAGED[name]
            actions.append(name)
        for d in docs:
            text = str(R[d].body)
            if _ANY_ACTION.search(text):
                services.add("*")
                actions.append("*")
            for svc, act in _ACTION.findall(text):
                if svc in ("sts", "iam") or svc in SERVICE_SINKS or svc in ("ec2", "lambda"):
                    services.add(svc)
                if f"{svc}:{act}" not in actions:
                    actions.append(f"{svc}:{act}")
            if not _ANY_RESOURCE.search(text):
                targets |= {t for t in out_e.get(d, []) if R.get(t) and R[t].type in SINKS}
    return Grant(services, actions, targets)


def build(g: graph.Graph, model: arch.Model) -> Result:
    comps = {c.id: c for c in model.components}
    R = g.resources
    out: dict[str, list[arch.Connection]] = {}
    for e in model.connections:
        out.setdefault(e.source, []).append(e)
    stores = [c for c in model.components if c.type in SINKS]

    def reach(identity: str) -> tuple[list[str], Grant]:
        gr = grants(g, identity)
        if "*" in gr.services:
            hit = [c.id for c in stores]
        else:
            hit = [c.id for c in stores if any(c.type in SERVICE_SINKS.get(s, ()) for s in gr.services)]
            if gr.targets:  # the policies name their resources: those, where they're drawn
                named = [t for t in gr.targets if t in comps]
                hit = [t for t in hit if t in named] or named
        return hit, gr

    def sensitive(cid: str) -> bool:
        c = comps[cid]
        return c.type in ("aws_secretsmanager_secret", "aws_ssm_parameter") or bool(SENSITIVE.search(c.name))

    def public_ip(c: arch.Component) -> bool:
        if _has(c, "public IP"):
            return True
        sub = R.get(c.parent)  # launched into a subnet that hands out public IPs
        return bool(sub and arch._bool(sub.body.get("map_public_ip_on_launch")))

    # --- entry points: (component, why the internet reaches it, the ports)
    entries: list[tuple[str, str]] = []
    for c in model.components:
        b = R[c.id].body if c.id in R else {}
        ports = _ports(c)
        if c.type in ("aws_lb", "aws_alb", "aws_elb") and not arch._bool(b.get("internal")):
            entries.append((c.id, "internet-facing load balancer" + (f", open on {', '.join(ports)}" if ports else "")))
        elif c.type in ("aws_instance",) and ports and public_ip(c):
            entries.append((c.id, f"public IP, security group open to the internet on {', '.join(ports)}"))
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
        elif c.type == "aws_iam_user" and _has(c, "long-lived access key"):
            entries.append((c.id, "long-lived access key: whoever holds it can use it from anywhere"))

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
        if c.type == "aws_iam_user":
            hops = list(base)
            sinks = via_identity(eid, hops)
            if sinks:
                hops.append(reached(sinks))
                chains.append(
                    Chain("", "leaked key → data", "possible", f"{c.name}: {why}", ["internet", eid], sinks, hops)
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
            text, conf = compromise(node, len(path) > 1, bool(roles))
            hops = base + [
                f"{a} {next(x.label for x in out[a] if x.target == b)} {b}" for a, b in itertools.pairwise(path)
            ]
            hops.append(text)
            # what the workload touches directly (a database its configuration names, a volume attached to it)
            direct = [x.target for x in out.get(node.id, []) if x.target in comps and comps[x.target].type in SINKS]
            for d in direct:
                add_edge(node.id, d, next(x.label for x in out[node.id] if x.target == d), "access")
            for role in roles or [None]:
                h, steps, sinks = list(hops), ["internet", *path], list(direct)
                if role:
                    steps.append(role)
                    where = "the instance metadata service" if node.type != "aws_lambda_function" else "its environment"
                    h.append(f"{node.id} runs as {role}: the role's credentials come from {where}")
                    sinks += [t for t in via_identity(role, h) if t not in sinks]
                if sinks:
                    h.append(reached(sinks))
                elif not (role or "shell" in text):
                    continue  # traffic reaches it, but nothing follows
                kind = " → ".join(
                    ["internet"]
                    + [comps[p].tname for p in path]
                    + (["role"] if role else [])
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
        admin = any("grants" in h and re.search(r"AdministratorAccess|PowerUserAccess|grants \*", h) for h in ch.hops)
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
    return Result(chains, edges)
