"""An estate: every root of a folder (often several repositories) analysed as one.

Each root is read on its own, as always, then its graph goes into one estate graph under the root's name, as if
the root were an instance of a module: `module.root["data-vault/prod"].aws_s3_bucket.research`. Everything that
understands module prefixes (references, the IAM model's lookups, plan addresses) works unchanged, and a policy in
one root that names another root's resource by its ARN reaches it. `link` (rules for remote state, lookups by name
and accounts) joins the roots where the configuration names another root's resources indirectly.
"""

from __future__ import annotations

import re
from dataclasses import replace

from terrahunter import graph

_TAG = re.compile(r'^module\.root\["((?:[^"\\]|\\.)*)"\]\.?')
_ANY_TAG = re.compile(r'module\.root\["((?:[^"\\]|\\.)*)"\]\.')


def tag(root: str) -> str:
    """The module-like prefix a root's resources get in the estate graph."""
    return 'module.root["' + root.replace("\\", "\\\\").replace('"', '\\"') + '"]'


def root_of(addr: str) -> str:
    """The root an estate address belongs to ("" outside an estate)."""
    m = _TAG.match(addr)
    return m.group(1).replace('\\"', '"').replace("\\\\", "\\") if m else ""


def local(addr: str) -> str:
    """An estate address without its root: as the root's own code names it."""
    return _TAG.sub("", addr, count=1)


def label(addr: str) -> str:
    """An estate address for people: `data-vault/prod: aws_s3_bucket.research`."""
    r = root_of(addr)
    return f"{r}: {local(addr)}" if r else addr


def shown(text: str) -> str:
    """Text with every estate address in it as people read it (`data-vault/prod: aws_s3_bucket.research`)."""
    return _ANY_TAG.sub(lambda m: m.group(1).replace('\\"', '"').replace("\\\\", "\\") + ": ", text)


def account_of(g: graph.Graph) -> str:
    """The account (AWS) or project (Google Cloud) a root deploys into, where its code says; "" when it doesn't."""
    from terrahunter import escalate

    own = sorted(escalate.own_accounts(g))
    if len(own) == 1:
        return own[0]
    projects = {
        str(r.body.get("project", "")).strip('"')
        for r in g.resources.values()
        if r.type.startswith("google_") and r.body.get("project") and "${" not in str(r.body.get("project"))
    }
    return f"gcp:{projects.pop()}" if len(projects) == 1 else ""


def same_account(g: graph.Graph, a: str, b: str) -> bool:
    """Whether two estate addresses are in the same account or project: the same root, or roots whose code names the
    same one. Roots that don't say are kept apart."""
    ra, rb = root_of(a), root_of(b)
    if ra == rb:
        return True
    acct = g.accounts.get(ra, "")
    return bool(acct) and acct == g.accounts.get(rb, "")


def merge(graphs: dict[str, graph.Graph]) -> graph.Graph:
    """One graph of every root's, each root's addresses under its tag."""
    out = graph.Graph("(estate)")
    for root, g in graphs.items():
        out.accounts[root] = account_of(g)
        t = tag(root)

        def at(a: str, t: str = t) -> str:
            return f"{t}.{a}"

        for a, r in g.resources.items():
            out.resources[at(a)] = replace(r, address=at(a), module=f"{t}.{r.module}" if r.module else t)
        for e in g.edges:
            out.edges.append(replace(e, source=at(e.source), target=at(e.target)))
        for a, u in g.unknown.items():
            out.unknown[at(a)] = replace(u, address=at(u.address))
        out.modules += [t if m == "(root)" else f"{t}.{m}" for m in g.modules]
        for m, d in g.module_dirs.items():
            out.module_dirs[f"{t}.{m}" if m else t] = d
        out.folders += [f for f in g.folders if f not in out.folders]
        out.notes += [f"{root}: {n}" for n in g.notes]
        out.info += [f"{root}: {n}" for n in g.info]
        out.outputs.update({f"{t}.{n}": [at(a) for a in v] for n, v in g.outputs.items()})
    return out


# a data source that looks a resource up by name → the managed type it finds, and (data attribute, resource
# attribute) pairs that must all be equal; a type not listed matches the same managed type by `name`
_LOOKUPS: dict[str, tuple[str, tuple[tuple[str, str], ...]]] = {
    "aws_s3_bucket": ("aws_s3_bucket", (("bucket", "bucket"),)),
    "aws_iam_user": ("aws_iam_user", (("user_name", "name"),)),
    "aws_lambda_function": ("aws_lambda_function", (("function_name", "function_name"),)),
    "aws_db_instance": ("aws_db_instance", (("db_instance_identifier", "identifier"),)),
    "aws_rds_cluster": ("aws_rds_cluster", (("cluster_identifier", "cluster_identifier"),)),
    "aws_ecs_cluster": ("aws_ecs_cluster", (("cluster_name", "name"),)),
    "aws_elasticache_cluster": ("aws_elasticache_cluster", (("cluster_id", "cluster_id"),)),
    "aws_opensearch_domain": ("aws_opensearch_domain", (("domain_name", "domain_name"),)),
    "aws_cognito_user_pools": ("aws_cognito_user_pool", (("name", "name"),)),
    "aws_kms_alias": ("aws_kms_alias", (("name", "name"),)),
    "aws_secretsmanager_secret_version": ("aws_secretsmanager_secret", (("secret_id", "name"),)),
    "google_service_account": ("google_service_account", (("account_id", "account_id"), ("project", "project"))),
    "google_secret_manager_secret": ("google_secret_manager_secret", (("secret_id", "secret_id"),)),
    "google_secret_manager_secret_version": ("google_secret_manager_secret", (("secret", "secret_id"),)),
    "google_storage_bucket": ("google_storage_bucket", (("name", "name"),)),
}


def _literal(r: graph.Resource, attr: str) -> str:
    from terrahunter import deps

    return deps.unquote(r.body.get(attr)) or ""


def _found_by(g: graph.Graph, d: graph.Resource) -> list[str]:
    """The managed resources in other roots that a data source finds by name (in its own account first)."""
    rtype, keys = _LOOKUPS.get(d.type, (d.type, (("name", "name"),)))
    if d.type.startswith("azurerm_"):
        keys = (("name", "name"), ("resource_group_name", "resource_group_name"))
    if not _literal(d, keys[0][0]):  # looked up by something else (a filter, an ARN, an expression)
        return []
    want = [(_literal(d, a), b) for a, b in keys if _literal(d, a)]
    here = root_of(d.address)
    hits = [
        a
        for a, r in g.resources.items()
        if r.mode == "managed" and r.type == rtype and root_of(a) != here and all(_literal(r, b) == v for v, b in want)
    ]
    same = [a for a in hits if same_account(g, d.address, a)]
    return same or hits


def link(g: graph.Graph, surveys: dict) -> list[str]:
    """Join the roots where one names another's resources indirectly: a remote state's outputs are the resources
    the other root's outputs name, and a data source that looks a resource up by name is that resource. Each
    reference to the remote state or the data source also becomes one to what it stands for. → what was linked."""
    by_target: dict[str, list[graph.Edge]] = {}
    for e in g.edges:
        by_target.setdefault(e.target, []).append(e)
    stands: dict[str, list[tuple[str, str]]] = {}  # remote state or data source → (what it stands for, output)
    for root, s in surveys.items():
        for n in s.of("remote-state", "matched"):
            addr = f"{tag(root)}.{(n.via + '.') if n.via else ''}{n.name}"
            other = tag(n.detail)
            outs = sorted(k for k in g.outputs if k.startswith(other + "."))
            if addr in g.resources and outs:
                stands[addr] = [(a, k[len(other) + 1 :]) for k in outs for a in g.outputs[k]]
    for a, r in g.resources.items():
        if r.mode == "data" and r.type not in ("terraform_remote_state", "tfe_outputs"):
            found = _found_by(g, r)
            if found:
                stands[a] = [(f, "") for f in found]
    g.links = stands
    added: list[graph.Edge] = []
    seen = {(e.source, e.target, e.attr) for e in g.edges}
    for addr, targets in stands.items():
        for e in by_target.get(addr, []):
            for t, output in targets:
                if (output and e.output and output != e.output) or e.source == t or (e.source, t, e.attr) in seen:
                    continue
                seen.add((e.source, t, e.attr))
                added.append(graph.Edge(e.source, t, e.attr))
    g.edges += added
    notes = []
    for addr, targets in stands.items():
        shown = sorted({label(t) for t, _ in targets})
        if by_target.get(addr):
            notes.append(
                f"{label(addr)} → " + ", ".join(shown[:4]) + (f" (+{len(shown) - 4} more)" if len(shown) > 4 else "")
            )
    return notes
