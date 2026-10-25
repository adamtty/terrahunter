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
    return out
