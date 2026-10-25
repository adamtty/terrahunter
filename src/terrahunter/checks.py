"""Check by hand: what an attack path rests on that the Terraform doesn't show.

A path through an application assumes its code mishandles input; a shell over SSH assumes a key outside the
configuration; a container reaching its host's metadata service assumes the host doesn't block it. Scripts that run at
deploy time (provisioners, a `null_resource`) can change what the Terraform describes, or load data into it. Each such
assumption becomes a question, with where to look and the paths that depend on it, so whoever reads the results knows
what to confirm before acting on a *likely* or *possible* path.
"""

from __future__ import annotations

import re
from pathlib import Path

from terrahunter import arch, chains, deps, graph, kb

# where a workload's code comes from: the attributes that name a local file or folder, or an image
_CODE_ATTRS = ("filename", "source", "source_dir", "source_file", "output_path", "image")
# the references a workload's code is reached through (not its layers, network or permissions)
_CODE_REFS = re.compile(
    r"^(filename|s3_(bucket|key|object_version)|source\w*|image\w*|task_definition|container_definitions|user_data"
    r"|metadata_startup_script|custom_data|template|app_settings|package\w*|zip_deploy_file|build_config)"
)
# credentials a deploy-time script carries: an access key, a generated key or password, a secret's value
_CREDENTIAL = re.compile(
    r"\b(aws_iam_access_key\.[\w-]+|tls_private_key\.[\w-]+|random_password\.[\w-]+|"
    r"aws_secretsmanager_secret_version\.[\w-]+|aws_iam_user_login_profile\.[\w-]+)"
)
# what boots with a script: machines, their templates, their scale sets
_BOOTED = {
    "aws_instance",
    "aws_launch_template",
    "aws_launch_configuration",
    "google_compute_instance",
    "google_compute_instance_template",
    "azurerm_virtual_machine",
    "azurerm_linux_virtual_machine",
    "azurerm_windows_virtual_machine",
}
_RULE = re.compile(r"\[([a-z0-9-]+)\]$")
_IMAGE = re.compile(r"""['"]?image['"]?\s*[:=]\s*['"]([^'"]+)['"]""")


def _local(g: graph.Graph, r: graph.Resource, value: str) -> str:
    """A path in the folders under analysis, relative to its folder (noted when it's built at deploy time and isn't
    there), or "" when it isn't one."""
    base = g.module_dirs.get(r.module)
    if base is None or "${" in value.replace("${path.module}", "").replace("${path.root}", "") or "://" in value:
        return ""
    value = value.replace("${path.module}/", "").replace("${path.root}/", "")
    p = (Path(value) if Path(value).is_absolute() else base / value).resolve()
    for d in g.dirs:
        d = d.resolve()
        if p == d or d in p.parents:
            shown = p.relative_to(d).as_posix() or "."
            return shown if p.exists() else f"{shown} (built at deploy time: not in the folder)"
    return ""


def code_of(g: graph.Graph, addr: str) -> list[str]:
    """Where a workload's code is: local files and folders it's built from (an archive's source, an uploaded object),
    or the image it runs, through up to two references."""
    R = g.resources
    out_e: dict[str, list[str]] = {}
    for e in g.edges:
        if _CODE_REFS.search(e.attr):
            out_e.setdefault(e.source, []).append(e.target)
    seen, frontier, found = {addr}, [addr], []
    for _ in range(3):
        nxt = []
        for a in frontier:
            r = R.get(a)
            if r is None:
                continue
            for k in _CODE_ATTRS:
                v = deps.unquote(r.body.get(k))
                if not v:
                    continue
                if k == "image":
                    found.append(f"image {v}")
                elif where := _local(g, r, v):
                    found.append(where)
            found += [f"image {m}" for m in _IMAGE.findall(str(r.body.get("container_definitions", "")))]
            nxt += [t for t in out_e.get(a, []) if t not in seen]
        seen.update(nxt)
        frontier = nxt
    return sorted(dict.fromkeys(found), key=lambda w: "(built" in w)  # what's there first


def _kinds(r: graph.Resource) -> str:
    blocks = r.body.get("provisioner")
    blocks = blocks if isinstance(blocks, list) else [blocks]
    return ", ".join(sorted({deps.unquote(k) or k for b in blocks if isinstance(b, dict) for k in b}))


def _literal_name(r: graph.Resource | None) -> str:
    """A resource's own name as written (a bucket's, a table's), when it's a literal long enough to search for."""
    if r is None:
        return ""
    for k in ("bucket", "name", "function_name", "table_name"):
        v = deps.unquote(r.body.get(k))
        if v and "${" not in v and len(v) >= 6:
            return v
    return ""


def _where(r: graph.Resource | None) -> list[str]:
    return [f"{r.file}:{r.line}"] if r is not None and r.file else []


def _scripts(g: graph.Graph) -> dict[str, list[str]]:
    """Deploy-time scripts and what they act on: a resource's provisioners (they act on it, and on what their
    commands name), and a null_resource or terraform_data's (on what they name)."""
    out: dict[str, list[str]] = {}
    for a, r in g.resources.items():
        blocks = r.body.get("provisioner")
        if not blocks:
            continue
        text = str(blocks) + str(r.body.get("triggers", "")) + str(r.body.get("triggers_replace", ""))
        named = [x for x in g.resources if x != a and x in text]
        acts = ([] if r.type in ("null_resource", "terraform_data") else [a]) + named
        if acts:
            out[a] = acts
    return out


def find(g: graph.Graph, paths: list[chains.Chain], assumed: dict[int, list[tuple[str, str]]]) -> list[chains.Check]:
    """The checks for these paths, most paths first; each path's `checks` names its own."""
    R = g.resources
    found: dict[str, chains.Check] = {}
    scripts = _scripts(g)
    boots = [a for a, r in R.items() if r.mode == "managed" and r.type in _BOOTED]
    texts: dict[str, str] = {}

    def boot_text(m: str) -> str:
        if m not in texts:
            texts[m] = arch.boot_script(g, m)
        return texts[m]

    rules = {r["id"]: r for c in ("aws", "azure", "gcp") for r in kb.techniques(c)}
    models: list = []

    def model():
        if not models:
            from terrahunter import iam

            models.append(iam.Model(g))
        return models[0]

    def add(n: int, kind: str, about: str, question: str, where: list[str]) -> None:
        cid = f"{kind}:{about}"
        if cid not in found:
            found[cid] = chains.Check(cid, kind, about, question, where)
        if n not in found[cid].chains:
            found[cid].chains.append(n)

    for n, ch in enumerate(paths):
        on = [*ch.steps, *ch.sinks]
        for kind, about in assumed.get(id(ch), []):
            r = R.get(about)
            if kind == "code":
                where = code_of(g, about) or _where(r)
                add(
                    n,
                    kind,
                    about,
                    f"Does {about}'s code let a request run commands, read files, fetch URLs or build queries from "
                    "its input?" + ("" if code_of(g, about) else " (its code isn't in the folders analysed)"),
                    where,
                )
            elif kind == "login":
                add(
                    n,
                    kind,
                    about,
                    f"Is there a key or password for {about} outside the Terraform (a key pair, the "
                    "image's own users, a vault)?",
                    _where(r),
                )
            elif kind == "imds":
                add(
                    n,
                    kind,
                    about,
                    f"Does {about} keep its containers from the instance metadata service (an "
                    "iptables rule in its user data, ECS_AWSVPC_BLOCK_IMDS, a hop limit of 1)?",
                    _where(r),
                )
            elif kind == "placement":
                add(
                    n,
                    kind,
                    about,
                    f"Can {about}'s tasks be placed on the attacker's host: its placement "
                    "constraints, and anything that changes them after deploy?",
                    _where(r),
                )
            elif kind == "unresolved":
                add(
                    n,
                    kind,
                    about,
                    f"{about}'s exposure depends on a value the Terraform doesn't settle (a variable, "
                    "a condition on the caller): check what it is where this is deployed.",
                    _where(r),
                )
            elif kind == "implied":
                add(
                    n,
                    kind,
                    about,
                    "Is the organization policy iam.automaticIamGrantsForDefaultServiceAccounts "
                    "enforced for this project, or the default compute account's Editor grant removed?",
                    _where(r),
                )
        # a policy on the path whose actions or resources are one of two branches the code doesn't settle
        for step in ch.steps:
            if R.get(step) and R[step].type in ("aws_iam_role", "aws_iam_user"):
                for st in model().statements(step):
                    if st.maybe:
                        add(
                            n,
                            "branch",
                            st.source,
                            f"Which branch of {st.source}'s conditional applies where this "
                            f"is deployed? It decides what {step} may do ({', '.join(st.actions[:3]) or 'its actions'}).",
                            _where(R.get(st.source)),
                        )
        # the techniques the path uses, with the knowledge base's preconditions
        for h in ch.hops:
            m = _RULE.search(h)
            rule = rules.get(m.group(1)) if m else None
            conds = (rule or {}).get("requires", {}).get("conditions") or []
            if rule and conds:
                add(n, "technique", rule["id"], f"{rule.get('title') or rule['id']}: {'; '.join(conds)}", [])
        # scripts that run at deploy time on what the path goes through or reaches, by what they act on
        for x in dict.fromkeys(on):
            by = [a for a, acts in scripts.items() if x in acts]
            if by:
                carried = sorted({c for a in by for c in _CREDENTIAL.findall(str(R[a].body.get("provisioner")))})
                add(
                    n,
                    "script",
                    x,
                    f"Deploy-time scripts act on {x} ({', '.join(f'{a}: {_kinds(R[a])}' for a in by[:4])}"
                    + (" …" if len(by) > 4 else "")
                    + "): check what they change or load"
                    + (f"; they carry {', '.join(carried)}" if carried else "")
                    + ".",
                    [w for a in by for w in _where(R[a])],
                )
            # a machine's boot script that names it: what it does there isn't in the Terraform
            name = _literal_name(R.get(x))
            for m in boots:
                if m != x and (x in boot_text(m) or name and name in boot_text(m)):
                    add(
                        n,
                        "boot",
                        x,
                        f"{m}'s boot script names {x}: check what it does to it (changes it, empties "
                        "or deletes it, loads data into it).",
                        _where(R[m]),
                    )
    out = sorted(found.values(), key=lambda c: (-len(c.chains), c.id))
    for c in out:
        for n in c.chains:
            paths[n].checks.append(c.id)
    return out
