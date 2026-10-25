"""Stage 3a, the connection graph: every resource in a root and its modules, and every reference between them.

The root and each module it calls (local, or downloaded by `init` / `get`, found the same way as stage 2) is a
*scope*. A reference is read only inside `${ … }` (a quoted string without one is text, never a reference) and
resolved in its scope:

- `type.name` / `data.type.name` → that resource in the same scope;
- `var.x` → the argument the calling module passes for `x`, resolved in the caller's scope (in the root, a variable
  is an input: no edge);
- `local.x` → the local's own expression, in the same scope;
- `module.y.out` → module y's output `out`, resolved in y's scope; when y's code isn't available, an **unknown** node
  stands in for it, so a hole in the picture shows as a hole.

Every attribute of every resource is walked, and each reference that reaches another resource becomes an edge that
remembers the attribute it came from. Lookups are cached and cycle-safe. Without a plan, `count` and `for_each`
instances aren't expanded: one node per resource block.

Values known before apply are evaluated (`values`): the root's variables (defaults, then `terraform.tfvars`,
`*.auto.tfvars`, `--var-file`, `--var`), what each module call passes, locals, and what's built from them. A
resource or module whose `count` is 0 or whose `for_each` is empty leaves the graph (noted), and every attribute
whose value is known gets it in place of the expression, so `cidr_blocks = [var.allowed]` reads as the CIDR.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

import hcl2

from terrahunter import deps, sandbox, values

MAX_DEPTH = 24  # resolution hops through vars, locals and outputs
MAX_FILE_BYTES = 1024 * 1024  # file() / templatefile(): a policy or a template, not a dataset
_SKIP_ATTRS = {"count", "for_each", "depends_on", "lifecycle", "provider", "provisioner", "connection"}
_SKIP_HEADS = {"var", "local", "module", "each", "count", "path", "terraform", "self", "data"}
# a literal index after it (`aws_subnet.pub[0]`, `aws_subnet.q["k"]`) is kept: a plan maps it to that one instance
_RES = re.compile(r'(?<![\w.])(data\.)?([a-z][a-z0-9_]*)\.([A-Za-z0-9_-]+)(?:\[(\d+|"[^"\]]*")\])?')
_VAR = re.compile(r"(?<![\w.])var\.([A-Za-z0-9_-]+)")
_LOCAL = re.compile(r"(?<![\w.])local\.([A-Za-z0-9_-]+)")
_MOD = re.compile(r"(?<![\w.])module\.([A-Za-z0-9_-]+)(?:\[([^\]]*)\])?\.([A-Za-z0-9_-]+)")
# a block's labels may be quoted or not (`data aws_iam_policy_document "x"` is valid HCL)
_BLOCK_LINE = re.compile(
    r'^[ \t]*(resource|data|module)\s+"?([A-Za-z0-9_-]+)"?(?:\s+"?([A-Za-z0-9_-]+)"?)?\s*\{', re.MULTILINE
)


@dataclass
class Resource:
    address: str  # module.app.aws_instance.web, data.aws_ami.al
    type: str
    name: str
    mode: str  # managed | data
    module: str  # "" for the root, else module.app(.module.x…)
    file: str  # relative to its folder (`repo:` prefix for a --with folder)
    line: int
    body: dict = field(repr=False)


@dataclass
class Edge:
    source: str
    target: str
    attr: str  # the attribute of the source the reference is in (dotted path)
    index: str = ""  # a literal index the reference names on the target (`0`, `k`), else ""
    module_index: str = ""  # a literal module instance it names (`worker=0` for module.worker["0"].x), else ""


@dataclass
class Unknown:
    address: str  # module.x (with its module prefix)
    source: str
    status: str  # download | outside | missing | unresolved
    detail: str


@dataclass
class Graph:
    root: str
    resources: dict[str, Resource] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    unknown: dict[str, Unknown] = field(default_factory=dict)
    modules: list[str] = field(default_factory=list)  # module instances loaded, by address
    notes: list[str] = field(default_factory=list)  # what couldn't be read: the analysis is incomplete
    info: list[str] = field(default_factory=list)  # worth knowing, not a gap (blocks not deployed)
    module_dirs: dict[str, Path] = field(default_factory=dict, repr=False)  # module address ("" root) → its directory

    @property
    def dirs(self) -> list[Path]:
        """The directories read (real paths, the root's first), for the scanners."""
        return list(dict.fromkeys(self.module_dirs.values()))

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "resources": [{k: v for k, v in asdict(r).items() if k != "body"} for r in self.resources.values()],
            "edges": [
                {k: v for k, v in asdict(e).items() if k not in ("index", "module_index") or v} for e in self.edges
            ],
            "unknown": [asdict(u) for u in self.unknown.values()],
            "modules": self.modules,
            "notes": self.notes,
            "info": self.info,
        }


@dataclass
class _Scope:
    path: tuple[str, ...]
    dir: Path
    parent: _Scope | None
    resources: dict[str, str] = field(default_factory=dict)  # "type.name" / "data.type.name" → address
    locals: dict[str, object] = field(default_factory=dict)
    outputs: dict[str, object] = field(default_factory=dict)
    calls: dict[str, dict] = field(default_factory=dict)  # module name → its call body (the arguments)
    variables: dict[str, object] = field(default_factory=dict)  # name → its default (_UNSET when it has none)
    children: dict[str, _Scope] = field(default_factory=dict)

    @property
    def prefix(self) -> str:
        return "".join(f"module.{p}." for p in self.path)


def _exprs(v) -> list[str]:
    """The expression text inside every `${ … }` of a value (brace-balanced), anywhere inside it."""
    out: list[str] = []
    stack = [v]
    while stack:
        x = stack.pop()
        if isinstance(x, dict):
            stack += [y for k, y in x.items() if not str(k).startswith("__")]
        elif isinstance(x, list):
            stack += x
        elif isinstance(x, str):
            i = x.find("${")
            while i != -1:
                depth, j = 0, i + 2
                while j < len(x):
                    if x[j] == "{":
                        depth += 1
                    elif x[j] == "}":
                        if depth == 0:
                            break
                        depth -= 1
                    j += 1
                out.append(x[i + 2 : j])
                i = x.find("${", j)
    return out


def _attrs(body, prefix: str = ""):
    """(dotted attribute path, value) for each leaf of a resource body; `dynamic "x" { content {…} }` reads as x."""
    if isinstance(body, dict):
        for k, v in body.items():
            k = deps._key(k)
            if k.startswith("__") or (not prefix and k in _SKIP_ATTRS):
                continue
            if k == "dynamic":
                for blk in v if isinstance(v, list) else [v]:
                    for label, spec in blk.items() if isinstance(blk, dict) else []:
                        for sp in spec if isinstance(spec, list) else [spec]:
                            if isinstance(sp, dict):
                                yield from _attrs(sp.get("content"), f"{prefix}{deps._key(label)}.")
                continue
            yield from _attrs(v, f"{prefix}{k}.") if isinstance(v, (dict, list)) else [(f"{prefix}{k}", v)]
    elif isinstance(body, list):
        for x in body:
            yield from _attrs(x, prefix) if isinstance(x, (dict, list)) else [(prefix.rstrip("."), x)]


def dir_label(d: Path, folder: Path, allowed: list[Path]) -> str:
    """How a directory is named in the output: relative to the folder, or `repo:path` in a --with folder."""
    base = deps._inside_any(d, allowed) or folder
    rel = os.path.relpath(d, base)
    return (base.name + ":" if base != folder else "") + (Path(rel).as_posix() if rel != "." else ".")


_UNSET = object()
_TFVARS_AUTO = re.compile(r"\.auto\.tfvars(\.json)?$")


def read_tfvars(path: Path) -> dict:
    """A .tfvars or .tfvars.json file → {name: value in the parser's shape}. Raises OSError / ValueError."""
    text = sandbox.read_regular(path).decode("utf-8", "replace")
    if path.name.endswith(".json"):
        return deps._requote(json.loads(text))
    data = deps._hcl(text)
    return {k: v for k, v in data.items() if not str(k).startswith("__")}


def build(
    folder: Path,
    root: str,
    with_folders: list[Path] | None = None,
    variables: dict | None = None,
    var_files: list[Path] | None = None,
) -> Graph:
    """The graph of one root. `variables` ({name: value in the parser's shape}) and `var_files` are the root's
    inputs, as `-var` and `-var-file` would give them."""
    folder = folder.resolve()
    allowed = [folder] + [w.resolve() for w in with_folders or []]
    root_dir = (folder / root).resolve()
    g = Graph(root)
    downloads = deps._downloads(root_dir)

    def label(d: Path) -> str:
        return dir_label(d, folder, allowed)

    def load(d: Path, path: tuple[str, ...], parent: _Scope | None) -> _Scope:
        sc = _Scope(path, d, parent)
        g.modules.append(sc.prefix.rstrip(".") or "(root)")
        g.module_dirs[sc.prefix.rstrip(".")] = d
        for fname, doc, text in deps.load_dir(d, g.notes, label(d)):
            lines = {}
            for m in _BLOCK_LINE.finditer(text):
                key = (m.group(1), m.group(2), m.group(3))
                lines.setdefault(key, text.count("\n", 0, m.start()) + 1)
            where = f"{label(d)}/{fname}".removeprefix("./")
            for kind, mode in (("resource", "managed"), ("data", "data")):
                for group in deps._groups(doc.get(kind)):
                    for rtype, named in group.items() if isinstance(group, dict) else []:
                        rtype = deps._key(rtype)
                        for name, body in named.items() if isinstance(named, dict) else []:
                            name = deps._key(name)
                            body = body[0] if isinstance(body, list) and body else body
                            local = f"{'data.' if mode == 'data' else ''}{rtype}.{name}"
                            addr = sc.prefix + local
                            sc.resources[local] = addr
                            g.resources[addr] = Resource(
                                addr,
                                rtype,
                                name,
                                mode,
                                sc.prefix.rstrip("."),
                                where,
                                lines.get((kind, rtype, name), 0),
                                body if isinstance(body, dict) else {},
                            )
            for group in deps._groups(doc.get("locals")):
                if isinstance(group, dict):
                    sc.locals.update({k: v for k, v in group.items() if not str(k).startswith("__")})
            for name, body in deps._blocks(doc, "output"):
                sc.outputs[name] = body.get("value")
            for name, body in deps._blocks(doc, "variable"):
                sc.variables[name] = body.get("default", _UNSET)
            for name, body in deps._blocks(doc, "module"):
                sc.calls[name] = body
                src = deps.unquote(body.get("source"))
                child_addr = f"{sc.prefix}module.{name}"
                if src is None:
                    g.unknown[child_addr] = Unknown(
                        child_addr,
                        sandbox.one_line(body.get("source"), 120),
                        "unresolved",
                        "the source is an expression",
                    )
                    continue
                status, target, note = deps.locate_module(d, src, ".".join(path + (name,)), folder, allowed, downloads)
                if status != "present":
                    g.unknown[child_addr] = Unknown(child_addr, src, status, note)
                elif len(path) < deps.MAX_MODULE_DEPTH:
                    sc.children[name] = load(target, path + (name,), sc)
        return sc

    top = load(root_dir, (), None)

    # --- values known before apply: the root's inputs, then what each scope's variables and locals evaluate to
    inputs: dict[str, object] = {}
    auto = [root_dir / "terraform.tfvars", root_dir / "terraform.tfvars.json"]
    auto += sorted(p for p in root_dir.iterdir() if _TFVARS_AUTO.search(p.name)) if root_dir.is_dir() else []
    for f in [p for p in auto if p.exists()] + list(var_files or []):
        try:
            inputs.update(read_tfvars(Path(f)))
        except (OSError, ValueError, RecursionError, Exception) as e:  # noqa: BLE001 - a bad file is a note
            g.notes.append(
                f"{label(Path(f).resolve().parent)}/{Path(f).name}: variables couldn't be read ({type(e).__name__})"
            )
    inputs.update(variables or {})
    known: dict[tuple, object] = {}

    def resolver(sc: _Scope):
        def resolve(kind: str, name: str):
            key = (sc.path, kind, name)
            if key in known:
                if known[key] is _UNSET:
                    raise values.Unknown(f"{kind}.{name}")
                return known[key]
            known[key] = _UNSET  # in progress: a cycle is unknown
            if kind == "local" and name in sc.locals:
                v = evaluate(sc.locals[name], sc)
            elif kind == "var" and sc.parent is None and name in inputs:
                v = evaluate(inputs[name], sc)
            elif kind == "var" and sc.parent is not None and name in sc.parent.calls.get(sc.path[-1], {}):
                v = evaluate(sc.parent.calls[sc.path[-1]][name], sc.parent)
            elif kind == "var" and sc.variables.get(name, _UNSET) is not _UNSET:
                v = evaluate(sc.variables[name], sc)
            elif kind == "path" and name in ("module", "root", "cwd"):
                top = sc
                while top.parent is not None:
                    top = top.parent
                v = str(sc.dir if name == "module" else top.dir)
            else:
                raise values.Unknown(f"{kind}.{name}")
            known[key] = v
            return v

        return resolve

    def reader(sc: _Scope):
        def read(p: str) -> str:
            """file(): a regular file inside the folders under analysis, relative to the module's directory."""
            path = Path(p) if Path(p).is_absolute() else sc.dir / p
            try:
                real = path.resolve()
                if deps._inside_any(real, allowed) is None:
                    raise values.Unknown(f"file {p} is outside the folders under analysis")
                return sandbox.read_regular(real, MAX_FILE_BYTES).decode("utf-8")
            except (OSError, UnicodeDecodeError) as e:
                raise values.Unknown(f"file {p}") from e

        return read

    def evaluate(v, sc: _Scope):
        return values.Evaluator(resolver(sc), reader(sc)).value(v)

    def deployed(body: dict, sc: _Scope) -> bool:
        """False when count is 0 or for_each is empty, with these values; True when it isn't, or can't be told."""
        try:
            if "count" in body:
                return evaluate(body["count"], sc) not in (0, False)
            if "for_each" in body:
                return bool(evaluate(body["for_each"], sc))
        except values.Unknown:
            pass
        return True

    gone: list[str] = []

    def prune(sc: _Scope) -> None:
        for local, addr in list(sc.resources.items()):
            if not deployed(g.resources[addr].body, sc):
                gone.append(addr)
                del sc.resources[local], g.resources[addr]
        for name, call in list(sc.calls.items()):
            if deployed(call, sc):
                continue
            child_addr = f"{sc.prefix}module.{name}"
            gone.append(child_addr)
            g.unknown.pop(child_addr, None)
            child = sc.children.pop(name, None)
            for c in scopes(child) if child else []:
                g.module_dirs.pop(c.prefix.rstrip("."), None)
                if c.prefix.rstrip(".") in g.modules:
                    g.modules.remove(c.prefix.rstrip("."))
                for addr in c.resources.values():
                    g.resources.pop(addr, None)
        for child in sc.children.values():
            prune(child)

    cache: dict[tuple, frozenset[str]] = {}

    def resolve(value, sc: _Scope, depth: int) -> set[str]:
        out: set[str] = set()
        if depth > MAX_DEPTH:
            return out
        for e in _exprs(value):
            for m in _RES.finditer(e):
                head = m.group(2)
                if not m.group(1) and head in _SKIP_HEADS:
                    continue
                local = f"{'data.' if m.group(1) else ''}{head}.{m.group(3)}"
                if local in sc.resources:
                    idx = (m.group(4) or "").strip('"')
                    out.add(sc.resources[local] + (f"[{idx}]" if m.group(4) else ""))
            for m in _VAR.finditer(e):
                out |= lookup(("var", m.group(1)), sc, depth)
            for m in _LOCAL.finditer(e):
                out |= lookup(("local", m.group(1)), sc, depth)
            for m in _MOD.finditer(e):
                found = lookup(("module", m.group(1), m.group(3)), sc, depth)
                key = (m.group(2) or "").strip('"')
                # a literal instance of the module (module.worker["0"]): the edge says which, for the plan
                out |= {f"{f}@{m.group(1)}={key}" for f in found} if key and "${" not in key and depth == 0 else found
        return out

    def lookup(key: tuple, sc: _Scope, depth: int) -> frozenset[str]:
        ck = (sc.path,) + key
        if ck in cache:
            return cache[ck]
        cache[ck] = frozenset()  # in progress: a cycle resolves to nothing rather than looping
        found: set[str] = set()
        if key[0] == "var" and sc.parent is not None:
            arg = sc.parent.calls.get(sc.path[-1], {}).get(key[1])
            found = resolve(arg, sc.parent, depth + 1) if arg is not None else set()
        elif key[0] == "local" and key[1] in sc.locals:
            found = resolve(sc.locals[key[1]], sc, depth + 1)
        elif key[0] == "module":
            child = sc.children.get(key[1])
            if child is not None and key[2] in child.outputs:
                found = resolve(child.outputs[key[2]], child, depth + 1)
            elif child is None and f"{sc.prefix}module.{key[1]}" in g.unknown:
                found = {f"{sc.prefix}module.{key[1]}"}
        cache[ck] = frozenset(found)
        return cache[ck]

    def scopes(sc: _Scope):
        yield sc
        for c in sc.children.values():
            yield from scopes(c)

    prune(top)
    if gone:
        g.info.append(
            f"{len(gone)} resource or module block{'s' if len(gone) != 1 else ''} not deployed with these variables "
            f"(count = 0 or an empty for_each): "
            + ", ".join(gone[:6])
            + (f" (+{len(gone) - 6} more)" if len(gone) > 6 else "")
        )

    seen: set[tuple[str, str, str, str]] = set()
    for sc in scopes(top):
        for addr in sc.resources.values():
            for attr, value in _attrs(g.resources[addr].body):
                for found in sorted(resolve(value, sc, 0)):
                    found, _, mod = found.partition("@")
                    target, _, idx = found.partition("[")
                    idx = idx[:-1]
                    if target != addr and (addr, target, attr, idx + "@" + mod) not in seen:
                        seen.add((addr, target, attr, idx + "@" + mod))
                        g.edges.append(Edge(addr, target, attr, idx, mod))

    # known values in place of their expressions (after the edges, which read the references)
    def substitute(v, sc: _Scope):
        if isinstance(v, str) and "${" in v:
            try:
                return values.to_parser(evaluate(v, sc))
            except values.Unknown:
                pass
            inner = v[2:-1].strip() if v.startswith("${") and v.endswith("}") else ""
            if inner.startswith("jsonencode(") and inner.endswith(")"):
                # a policy or definition written as jsonencode({…}): the object, with what's known in it evaluated
                try:
                    obj = hcl2.loads("x = " + inner[len("jsonencode(") : -1] + "\n").get("x")
                except Exception:  # noqa: BLE001 - not an object the parser reads: leave it as written
                    return v
                return substitute(obj, sc) if isinstance(obj, (dict, list)) else v
            if inner:
                try:
                    return values.partial(inner, values.Evaluator(resolver(sc), reader(sc)).expr)
                except values.Unknown:
                    pass
            return v
        if isinstance(v, list):
            return [substitute(x, sc) for x in v]
        if isinstance(v, dict):
            return {k: substitute(x, sc) if not str(k).startswith("__") else x for k, x in v.items()}
        return v

    for sc in scopes(top):
        for addr in sc.resources.values():
            g.resources[addr].body = substitute(g.resources[addr].body, sc)
    return g
