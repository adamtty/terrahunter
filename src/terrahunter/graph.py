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
"""

from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from terrahunter import deps, sandbox

MAX_DEPTH = 24  # resolution hops through vars, locals and outputs
_SKIP_ATTRS = {"count", "for_each", "depends_on", "lifecycle", "provider", "provisioner", "connection"}
_SKIP_HEADS = {"var", "local", "module", "each", "count", "path", "terraform", "self", "data"}
_RES = re.compile(r"(?<![\w.])(data\.)?([a-z][a-z0-9_]*)\.([A-Za-z0-9_-]+)")
_VAR = re.compile(r"(?<![\w.])var\.([A-Za-z0-9_-]+)")
_LOCAL = re.compile(r"(?<![\w.])local\.([A-Za-z0-9_-]+)")
_MOD = re.compile(r"(?<![\w.])module\.([A-Za-z0-9_-]+)(?:\[[^\]]*\])?\.([A-Za-z0-9_-]+)")
_BLOCK_LINE = re.compile(r'^\s*(resource|data|module)\s+"([^"]+)"(?:\s+"([^"]+)")?', re.MULTILINE)


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
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "resources": [{k: v for k, v in asdict(r).items() if k != "body"} for r in self.resources.values()],
            "edges": [asdict(e) for e in self.edges],
            "unknown": [asdict(u) for u in self.unknown.values()],
            "modules": self.modules,
            "notes": self.notes,
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


def build(folder: Path, root: str, with_folders: list[Path] | None = None) -> Graph:
    folder = folder.resolve()
    allowed = [folder] + [w.resolve() for w in with_folders or []]
    root_dir = (folder / root).resolve()
    g = Graph(root)
    downloads = deps._downloads(root_dir)

    def label(d: Path) -> str:
        base = deps._inside_any(d, allowed) or folder
        rel = os.path.relpath(d, base)
        return (base.name + ":" if base != folder else "") + (Path(rel).as_posix() if rel != "." else ".")

    def load(d: Path, path: tuple[str, ...], parent: _Scope | None) -> _Scope:
        sc = _Scope(path, d, parent)
        g.modules.append(sc.prefix.rstrip(".") or "(root)")
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
                    out.add(sc.resources[local])
            for m in _VAR.finditer(e):
                out |= lookup(("var", m.group(1)), sc, depth)
            for m in _LOCAL.finditer(e):
                out |= lookup(("local", m.group(1)), sc, depth)
            for m in _MOD.finditer(e):
                out |= lookup(("module", m.group(1), m.group(2)), sc, depth)
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

    seen: set[tuple[str, str, str]] = set()
    for sc in scopes(top):
        for addr in sc.resources.values():
            for attr, value in _attrs(g.resources[addr].body):
                for target in sorted(resolve(value, sc, 0)):
                    if target != addr and (addr, target, attr) not in seen:
                        seen.add((addr, target, attr))
                        g.edges.append(Edge(addr, target, attr))
    return g
