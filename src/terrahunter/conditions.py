"""Evaluate the knowledge base's machine-readable conditions (a catalogue entry's `test`, `when`) on the graph.

The rules are the knowledge base's (catalog/README.md, "Conditions"). A test is a check, `all`, `any`, `not` or
`always`; a check names an attribute of the subject, or of a related resource reached through `of` hops, optionally
looks `inside` its value (JSON, a map's keys or values, a string pattern), and compares it (`is`, `in`, `not_in`,
`matches`, `contains`, `present`, `gt`, `ge`, `lt`, `le`, `element`). Results are three-valued: True, False, or None
when a value is an expression that couldn't be resolved (an exposure whose test is unknown is possible, not dropped).

- A check on a list passes when any element passes; `contains` tests the list as a whole.
- Checks in one `all` that share a repeated-block prefix (`ingress.cidr_blocks`, `ingress.from_port`) hold on the
  same block instance.
- A related resource that doesn't exist makes `quantifier: any` fail and `none` pass. A reference the graph can't
  follow (a name given as a literal, a variable that wasn't resolved) makes the hop unknown.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import deps, graph, policies

OPS = ("is", "in", "not_in", "matches", "contains", "present", "gt", "ge", "lt", "le")
_UNKNOWN = object()  # a value that's an expression terrahunter couldn't resolve
# a value that is one attribute of a resource the configuration creates (aws_iam_user.bob.arn): unknown, but never a
# wildcard, and never an ARN AWS owns (arn:aws:iam::aws:policy/…), so comparing it with those is settled
_RESOURCE_REF = re.compile(
    r"^\$\{(?!(var|local|data|module|each|count|path|terraform|self)\.)[a-z][a-z0-9_]*\.[A-Za-z0-9_-]+(\[[^\]]*\])?"
    r"\.[A-Za-z0-9_]+\}$"
)


def _literal_text(v) -> str:
    """The text a template has outside its ${…} expressions (the quotes aside)."""
    if not isinstance(v, str):
        return ""
    t = v[1:-1] if len(v) >= 2 and v[0] == v[-1] == '"' else v
    return re.sub(r"\$\{[^}]*\}", "", t).strip()


def _never(want) -> bool:
    """Whether a resource's own attribute can't be this literal."""
    return isinstance(want, str) and (want == "*" or want.startswith("arn:aws:iam::aws:"))


_PATH = re.compile(r'\.([A-Za-z0-9_\-:]+)|\["((?:[^"\\]|\\.)*)"\]|\[(\*|\d+)\]')


# --- three-valued logic ------------------------------------------------------------------------------------------
def all3(results) -> bool | None:
    out: bool | None = True
    for r in results:
        if r is False:
            return False
        if r is None:
            out = None
    return out


def any3(results) -> bool | None:
    out: bool | None = False
    for r in results:
        if r is True:
            return True
        if r is None:
            out = None
    return out


def not3(r: bool | None) -> bool | None:
    return None if r is None else not r


def quantify(q: str, results: list) -> bool | None:
    if q == "all":
        return all3(results)
    if q == "none":
        return not3(any3(results))
    return any3(results)


# --- the graph, indexed ------------------------------------------------------------------------------------------
@dataclass
class Index:
    g: graph.Graph
    out_edges: dict[str, list[graph.Edge]] = field(default_factory=dict)
    in_edges: dict[str, list[graph.Edge]] = field(default_factory=dict)
    by_type: dict[str, list[str]] = field(default_factory=dict)

    @classmethod
    def of(cls, g: graph.Graph) -> Index:
        ix = cls(g)
        for e in g.edges:
            ix.out_edges.setdefault(e.source, []).append(e)
            ix.in_edges.setdefault(e.target, []).append(e)
        for a, r in g.resources.items():
            if r.mode == "managed":
                ix.by_type.setdefault(r.type, []).append(a)
        return ix


def _attr_matches(edge_attr: str, attr: str) -> bool:
    return edge_attr == attr or edge_attr.startswith(attr + ".")


def related(ix: Index, addr: str, hop: dict) -> list[str] | None:
    """The resources one `of` hop reaches from addr; None when the reference can't be followed."""
    R = ix.g.resources
    types = set(hop.get("type") or [])
    if hop.get("scope"):
        return [a for t in types for a in ix.by_type.get(t, [])]
    if hop.get("via"):
        return [
            e.source
            for e in ix.in_edges.get(addr, [])
            if e.source in R and R[e.source].type in types and _attr_matches(e.attr, hop["via"])
        ]
    if hop.get("through"):
        found = [
            e.target
            for e in ix.out_edges.get(addr, [])
            if e.target in R and R[e.target].type in types and _attr_matches(e.attr, hop["through"])
        ]
        if found or addr not in R:
            return list(dict.fromkeys(found))
        vals = values(R[addr].body, hop["through"].split("."))
        return None if vals else []  # set, but to nothing the graph has: unknown; unset: no related resource
    return []


# --- values ------------------------------------------------------------------------------------------------------
def _child(node: dict, key: str) -> list:
    """node[key], with HCL's quoted keys and `dynamic "key" { content {…} }` blocks read as the key."""
    for k, v in node.items():
        if deps._key(k) == key:
            return [v]
    out = []
    for blk in _as_list(node.get("dynamic")):
        if isinstance(blk, dict):
            for label, spec in blk.items():
                if deps._key(label) == key:
                    out += [sp.get("content") for sp in _as_list(spec) if isinstance(sp, dict) and "content" in sp]
    return out


def _as_list(v) -> list:
    return v if isinstance(v, list) else ([] if v is None else [v])


def values(node, path: list[str]) -> list:
    """Every value at a dotted path, through blocks (lists of objects) and nested objects; [] when unset."""
    cur = [node]
    for seg in path:
        nxt = []
        for x in cur:
            for y in _as_list(x) if isinstance(x, list) else [x]:
                if isinstance(y, dict):
                    nxt += _child(y, seg)
        cur = nxt
    out = []
    for v in cur:
        if isinstance(v, list) and not any(isinstance(x, dict) for x in v):
            out += v  # a list attribute: its elements
        elif v is not None:
            out.append(v)
    return out


def scalar(v):
    """A parser value as a plain one: '"x"' → 'x', an unresolved expression → _UNKNOWN; JSON values as they are."""
    if isinstance(v, str):
        if len(v) >= 2 and v[0] == v[-1] == '"':
            u = deps.unquote(v)
            return _UNKNOWN if u is None else u
        if "${" in v:
            return _UNKNOWN
        return v
    return v


def _canon(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return str(v).lower()


def _num(v):
    try:
        return float(v) if not isinstance(v, bool) else None
    except (TypeError, ValueError):
        return None


def _json_path(doc, path: str) -> list:
    if not path or path == "$":
        return [doc]
    if not path.startswith("$"):
        return []
    cur = [doc]
    steps = list(_PATH.finditer(path[1:]))
    for i, m in enumerate(steps):
        key = m.group(1) if m.group(1) is not None else m.group(2)
        last = i == len(steps) - 1
        nxt = []
        for x in cur:
            if key is not None:
                if isinstance(x, dict):
                    if key in x:
                        nxt.append(x[key])
                    else:  # IAM keys compare case-insensitively
                        nxt += [v for k, v in x.items() if str(k).lower() == key.lower()]
            elif m.group(3) == "*":
                # an object's values, so `$.Condition[*]["aws:SourceVpc"]` reads that key under any operator; as the
                # last step, an object is one item (a policy's Statement may be a single object)
                if isinstance(x, list):
                    nxt += x
                else:
                    nxt += list(x.values()) if isinstance(x, dict) and not last else [x]
            elif isinstance(x, list) and int(m.group(3)) < len(x):
                nxt.append(x[int(m.group(3))])
        cur = nxt
    return cur


def look_inside(raw: list, inside: dict) -> list:
    """The values an `inside` selects from each raw value (_UNKNOWN for a value that can't be read)."""
    fmt, path, pattern = inside.get("format", "json"), inside.get("path"), inside.get("pattern")
    out: list = []
    for v in raw:
        if fmt == "json":
            doc = policies.document(v, any_json=True)
            if doc is None:
                out.append(_UNKNOWN if scalar(v) is _UNKNOWN or isinstance(v, str) and "${" in v else None)
                continue
            out += _json_path(doc, path or "$")
        elif fmt in ("map_key", "map_value"):
            m = policies.document(v, any_json=True) if not isinstance(v, dict) else policies._unquote_all(v)
            if not isinstance(m, dict):
                out.append(_UNKNOWN if scalar(v) is _UNKNOWN else None)
                continue
            if path and path != "$":
                hit = _json_path(m, path)
                out += [k for k in m if any(m[k] is h for h in hit)] if fmt == "map_key" else hit
            else:
                out += list(m) if fmt == "map_key" else list(m.values())
        else:  # string, uri
            s = scalar(v)
            if s is _UNKNOWN:
                out.append(_UNKNOWN)
            elif isinstance(s, str) and pattern:
                for mt in re.finditer(pattern, s):
                    out.append(mt.group(1) if mt.groups() else mt.group(0))
            elif isinstance(s, str):
                out.append(s)
    return [x for x in out if x is not None]


def _compare(op: str, want, v) -> bool | None:
    s = scalar(v)
    if s is _UNKNOWN:
        ref = isinstance(v, str) and bool(_RESOURCE_REF.match(v))
        # a template with text of its own around the expression ("arn:aws:iam::${…}:root") isn't the wildcard either
        if op == "is" and want == "*" and _literal_text(v):
            return False
        if ref and op == "is" and _never(want):
            return False
        if ref and op == "in" and all(_never(w) for w in want):
            return False
        return None
    if op == "is":
        return _canon(s) == _canon(want)
    if op == "in":
        return _canon(s) in {_canon(w) for w in want}
    if op == "not_in":
        return _canon(s) not in {_canon(w) for w in want}
    if op == "matches":
        return bool(re.search(want, s if isinstance(s, str) else _canon(s)))
    n, w = _num(s), _num(want)
    if n is None or w is None:
        return False
    return {"gt": n > w, "ge": n >= w, "lt": n < w, "le": n <= w}[op]


# --- evaluation --------------------------------------------------------------------------------------------------
@dataclass
class _Ctx:
    ix: Index
    addr: str  # the subject's address ("" inside an element)
    body: object  # the subject's body, or the element being judged
    item: bool = False  # judging an element: `attr` is a key path in the item, not a resource attribute
    bound: dict[str, object] = field(default_factory=dict)  # repeated-block prefix → the instance being judged


def evaluate(test, addr: str, ix: Index) -> bool | None:
    """Evaluate a test on the resource at addr: True, False, or None (unknown)."""
    r = ix.g.resources.get(addr)
    return _test(test, _Ctx(ix, addr, r.body if r else {}))


def _test(t, ctx: _Ctx) -> bool | None:
    if not isinstance(t, dict):
        return True
    if "all" in t:
        return _all(t["all"], ctx)
    if "any" in t:
        return any3(_test(x, ctx) for x in t["any"])
    if "not" in t:
        return not3(_test(t["not"], ctx))
    if "always" in t:
        return bool(t["always"])
    return _check(t, ctx)


def _attrs_in(t) -> list[str]:
    """The attributes the plain checks of a test name (not through `of` or inside `element`)."""
    if not isinstance(t, dict):
        return []
    if "all" in t or "any" in t:
        return [a for x in t.get("all", t.get("any", [])) for a in _attrs_in(x)]
    if "not" in t:
        return _attrs_in(t["not"])
    return [t["attr"]] if "attr" in t and "of" not in t else []


def _all(tests: list, ctx: _Ctx) -> bool | None:
    if not ctx.item:
        attrs = [a.split(".") for x in tests for a in _attrs_in(x)]
        for n in range(1, max((len(a) for a in attrs), default=0)):
            prefixes = {".".join(a[:n]) for a in attrs if len(a) > n}
            for p in sorted(prefixes):
                if p in ctx.bound or sum(1 for a in attrs if len(a) > n and ".".join(a[:n]) == p) < 2:
                    continue
                blocks = [b for b in _block_values(ctx, p) if isinstance(b, dict)]
                if len(blocks) < 2:
                    continue
                return any3(
                    _all(tests, _Ctx(ctx.ix, ctx.addr, ctx.body, ctx.item, {**ctx.bound, p: b})) for b in blocks
                )
    return all3(_test(x, ctx) for x in tests)


def _block_values(ctx: _Ctx, path: str) -> list:
    base, rest = _start(ctx, path)
    out = []
    for v in values(base, rest) if rest else _as_list(base):
        out += v if isinstance(v, list) else [v]
    return out


def _start(ctx: _Ctx, path: str):
    """Where a path starts: the bound block instance of its longest bound prefix, or the subject's body."""
    segs = path.split(".")
    for n in range(len(segs) - 1, 0, -1):
        p = ".".join(segs[:n])
        if p in ctx.bound:
            return ctx.bound[p], segs[n:]
    return ctx.body, segs


def _raw(c: dict, ctx: _Ctx) -> list:
    attr = c.get("attr", "")
    if ctx.item:
        if not attr:
            return [ctx.body]
        out = []
        for v in _json_path(ctx.body, "$." + attr):  # a list is its elements (["*"] for one AWS principal)
            out += [x for x in v if x is not None] if isinstance(v, list) else [] if v is None else [v]
        return out
    if attr == "id" and ctx.addr in ctx.ix.g.resources:
        return ["(id)"]  # every resource has one, known or not
    base, rest = _start(ctx, attr)
    return values(base, rest)


def _documents(c: dict, ctx: _Ctx, raw: list) -> list:
    """A policy attribute that names a `data "aws_iam_policy_document"` reads as the JSON the document produces."""
    R = ctx.ix.g.resources
    docs = [
        policies.render_document(R[e.target].body)
        for e in ctx.ix.out_edges.get(ctx.addr, [])
        if e.attr == c.get("attr") and e.target in R and R[e.target].type == "aws_iam_policy_document"
    ]
    if not docs:
        return raw
    return [v for v in raw if not (isinstance(v, str) and "aws_iam_policy_document" in v)] + docs


def _check(c: dict, ctx: _Ctx) -> bool | None:
    if "of" in c and not ctx.item:
        hops = c["of"] if isinstance(c["of"], list) else [c["of"]]
        rest = {k: v for k, v in c.items() if k != "of"}
        return _hops(hops, rest, ctx.addr, ctx.ix)
    raw = _raw(c, ctx)
    if c.get("inside", {}).get("format", "json") == "json" and "inside" in c and not ctx.item:
        raw = _documents(c, ctx, raw)
    if "inside" in c:
        raw = look_inside(raw, c["inside"])
    present = bool(raw)
    if not raw and "unset" in c:
        raw = [c["unset"]]
    results: list[bool | None] = []
    if "present" in c:
        results.append(present == bool(c["present"]))
    for op in OPS:
        if op == "present" or op not in c:
            continue
        if op == "contains":
            known = [scalar(v) for v in raw]
            if any(_canon(v) == _canon(c[op]) for v in known if v is not _UNKNOWN):
                results.append(True)
            else:
                results.append(None if any(v is _UNKNOWN for v in known) else False)
        else:
            results.append(any3(_compare(op, c[op], v) for v in raw))
    if "element" in c:
        items = [v for v in raw if v is not _UNKNOWN]
        res = [_test(c["element"], _Ctx(ctx.ix, "", it, item=True)) for it in items]
        if any(v is _UNKNOWN for v in raw):
            res.append(None)
        results.append(quantify(c.get("element_quantifier", "any"), res))
    return all3(results)


def _hops(hops: list[dict], check: dict, addr: str, ix: Index) -> bool | None:
    hop, more = hops[0], hops[1:]
    rel = related(ix, addr, hop)
    if rel is None:
        return None
    if more:
        res = [_hops(more, check, a, ix) for a in rel]
    else:
        res = [_test(check, _Ctx(ix, a, ix.g.resources[a].body)) for a in rel]
    return quantify(hop.get("quantifier", "any"), res)
