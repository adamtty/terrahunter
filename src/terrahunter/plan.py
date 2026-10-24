"""Plan mode: a `terraform show -json` plan (or state) makes the graph what will really be deployed.

Read from the code alone, the graph has one node per resource block, and values that depend on variables, tfvars,
conditionals or data sources stay as expressions. The plan has every instance with its values, so:

- **instances**: `aws_subnet.pub` with `count = 2` becomes `aws_subnet.pub[0]` and `aws_subnet.pub[1]`, a module
  called with `for_each` becomes one set of resources per key, and a block with `count = 0` leaves the map;
- **values**: where the code has an expression the plan resolved (`var.public ? "0.0.0.0/0" : …`, a CIDR from
  tfvars), the plan's value takes its place, so the exposure checks see what will be deployed. Values the plan marks
  sensitive are never copied in; values unknown until apply are absent from a plan and stay as they were;
- **connections**: each one is re-drawn between instances. A reference to a literal index (`aws_subnet.pub[0]`)
  goes to that instance only; inside a module instance, references stay inside it; counted resources referencing
  counted resources with the same indexes pair index by index; anything else reaches every instance.

The plan is input like the code: it's read with a size limit, never executed, and anything in it that isn't the
expected shape is skipped (and noted), never fatal.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import replace
from pathlib import Path

from terrahunter import graph, sandbox

MAX_PLAN_BYTES = 128 * 1024 * 1024
_INDEX = re.compile(r"\[[^\]]*\]")
_LAST_INDEX = re.compile(r"\[([^\]]*)\]$")
_MODULE_SEG = re.compile(r'module\.[A-Za-z0-9_-]+(?:\["(?:[^"\\]|\\.)*"\]|\[\d+\])?')


class PlanError(RuntimeError):
    """The plan can't be read at all."""


def load(path: Path) -> dict:
    try:
        data = json.loads(sandbox.read_regular(Path(path), MAX_PLAN_BYTES).decode("utf-8", "replace"))
    except OSError as e:
        raise PlanError(f"can't read the plan: {sandbox.one_line(e, 200)}") from None
    except (ValueError, RecursionError):
        raise PlanError("the plan isn't JSON: pass the output of `terraform show -json <plan file>`") from None
    if not isinstance(data, dict) or not isinstance(data.get("planned_values") or data.get("values"), dict):
        raise PlanError("no planned_values (or values) in it: pass the output of `terraform show -json <plan file>`")
    return data


def _instances(data: dict) -> dict[str, list[dict]]:
    """Block address (indexes removed) → its planned instances [{address, index, values, sensitive}]."""
    out: dict[str, list[dict]] = {}
    top = (data.get("planned_values") or data.get("values") or {}).get("root_module")
    stack = [top] if isinstance(top, dict) else []
    seen = 0
    while stack:
        m = stack.pop()
        for r in m.get("resources") or []:
            if not isinstance(r, dict) or not isinstance(r.get("address"), str):
                continue
            seen += 1
            if seen > sandbox.MAX_FILES * 10:
                return out
            out.setdefault(_INDEX.sub("", r["address"]), []).append(
                {
                    "address": sandbox.one_line(r["address"], 300),
                    "index": r.get("index"),
                    "values": r.get("values") if isinstance(r.get("values"), dict) else {},
                    "sensitive": r.get("sensitive_values") if isinstance(r.get("sensitive_values"), dict) else {},
                }
            )
        stack += [c for c in m.get("child_modules") or [] if isinstance(c, dict)]
    return out


def _configured(data: dict) -> set[str]:
    """Every resource block address in the plan's configuration (modules included, no indexes)."""
    out: set[str] = set()
    top = (data.get("configuration") or {}).get("root_module")
    stack = [("", top)] if isinstance(top, dict) else []
    while stack and len(out) < sandbox.MAX_FILES * 10:
        prefix, m = stack.pop()
        for r in m.get("resources") or []:
            if isinstance(r, dict) and isinstance(r.get("address"), str):
                out.add(prefix + r["address"])
        for name, call in (m.get("module_calls") or {}).items() if isinstance(m.get("module_calls"), dict) else []:
            if isinstance(call, dict) and isinstance(call.get("module"), dict):
                stack.append((f"{prefix}module.{name}.", call["module"]))
    return out


def _hcl(v):
    """A plan value in the parser's shape: strings quoted, the rest as they are."""
    if isinstance(v, str):
        return f'"{v}"'
    if isinstance(v, list):
        return [_hcl(x) for x in v]
    if isinstance(v, dict):
        return {k: _hcl(x) for k, x in v.items()}
    return v


def _expr(v) -> bool:
    return isinstance(v, str) and "${" in v or isinstance(v, list) and any(_expr(x) for x in v)


def overlay(body: dict, values: dict, sensitive) -> dict:
    """The body with the plan's known values in place of expressions (and of attributes the code leaves out, such
    as blocks from a `dynamic`). Sensitive values are left alone."""
    out = dict(body)
    sens = sensitive if isinstance(sensitive, dict) else {}
    for k, pv in values.items():
        if pv is None or sens.get(k) is True or k.startswith("__"):
            continue
        bv = body.get(k)
        if isinstance(bv, list) and isinstance(pv, list) and bv and all(isinstance(x, dict) for x in bv + pv):
            if len(bv) == len(pv):  # nested blocks, one for one
                sub = sens.get(k) if isinstance(sens.get(k), list) else []
                out[k] = [
                    overlay(b, p, sub[i] if i < len(sub) else {}) for i, (b, p) in enumerate(zip(bv, pv, strict=True))
                ]
            elif not _contains_sensitive(sens.get(k)):
                out[k] = _hcl(pv)
        elif (bv is None or _expr(bv)) and not _contains_sensitive(sens.get(k)):
            out[k] = _hcl(pv)
    return out


def _contains_sensitive(s) -> bool:
    if s is True:
        return True
    if isinstance(s, dict):
        return any(_contains_sensitive(x) for x in s.values())
    if isinstance(s, list):
        return any(_contains_sensitive(x) for x in s)
    return False


def _modules(addr: str) -> list[str]:
    """The module segments of an address, with their indexes: `module.a["x"].aws_y.z` → ['module.a["x"]']."""
    out, pos = [], 0
    while m := _MODULE_SEG.match(addr, pos):  # consecutive from the start: a key may hold dots
        out.append(m.group(0))
        pos = m.end() + 1
    return out


def _own_index(addr: str) -> str | None:
    m = _LAST_INDEX.search(addr)
    return m.group(1).strip('"') if m else None


def apply(g: graph.Graph, data: dict) -> graph.Graph:
    """The graph with the plan's instances, values and instance-to-instance connections."""
    planned = _instances(data)
    configured = _configured(data)
    if planned and not (set(planned) & set(g.resources)):
        g.notes.append("the plan doesn't match this root module (none of its resources are here), so it wasn't used")
        return g
    expanded: dict[str, list[str]] = {}  # block address → instance addresses
    resources: dict[str, graph.Resource] = {}
    gone = []
    for addr, r in g.resources.items():
        insts = planned.get(addr)
        if not insts:
            if addr in configured and r.mode == "managed":
                gone.append(addr)  # count = 0, or for_each over nothing: it won't exist
                continue
            resources[addr] = r
            expanded[addr] = [addr]
            continue
        expanded[addr] = []
        for i in sorted(insts, key=lambda x: x["address"]):
            a = i["address"]
            suffix = a[len(_INDEX.sub("", a)) :] if a.endswith("]") else ""
            body = overlay(copy.deepcopy(r.body), i["values"], i["sensitive"])
            mods = _modules(a)
            # the module instance's keys in the name, so web in module.web["a"] and ["b"] read apart: `web (a)`
            keys = [_own_index(m) for m in mods if _own_index(m) is not None]
            name = r.name + (suffix or "") + (f" ({', '.join(keys)})" if keys else "")
            resources[a] = replace(r, address=a, name=name, module=".".join(mods), body=body)
            expanded[addr].append(a)
    if gone:
        g.info.append(
            f"{len(gone)} resource block{'s' if len(gone) != 1 else ''} the plan creates no instance of (count = 0): "
            + ", ".join(gone[:5])
            + (f" (+{len(gone) - 5} more)" if len(gone) > 5 else "")
        )
    unplanned = [
        a for a in g.resources if a not in planned and a not in configured and g.resources[a].mode == "managed"
    ]
    if unplanned:
        g.notes.append(f"{len(unplanned)} resource(s) aren't in the plan, so they're kept as read from the code")

    edges: list[graph.Edge] = []
    seen: set[tuple[str, str, str]] = set()
    for e in g.edges:
        sources = expanded.get(e.source, [])
        targets = expanded.get(e.target, [e.target])  # an unknown module stays itself
        if e.index:
            hit = [t for t in targets if _own_index(t) == e.index]
            targets = hit or targets
        for s in sources:
            ts = _pair(s, e.source, targets, e.target, expanded)
            for t in ts:
                if s != t and (s, t, e.attr) not in seen:
                    seen.add((s, t, e.attr))
                    edges.append(graph.Edge(s, t, e.attr))
    g.resources, g.edges = resources, edges
    return g


def _pair(s: str, s_block: str, targets: list[str], t_block: str, expanded: dict) -> list[str]:
    """The target instances one source instance connects to."""
    # inside the same module instance: a reference never crosses into a sibling instance of the module
    sm, tm = _modules(s_block), _modules(t_block)
    common = 0
    while common < min(len(sm), len(tm)) and sm[common] == tm[common]:
        common += 1
    if common:
        mine = _modules(s)[:common]
        targets = [t for t in targets if _modules(t)[:common] == mine] or targets
    # counted → counted with the same indexes: index by index
    si = _own_index(s)
    t_all = expanded.get(t_block, [])
    if (
        si is not None
        and len(targets) > 1
        and {_own_index(x) for x in t_all} == {_own_index(x) for x in expanded.get(s_block, [])}
    ):
        same = [t for t in targets if _own_index(t) == si]
        targets = same or targets
    return targets
