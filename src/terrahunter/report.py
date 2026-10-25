"""Stage 6, the results: one Markdown report to share (a ticket, a pull request, a wiki page).

For each root: what to fix first (each change with the paths it breaks and where to make it), every attack path hop
by hop with what's wrong at each, the scanner findings, and what the analysis couldn't see. Everything that came from
the folder (names, paths, scanner text) is escaped, so it reads as text, never as Markdown or HTML.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from terrahunter import __version__, arch, chains, deps, graph, sandbox, scanners

_MD = re.compile(r"([\\`*_\[\]#|<>~&!])")  # what could start emphasis, code, a link, HTML or a table cell
_LINE_START = re.compile(r"^(\d*)([+\-=.)])")  # a list or heading marker, were it to start a line
EFFECT = {"breaks": "removes the path", "narrows": "reaches less", "hardens": "harder to exploit"}


@dataclass
class RootResult:
    root: str
    survey: deps.Survey
    graph: graph.Graph
    model: arch.Model
    scan: scanners.Scan | None
    paths: chains.Result


def md(text: object, limit: int = 400) -> str:
    """Folder-derived text as plain Markdown text: one line, every special character escaped."""
    return _LINE_START.sub(r"\1\\\2", _MD.sub(r"\\\1", sandbox.one_line(text, limit)))


def code(text: object, limit: int = 200) -> str:
    """Folder-derived text as inline code: no backtick can end it early, no pipe can split a table cell."""
    return "`" + sandbox.one_line(text, limit).replace("`", "'").replace("|", "\\|") + "`"


def _where(w: dict) -> str:
    return code(f"{w['file']}:{w['line']}" if w["line"] else w["file"])


def _hops_about(c: chains.Chain, step: str) -> list[str]:
    if step == "internet":
        return [h for h in c.hops if h.startswith("Internet")]
    return [h for h in c.hops if step in h and not h.startswith(("reaches:", "Internet"))]


def _name(step: str, comps: dict) -> str:
    return "The internet" if step == "internet" else comps[step].name if step in comps else step


def _path_title(c: chains.Chain, comps: dict) -> str:
    names = [_name(s, comps) for s in c.steps]
    if c.steps == ["internet"]:
        names += [_name(s, comps) for s in c.sinks]
    elif c.sinks:
        names.append(f"{len(c.sinks)} data store{'s' if len(c.sinks) != 1 else ''}")
    return " → ".join(md(n, 80) for n in names)


def _root(r: RootResult) -> list[str]:
    comps = {c.id: c for c in r.model.components}
    p = r.paths
    out = [f"## {md(r.root)}", ""]
    counts = {s: sum(1 for c in p.chains if c.severity == s) for s in ("critical", "high", "medium")}
    out.append(
        f"{len(p.chains)} attack path{'s' if len(p.chains) != 1 else ''}"
        + (f" ({', '.join(f'{n} {s}' for s, n in counts.items() if n)})" if p.chains else "")
        + f" · {len(r.graph.resources)} resources · {len(r.graph.edges)} connections"
        + (f" · {len(r.scan.findings)} scanner findings" if r.scan else "")
        + (f" · {len(r.graph.unknown)} modules not available" if r.graph.unknown else "")
    )
    out.append("")

    if p.fixes:
        out += ["### Fix first", "", "| # | Change | Effect | Paths | Where |", "|---|---|---|---|---|"]
        for i, f in enumerate(p.fixes, 1):
            paths = ", ".join(str(n + 1) for n in f.chains)
            where = "<br>".join(f"{code(w['address'])} {_where(w)}" for w in f.where[:4])
            more = f"<br>+{len(f.where) - 4} more" if len(f.where) > 4 else ""
            out.append(f"| {i} | {md(f.action)} | {EFFECT[f.effect]} | {paths} | {where}{more} |")
        out.append("")

    out += ["### Attack paths", ""]
    if not p.chains:
        out += ["Nothing from the internet reaches data or a workload an attacker could take over.", ""]
    fix_no = {f.id: i for i, f in enumerate(p.fixes, 1)}
    for n, c in enumerate(p.chains, 1):
        out += [f"#### {n}. {c.severity.upper()} · {c.confidence} · {_path_title(c, comps)}", "", md(c.entry), ""]
        for k, step in enumerate(c.steps, 1):
            comp = comps.get(step)
            head = f"{k}. **{md(_name(step, comps), 80)}**"
            if comp:
                head += f" ({md(comp.tname)}, {code(comp.file + ':' + str(comp.line))})"
            out.append(head)
            bad = [b.text for b in comp.badges if b.risk] if comp else []
            worst = [
                f"{f['severity'].lower()}: {f['title'] or f['id']}"
                for f in (comp.findings if comp else [])
                if f["severity"] in ("CRITICAL", "HIGH")
            ][:3]
            for line in bad + worst:
                out.append(f"   - ⚠ {md(line)}")
            for line in _hops_about(c, step):
                out.append(f"   - {md(line)}")
        if c.sinks:
            out.append(f"{len(c.steps) + 1}. **Reaches {len(c.sinks)} data store{'s' if len(c.sinks) != 1 else ''}**")
            reach = next((h for h in c.hops if h.startswith("reaches:")), "")
            for s in c.sinks:
                sens = " ⚠ sensitive" if f"{s} ⚠sensitive" in reach else ""
                kind = comps[s].tname if s in comps else ""
                out.append(f"   - {code(s)} {md(kind)}{sens}")
        if c.fixes:
            refs = ", ".join(f"#{n}" for n in sorted(fix_no[f] for f in c.fixes if f in fix_no))
            out += ["", f"Fixes: {refs}"]
        out.append("")

    if p.leaks:
        out += [
            "### If these credentials leak",
            "",
            (
                "What an attacker holding each identity's credentials could become and reach, worst first: its own "
                "permissions, roles it can assume, and the privilege-escalation and lateral-movement techniques it has "
                "the permissions for (the rule ids are the knowledge base's)."
            ),
            "",
        ]
        for n, c in enumerate(p.leaks, 1):
            out += [f"#### {n}. {c.severity.upper()} · {c.confidence} · {md(c.entry)}", ""]
            out += [f"- {md(h)}" for h in c.hops if not h.startswith("reaches:")]
            reach = next((h for h in c.hops if h.startswith("reaches:")), "")
            if reach:
                out.append(f"- **{md(reach)}**")
            out.append("")

    if r.scan:
        out += ["### Findings", ""]
        st = ", ".join(
            f"{n} {s['version'] or ''}".rstrip()
            + (f": {s['findings']}" if s["ok"] else f": failed ({md(s['error'], 200)})")
            for n, s in r.scan.status.items()
        )
        sev: dict[str, int] = {}
        for f in r.scan.findings:
            sev[f.severity or "unrated"] = sev.get(f.severity or "unrated", 0) + 1
        out += [f"{st}. " + ", ".join(f"{k.lower()} {v}" for k, v in sev.items()), ""]
        top = [f for f in r.scan.findings if f.severity in ("CRITICAL", "HIGH")][:25]
        if top:
            out += ["| Severity | Check | Resource | Where | |", "|---|---|---|---|---|"]
            for f in top:
                out.append(
                    f"| {f.severity.lower()} | {code(f.id, 40)} | {code(f.address or '(not placed)')} | "
                    f"{code(f'{f.file}:{f.line}')} | {md(f.title, 160)} |"
                )
            rest = sum(1 for f in r.scan.findings if f.severity in ("CRITICAL", "HIGH")) - len(top)
            out += (["", f"…and {rest} more critical or high (all in `--graph-json`)."] if rest > 0 else []) + [""]

    gaps = [n for n in r.survey.open] + list(r.graph.unknown.values())
    if gaps or r.survey.notes or r.graph.notes:
        out += ["### Not seen", "", "What the analysis couldn't read: paths through these may be missing.", ""]
        seen = set()
        for n in r.survey.open:
            seen.add(f"module.{n.name}")
            out.append(f"- {code(n.name)} ({md(n.status)}): {md(n.detail, 200)}")
        for u in r.graph.unknown.values():
            if u.address not in seen and u.address.rsplit(".", 1)[-1] not in {x.name for x in r.survey.open}:
                out.append(f"- {code(u.address)} ({md(u.status)}): {md(u.detail, 200)}")
        for note in r.survey.notes + r.graph.notes + (r.scan.notes if r.scan else []):
            out.append(f"- {md(note, 300)}")
        out.append("")
    return out


def render(folder: str, results: list[RootResult]) -> str:
    total = sum(len(r.paths.chains) for r in results)
    crit = sum(1 for r in results for c in r.paths.chains if c.severity == "critical")
    out = [
        f"# terrahunter report: {md(folder, 120)}",
        "",
        f"terrahunter {md(__version__)} · {len(results)} root module{'s' if len(results) != 1 else ''} · "
        f"{total} attack path{'s' if total != 1 else ''}" + (f", {crit} critical" if crit else ""),
        "",
        (
            "Paths are mapped from the configuration alone (AWS, Azure and Google Cloud), and deny statements, "
            "conditions and permission boundaries aren't evaluated yet, so a grant may be narrower than it reads. Open the diagram "
            "(`terrahunter-diagram.html`) to walk through each path."
        ),
        "",
    ]
    for r in results:
        out += _root(r)
    return "\n".join(out).rstrip() + "\n"
