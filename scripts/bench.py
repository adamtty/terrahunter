"""Score terrahunter's attack paths against the knowledge base's labelled benchmark.

The knowledge base (adamtty/terrahunter-kb) has answer keys for deliberately vulnerable Terraform: each root's
expected attack paths (entry, steps, what they reach, how sure) and its `not_paths` (things that look exposed but
aren't). This runs terrahunter's stages 1-5 on every labelled root, without scanners, and compares:

- **recall**: expected paths terrahunter finds (an attack path with the same entry, or through the expected first
  hop), and of the data each one reaches, how much terrahunter's path reaches too;
- **precision**: terrahunter's paths that match an expected one; the rest are *contradicted* (they start at, or end
  at, something the key says isn't a path, and the key's reason is shown) or *unlabelled*;
- **confidence**: terrahunter's confidence against the key's, side by side.

Paths that start from credentials the project hands the attacker (`attacker-principal`) are scored apart, as
**given-credentials recall**: terrahunter's credentials search runs from the key's start identity, and the path is
found when the identity it ends as, or anything it reaches, is among what the search gains (the start itself
doesn't count).

  python scripts/bench.py --kb ../terrahunter-kb                  # every project (fetch them first:
  python scripts/bench.py --kb ../terrahunter-kb --project terragoat   #   python scripts/bench/fetch.py in the kb)
  python scripts/bench.py --kb ../terrahunter-kb --report bench.md --json bench.json

A generated estate (a folder with `bench/source.yaml` and `bench/expected.json`, its roots given as
`<repository>/<root>` with the variables, var files and plan its key assumes) is scored the same way with
`--estate DIR`, plus its paths from other accounts (`other-account`), against "from other accounts", and its
findings (hard-coded secrets, long-lived keys) against terrahunter's own:

  python scripts/bench.py --estate ~/estates/harbourline-2026-11-02 --report estate.md

With `--together`, an estate's roots are analysed as one (terrahunter's `--estate`: merged, linked, accounts kept
apart), so paths that cross roots and repositories count. Each root's key is scored against the paths that start in
that root, by the addresses its own code uses; what a path reaches may be in any root.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import re
import sys
from pathlib import Path

from terrahunter import arch, chains, deps, escalate, estate, graph, iam, plan, secrets

_INDEX = re.compile(r"\[[^\]]*\]")
# the inputs each project's answer key assumes (from its source.yaml notes), given as -var / -var-file would be
INPUTS = {
    # the scenarios open their entry points to the player's address (cg_whitelist); the key's attacker is the player
    "cloudgoat": {"variables": {"cg_whitelist": ['"0.0.0.0/0"'], "cgid": '"bench"', "profile": '"bench"'}},
    # the default challenge set, which terraform.tfvars.example turns on (every *_enabled defaults to false)
    "cloudfoxable": {"var_files": ["aws/terraform.tfvars.example"]},
    # every finding on: the full corpus the README describes and NCC's sample audits use
    "sadcloud": {"variables": {"all_findings": True}},
}
CONF = {"direct": "certain", "likely": "likely", "possible": "possible"}  # terrahunter → the key's words


def norm(addr: str) -> str:
    return _INDEX.sub("", addr)


def entry_of(c: chains.Chain) -> str:
    return c.steps[1] if len(c.steps) > 1 else (c.sinks[0] if c.sinks else "")


def build_root(folder: Path, root: str, inputs: dict | None = None) -> tuple[graph.Graph, graph.Graph]:
    """A root's graph with the key's inputs (and plan), and as written (for the secrets in the code itself)."""
    inputs = inputs or {}
    files = [folder / f for f in inputs.get("var_files", [])]
    g = graph.build(folder, root, variables=inputs.get("variables"), var_files=[f for f in files if f.is_file()])
    if inputs.get("plan"):  # an estate's plan for the root: the instances count/for_each make
        g = plan.apply(g, plan.load(folder / inputs["plan"]))
    given = inputs.get("variables") or inputs.get("var_files") or inputs.get("plan")
    return g, graph.build(folder, root) if given else g


def score_root(folder: Path, key: dict, inputs: dict | None = None) -> dict:
    with contextlib.redirect_stdout(io.StringIO()):
        g, written = build_root(folder, key["root"], inputs)
        model = arch.build(g)
        found = chains.build(g, model).chains
    return score(key, g, model, found, written)


class View:
    """How a graph's addresses compare with a key's: as they are, or, in an estate graph, as the key's root's own code
    names them (its root's prefix taken off), and which of them are that root's."""

    def __init__(self, root: str | None = None):
        self.root = root

    def __call__(self, addr: str) -> str:
        return norm(estate.local(addr) if self.root is not None else addr)

    def here(self, addr: str) -> bool:
        return self.root is None or estate.root_of(addr) == self.root


def score(
    key: dict,
    g: graph.Graph,
    model: arch.Model,
    found: list[chains.Chain],
    written: graph.Graph,
    view: View | None = None,
) -> dict:
    """One root's key against terrahunter's results: of that root, or (with a view) of an estate graph."""
    root = key["root"]
    view = view or View()
    found = [c for c in found if view.here(entry_of(c))]  # the paths that start in this root

    def reach(c: chains.Chain) -> set[str]:
        """What a path reaches: the data, what's kept in it, what it takes over, and the components it goes through
        (a VM it logs in to is controlled, and keys list it)."""
        return {view(x) for x in [*c.steps[1:], *c.sinks, *c.within, *c.controls]}

    expected = [p for p in key.get("paths", []) if p["steps"][:1] == ["internet"]]
    given = [p for p in key.get("paths", []) if p["steps"][:1] == ["attacker-principal"]]
    others = [p for p in key.get("paths", []) if p["steps"][:1] == ["other-account"]]
    not_paths = {norm(n["resource"]): n["why"] for n in key.get("not_paths", [])}
    out = {
        "root": root,
        "resources": sum(view.here(a) for a in g.resources),
        "expected": [],
        "given_credentials": len(given),
        "found": [],
    }
    out["given"] = score_given(g, model, given, view)
    out["outside"] = score_outside(g, model, others, view) if others else []
    # the secrets in the configuration as written: values the key's inputs give aren't in the code
    out["findings"], out["false_findings"] = score_findings(written, key, view)
    used: set[int] = set()
    for p in expected:
        e, first = norm(p["entry"]), norm(p["steps"][1]) if len(p["steps"]) > 1 else norm(p["entry"])
        want = {norm(r["resource"]) for r in p.get("reaches", [])}
        best, best_hit, best_rank = None, -1, (False, -1, -1)
        for i, c in enumerate(found):
            on_path = {view(x) for x in c.steps[1:]} | ({view(c.sinks[0])} if c.steps == ["internet"] else set())
            # the path's entry, its other ways in, and what opens the entry to the internet (a public container
            # on its storage account, a bucket policy on its bucket): keys may name either
            entries = {view(entry_of(c)), *map(view, c.also), *(view(o) for _, o in model.exposed.get(entry_of(c), []))}
            if e in entries or first in on_path | entries:
                # a path that starts where the key's does comes before one that only passes through it; then the
                # one that reaches more of it, then the one that goes the key's way
                hit = len(want & reach(c))
                rank = (e in entries, hit, len({norm(x) for x in p["steps"]} & {view(x) for x in c.steps}))
                if best is None or rank > best_rank:
                    best, best_hit, best_rank = i, hit, rank
        row = {
            "id": p["id"],
            "entry": p["entry"],
            "found": best is not None,
            "reaches": len(want),
            "reached": max(best_hit, 0),
            "key_confidence": p.get("confidence", ""),
            "why": p.get("why", ""),
        }
        if best is not None:
            used.add(best)
            row["confidence"] = CONF.get(found[best].confidence, found[best].confidence)
            row["missed"] = sorted(want - reach(found[best]))
        out["expected"].append(row)
    for i, c in enumerate(found):
        if i in used:
            verdict, reason = "matched", ""
        else:
            # a not-path is something that looks exposed but isn't: a path that starts there (or is that store on
            # the internet); reaching it from inside, with an identity's own grants, isn't what the key rules out
            hit = view(entry_of(c)) if view(entry_of(c)) in not_paths else None
            verdict, reason = ("contradicted", f"{hit}: {not_paths[hit]}") if hit else ("unlabelled", "")
        out["found"].append(
            {
                "entry": entry_of(c),
                "severity": c.severity,
                "confidence": c.confidence,
                "sinks": len(c.sinks),
                "verdict": verdict,
                "reason": reason,
            }
        )
    return out


def score_given(g: graph.Graph, model: arch.Model, given: list[dict], view: View | None = None) -> list[dict]:
    """The paths that start from given credentials, against the credentials search from the same identity."""
    view = view or View()
    im = iam.Models(g) if given else None
    by_norm = {view(a): a for a in g.resources if view.here(a)}
    rows = []
    for p in given:
        start = by_norm.get(norm(p["steps"][1]))
        want = {norm(r["resource"]) for r in p.get("reaches", [])}
        row = {"id": p["id"], "start": p["steps"][1], "found": False, "reaches": len(want), "reached": 0}
        if start is None:
            row["why"] = "the start identity isn't in the graph"
            rows.append(row)
            continue
        r = escalate.search(g, model, start, im)
        have = {view(a) for (_, a) in r.gains} - {view(start)}
        last = norm(p["steps"][-1])
        row["found"] = last in have or bool(want & have)
        row["reached"] = len(want & have)
        row["missed"] = sorted(want - have)
        row["techniques"] = sorted({gn.rule for gn in r.gains.values() if gn.rule.startswith("privesc")})
        row["key_techniques"] = p.get("techniques", [])
        rows.append(row)
    return rows


def score_outside(g: graph.Graph, model: arch.Model, others: list[dict], view: View | None = None) -> list[dict]:
    """Paths that start from a principal outside the estate's accounts, against terrahunter's "from other accounts":
    found when it lists the key's first role, and what it reaches from there."""
    view = view or View()
    mine = {view(c.steps[1]): c for c in escalate.outside(g, model) if view.here(c.steps[1])}
    rows = []
    for p in others:
        c = mine.get(norm(p["steps"][1]))
        want = {norm(r["resource"]) for r in p.get("reaches", [])}
        have = {view(x) for x in [*c.steps[1:], *c.sinks, *c.controls]} if c else set()
        rows.append(
            {
                "id": p["id"],
                "start": p["steps"][1],
                "found": c is not None,
                "reaches": len(want),
                "reached": len(want & have),
                "missed": sorted(want - have),
            }
        )
    return rows


FINDING_IDS = {"hardcoded-secret": "TH-SECRET", "long-lived-key": "TH-KEY"}


def score_findings(g: graph.Graph, key: dict, view: View | None = None) -> tuple[list[dict], list[dict]]:
    """An estate's findings (hard-coded secrets, long-lived keys) against terrahunter's own; and the not_findings
    it reports anyway. Exposures (a public control plane) are scored as found when the resource is drawn."""
    view = view or View()
    mine = {(f.id, view(f.address)) for f in secrets.find(g) if view.here(f.address)}
    drawn = {view(a) for a in g.resources if view.here(a)}
    rows = []
    for f in key.get("findings", []):
        res = norm(f["resource"])
        fid = FINDING_IDS.get(f.get("kind", ""))
        ok = (fid, res) in mine if fid else res in drawn
        rows.append({"id": f["id"], "kind": f.get("kind", ""), "resource": f["resource"], "found": ok})
    false = [
        {"id": f["id"], "resource": f["resource"], "why": f.get("why", "")}
        for f in key.get("not_findings", [])
        if any(r == norm(f["resource"]) for _, r in mine)
    ]
    return rows, false


def totals(rows: list[dict]) -> dict:
    exp = [p for r in rows for p in r["expected"]]
    fnd = [c for r in rows for c in r["found"]]
    reach = sum(p["reaches"] for p in exp if p["found"])
    return {
        "expected": len(exp),
        "found": sum(p["found"] for p in exp),
        "recall": sum(p["found"] for p in exp) / len(exp) if exp else 0.0,
        "reach_recall": sum(p["reached"] for p in exp if p["found"]) / reach if reach else 0.0,
        "paths": len(fnd),
        "matched": sum(c["verdict"] == "matched" for c in fnd),
        "contradicted": sum(c["verdict"] == "contradicted" for c in fnd),
        "unlabelled": sum(c["verdict"] == "unlabelled" for c in fnd),
        "precision": sum(c["verdict"] == "matched" for c in fnd) / len(fnd) if fnd else 0.0,
        "given_credentials": sum(r["given_credentials"] for r in rows),
        "outside": sum(len(r.get("outside", [])) for r in rows),
        "outside_found": sum(p["found"] for r in rows for p in r.get("outside", [])),
        "findings": sum(len(r.get("findings", [])) for r in rows),
        "findings_found": sum(p["found"] for r in rows for p in r.get("findings", [])),
        "false_findings": sum(len(r.get("false_findings", [])) for r in rows),
        "given_found": sum(p["found"] for r in rows for p in r.get("given", [])),
        "given_recall": (
            sum(p["found"] for r in rows for p in r.get("given", [])) / sum(len(r.get("given", [])) for r in rows)
            if any(r.get("given") for r in rows)
            else 0.0
        ),
        "given_reach_recall": (
            sum(p["reached"] for r in rows for p in r.get("given", []))
            / max(1, sum(p["reaches"] for r in rows for p in r.get("given", [])))
        ),
    }


def markdown(results: dict[str, list[dict]]) -> str:
    allrows = [r for rows in results.values() for r in rows]
    t = totals(allrows)
    lines = [
        "# terrahunter benchmark",
        "",
        (
            f"**Recall {t['recall']:.0%}** ({t['found']} of {t['expected']} expected internet paths found; of the data they "
            f"reach, {t['reach_recall']:.0%}) · **precision {t['precision']:.0%}** ({t['matched']} of {t['paths']} "
            f"paths match; {t['contradicted']} contradicted by the key, {t['unlabelled']} unlabelled) · "
            f"**given-credentials recall {t['given_recall']:.0%}** ({t['given_found']} of {t['given_credentials']} paths "
            f"that start from credentials the project hands the attacker; of what they reach, "
            f"{t['given_reach_recall']:.0%})"
        ),
        "",
        *(
            [
                (
                    "Inputs the answer keys assume: CloudGoat's `cg_whitelist` (the player's address) is `0.0.0.0/0`, "
                    "the player being the attacker; CloudFoxable uses its `terraform.tfvars.example` (its default "
                    "challenges); sadcloud runs with `all_findings = true` (the README's full corpus)."
                ),
                "",
            ]
            if set(results) & set(INPUTS)
            else []
        ),
        *(
            [
                (
                    f"From other accounts: {t['outside_found']} of {t['outside']} found · findings (hard-coded "
                    f"secrets, long-lived keys, exposures): {t['findings_found']} of {t['findings']} found, "
                    f"{t['false_findings']} reported where the key says there's none"
                ),
                "",
            ]
            if t["outside"] or t["findings"]
            else []
        ),
        "| Project | Roots | Expected | Found | Recall | Paths | Matched | Contradicted | Unlabelled | Given found |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for name, rows in results.items():
        x = totals(rows)
        given = f"{x['given_found']} of {x['given_credentials']}" if x["given_credentials"] else "—"
        lines.append(
            f"| {name} | {len(rows)} | {x['expected']} | {x['found']} | {x['recall']:.0%} | {x['paths']} | "
            f"{x['matched']} | {x['contradicted']} | {x['unlabelled']} | {given} |"
        )
    conf: dict[tuple[str, str], int] = {}
    for p in (p for r in allrows for p in r["expected"] if p["found"]):
        conf[(p["key_confidence"], p["confidence"])] = conf.get((p["key_confidence"], p["confidence"]), 0) + 1
    if conf:
        lines += [
            "",
            "**Confidence** (key → terrahunter): " + ", ".join(f"{a} → {b}: {n}" for (a, b), n in sorted(conf.items())),
        ]
    for name, rows in results.items():
        misses = [(r["root"], p) for r in rows for p in r["expected"] if not p["found"]]
        given_misses = [(r["root"], p) for r in rows for p in r.get("given", []) if not p["found"]]
        partial = [(r["root"], p) for r in rows for p in r["expected"] if p["found"] and p.get("missed")]
        wrong = [(r["root"], c) for r in rows for c in r["found"] if c["verdict"] == "contradicted"]
        if not (misses or partial or wrong or given_misses):
            continue
        lines += ["", f"## {name}", ""]
        for root, p in misses:
            lines.append(f"- **missed** {p['id']} `{p['entry']}` ({root}): {p['why'][:300]}")
        for _, p in partial:
            lines.append(
                f"- **partly** {p['id']} `{p['entry']}`: reaches {p['reached']} of {p['reaches']}; missing "
                + ", ".join(f"`{m}`" for m in p["missed"][:6])
                + (" …" if len(p["missed"]) > 6 else "")
            )
        for root, c in wrong:
            lines.append(f"- **contradicted** `{c['entry']}` ({root}, {c['severity']}): {c['reason'][:300]}")
        for root, p in given_misses:
            techs = ", ".join(p.get("key_techniques") or []) or "none cited"
            lines.append(f"- **given, missed** {p['id']} from `{p['start']}` ({root}): techniques {techs}")
    return "\n".join(lines) + "\n"


def _shaped(v):
    """A YAML value in the parser's shape, as --var gives it: strings quoted, the rest as they are."""
    if isinstance(v, str):
        return f'"{v}"'
    if isinstance(v, list):
        return [_shaped(x) for x in v]
    if isinstance(v, dict):
        return {k: _shaped(x) for k, x in v.items()}
    return v


def score_estate(folder: Path, together: bool = False) -> list[dict]:
    """A generated estate: its roots (bench/source.yaml: path, variables, var_files, plan) against its answer key
    (bench/expected.json, one entry per root, `root` = the root's path); `together`, analysed as one."""
    import yaml  # a dev dependency: only the benchmark reads YAML

    source = yaml.safe_load((folder / "bench" / "source.yaml").read_text()) or {}
    keys = {k["root"]: k for k in json.loads((folder / "bench" / "expected.json").read_text())}
    todo = []
    for r in source.get("roots", []):
        key = keys.get(r["path"])
        if key is None:
            print(f"{folder.name}: {r['path']} has no answer key; skipped", file=sys.stderr)
            continue
        variables = dict(r.get("variables") or {})
        # or written as -var=name=value in the notes (an estate laid out like a knowledge-base project)
        variables |= {
            k: v for k, v in re.findall(r"-var[= ]([A-Za-z_][\w-]*)=([^\s\"'`,;]+)", r.get("variable_notes", ""))
        }
        plan_file = r.get("plan")
        if plan_file is None and "plan" not in r and (folder / r["path"] / "plan.json").is_file():
            plan_file = f"{r['path']}/plan.json"  # the plan next to its root
        inputs = {
            "variables": {k: _shaped(v) for k, v in variables.items()} or None,
            "var_files": r.get("var_files") or [],
            "plan": plan_file,
        }
        todo.append((key, inputs))
    if not together:
        return [score_root(folder, key, inputs) for key, inputs in todo]
    with contextlib.redirect_stdout(io.StringIO()):
        built = {key["root"]: build_root(folder, key["root"], inputs) for key, inputs in todo}
        g = estate.merge({r: b[0] for r, b in built.items()})
        estate.link(g, {r: deps.survey(folder, r) for r in built})
        written = estate.merge({r: b[1] for r, b in built.items()})
        model = arch.build(g)
        found = chains.build(g, model).chains
    return [score(key, g, model, found, written, View(key["root"])) for key, _ in todo]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--kb", type=Path, help="a checkout of terrahunter-kb, with its projects fetched")
    ap.add_argument(
        "--estate",
        type=Path,
        action="append",
        default=[],
        help="a generated estate (its bench/source.yaml and bench/expected.json), scored on its own; repeatable",
    )
    ap.add_argument(
        "--together", action="store_true", help="analyse each estate's roots as one, so paths may cross roots"
    )
    ap.add_argument("--project", action="append", help="only these projects (repeatable)")
    ap.add_argument("--report", type=Path, help="write the Markdown report here")
    ap.add_argument("--json", type=Path, help="write the full results here")
    a = ap.parse_args(argv)
    results: dict[str, list[dict]] = {}
    for est in a.estate:
        results[est.name] = score_estate(est, a.together)
    if a.kb is None and not a.estate:
        ap.error("give --kb, --estate, or both")
    for key_file in sorted((a.kb / "bench").glob("*/expected.json")) if a.kb else []:
        name = key_file.parent.name
        if a.project and name not in a.project:
            continue
        folder = a.kb / "downloads" / "bench" / name
        if not folder.is_dir():
            print(f"{name}: not fetched (python scripts/bench/fetch.py {name} in the kb); skipped", file=sys.stderr)
            continue
        results[name] = [score_root(folder, root, INPUTS.get(name)) for root in json.loads(key_file.read_text())]
    if not results:
        print("nothing to score", file=sys.stderr)
        return 2
    md = markdown(results)
    print(md)
    if a.report:
        a.report.write_text(md)
    if a.json:
        a.json.write_text(
            json.dumps({"totals": totals([r for v in results.values() for r in v]), "projects": results}, indent=1)
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
