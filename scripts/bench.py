"""Score terrahunter's attack paths against the knowledge base's labelled benchmark.

The knowledge base (adamtty/terrahunter-kb) has answer keys for deliberately vulnerable Terraform: each root's
expected attack paths (entry, steps, what they reach, how sure) and its `not_paths` (things that look exposed but
aren't). This runs terrahunter's stages 1-5 on every labelled root, without scanners, and compares:

- **recall**: expected paths terrahunter finds (an attack path with the same entry, or through the expected first
  hop), and of the data each one reaches, how much terrahunter's path reaches too;
- **precision**: terrahunter's paths that match an expected one; the rest are *contradicted* (they start at, or end
  at, something the key says isn't a path, and the key's reason is shown) or *unlabelled*;
- **confidence**: terrahunter's confidence against the key's, side by side.

Paths that start from credentials the project hands the attacker (`attacker-principal`) need an "assume a
compromised identity" mode terrahunter doesn't have yet; they're counted apart and not in recall.

  python scripts/bench.py --kb ../terrahunter-kb                  # every project (fetch them first:
  python scripts/bench.py --kb ../terrahunter-kb --project terragoat   #   python scripts/bench/fetch.py in the kb)
  python scripts/bench.py --kb ../terrahunter-kb --report bench.md --json bench.json
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import re
import sys
from pathlib import Path

from terrahunter import arch, chains, graph

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


def score_root(folder: Path, key: dict, inputs: dict | None = None) -> dict:
    root = key["root"]
    inputs = inputs or {}
    with contextlib.redirect_stdout(io.StringIO()):
        files = [folder / f for f in inputs.get("var_files", [])]
        g = graph.build(folder, root, variables=inputs.get("variables"), var_files=[f for f in files if f.is_file()])
        model = arch.build(g)
        found = chains.build(g, model).chains
    expected = [p for p in key.get("paths", []) if p["steps"][:1] == ["internet"]]
    given = [p for p in key.get("paths", []) if p["steps"][:1] != ["internet"]]
    not_paths = {norm(n["resource"]): n["why"] for n in key.get("not_paths", [])}
    out = {"root": root, "resources": len(g.resources), "expected": [], "given_credentials": len(given), "found": []}
    used: set[int] = set()
    for p in expected:
        e, first = norm(p["entry"]), norm(p["steps"][1]) if len(p["steps"]) > 1 else norm(p["entry"])
        want = {norm(r["resource"]) for r in p.get("reaches", [])}
        best, best_hit = None, -1
        for i, c in enumerate(found):
            on_path = {norm(x) for x in c.steps[1:]} | ({norm(c.sinks[0])} if c.steps == ["internet"] else set())
            # the path's entry, its other ways in, and what opens the entry to the internet (a public container
            # on its storage account, a bucket policy on its bucket): keys may name either
            entries = {norm(entry_of(c)), *map(norm, c.also), *(norm(o) for _, o in model.exposed.get(entry_of(c), []))}
            if e in entries or first in on_path | entries:
                hit = len(want & {norm(s) for s in [*c.sinks, *c.within]})
                if hit > best_hit:
                    best, best_hit = i, hit
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
            row["missed"] = sorted(want - {norm(s) for s in [*found[best].sinks, *found[best].within]})
        out["expected"].append(row)
    for i, c in enumerate(found):
        if i in used:
            verdict, reason = "matched", ""
        else:
            hit = next((x for x in [norm(entry_of(c)), *map(norm, c.sinks)] if x in not_paths), None)
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
            f"{t['given_credentials']} paths start from given credentials (not scored yet)"
        ),
        "",
        (
            "Inputs the answer keys assume: CloudGoat's `cg_whitelist` (the player's address) is `0.0.0.0/0`, the player "
            "being the attacker; CloudFoxable uses its `terraform.tfvars.example` (its default challenges); sadcloud "
            "runs with `all_findings = true` (the README's full corpus)."
        ),
        "",
        "| Project | Roots | Expected | Found | Recall | Paths | Matched | Contradicted | Unlabelled |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for name, rows in results.items():
        x = totals(rows)
        lines.append(
            f"| {name} | {len(rows)} | {x['expected']} | {x['found']} | {x['recall']:.0%} | {x['paths']} | "
            f"{x['matched']} | {x['contradicted']} | {x['unlabelled']} |"
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
        partial = [(r["root"], p) for r in rows for p in r["expected"] if p["found"] and p.get("missed")]
        wrong = [(r["root"], c) for r in rows for c in r["found"] if c["verdict"] == "contradicted"]
        if not (misses or partial or wrong):
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
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--kb", type=Path, required=True, help="a checkout of terrahunter-kb, with its projects fetched")
    ap.add_argument("--project", action="append", help="only these projects (repeatable)")
    ap.add_argument("--report", type=Path, help="write the Markdown report here")
    ap.add_argument("--json", type=Path, help="write the full results here")
    a = ap.parse_args(argv)
    results: dict[str, list[dict]] = {}
    for key_file in sorted((a.kb / "bench").glob("*/expected.json")):
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
