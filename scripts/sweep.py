"""Robustness sweep: run terrahunter over many public Terraform repositories and report what goes wrong.

No answer keys: this measures whether terrahunter *works* on Terraform it has never seen, not whether its paths are
right. For each repository (a shallow clone of its default branch) it runs every root with `--all-roots --no-scan
--no-diagram`, with a time limit, and records:

- **crashes** (a traceback) and **errors** (terrahunter's error exit), grouped by their last line;
- **timeouts** and how long each repository took;
- **coverage gaps**: resource types the knowledge base has no catalogue entry for (counted by repository), modules
  it couldn't read and why, files it couldn't parse.

The clones are untrusted data: they're kept in their own folder (`--work`), and terrahunter (which reads no symlink
that leaves the folder) runs with its working directory outside them, never fetches modules, and never runs scanners.

  python scripts/sweep.py --report sweep.md                       # every repository in scripts/sweep-repos.txt
  python scripts/sweep.py --repo poseidon/typhoon --report one.md  # one repository
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

from terrahunter import kb

HERE = Path(__file__).resolve().parent
MAX_SIZE_KB = 300_000  # bigger repositories (mostly not Terraform: images, vendored code) are skipped
# providers that make no infrastructure (values, files, local commands): not a coverage gap
UTILITY = {
    "null",
    "random",
    "time",
    "local",
    "tls",
    "archive",
    "external",
    "template",
    "terraform",
    "http",
    "cloudinit",
}
_SAFE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def repos_from(path: Path) -> list[str]:
    return [x.strip() for x in path.read_text().splitlines() if x.strip() and not x.lstrip().startswith("#")]


def clone(name: str, work: Path, refresh: bool) -> tuple[Path | None, str]:
    """A shallow clone of the repository's default branch: (its folder, its commit), or (None, why)."""
    if not _SAFE.match(name):
        return None, "not owner/name"
    dest = work / "repos" / name.replace("/", "__")
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    if dest.is_dir() and not refresh:
        sha = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "HEAD"], capture_output=True, text=True, env=env, check=False
        )
        return dest, sha.stdout.strip()
    meta = subprocess.run(["gh", "api", f"repos/{name}", "--jq", ".size"], capture_output=True, text=True, check=False)
    size = int(meta.stdout.strip() or 0) if meta.returncode == 0 else 0
    if size > MAX_SIZE_KB:
        return None, f"{size // 1000} MB, over the sweep's limit"
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    p = subprocess.run(
        [
            "git",
            "clone",
            "--quiet",
            "--depth",
            "1",
            "--no-tags",
            f"https://github.com/{name}.git",
            str(dest),
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=600,
        check=False,
    )
    if p.returncode != 0:
        return None, (p.stderr.strip().splitlines() or ["clone failed"])[-1]
    sha = subprocess.run(
        ["git", "-C", str(dest), "rev-parse", "HEAD"], capture_output=True, text=True, env=env, check=False
    )
    return dest, sha.stdout.strip()


def run(folder: Path, out: Path, timeout: int) -> dict:
    """terrahunter on every root of the folder: exit code, time, its graph JSON, the last error line."""
    j = out / "graph.json"
    cmd = [
        sys.executable,
        "-m",
        "terrahunter",
        str(folder),
        "--all-roots",
        "--no-scan",
        "--no-diagram",
        "--graph-json",
        str(j),
        "--report",
        str(out / "report.md"),
    ]
    started = time.monotonic()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, cwd=out, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "seconds": timeout}
    took = round(time.monotonic() - started, 1)
    (out / "terrahunter.log").write_text(p.stdout + "\n--- stderr ---\n" + p.stderr)
    last = next((x for x in reversed((p.stderr or p.stdout).strip().splitlines()) if x.strip()), "")
    # terrahunter's exits: 0 nothing found, 1 paths found, 2 incomplete (something not seen), 3 an error
    if "Traceback (most recent call last)" in p.stderr:
        status = "crash"
    else:
        status = {0: "ok", 1: "ok", 2: "incomplete"}.get(p.returncode, "error")
    graphs = json.loads(j.read_text())["graphs"] if j.exists() else []
    return {"status": status, "exit": p.returncode, "seconds": took, "last": last[:300], "graphs": graphs}


def summarise(name: str, sha: str, r: dict) -> dict:
    """What one repository's run says about coverage."""
    types: Counter = Counter()
    unknown: Counter = Counter()
    notes: list[str] = []
    resources = 0
    for g in r.get("graphs", []):
        for res in g.get("resources", []):
            if res.get("mode", "managed") == "managed":
                types[res["type"]] += 1
                resources += 1
        for u in g.get("unknown", []):
            unknown[u.get("status", "?")] += 1
        notes += [*g.get("notes", []), *g.get("info", [])]
    uncatalogued = {t: n for t, n in types.items() if kb.entry(t) is None and t.split("_")[0] not in UTILITY}
    return {
        "repo": name,
        "commit": sha,
        "status": r["status"],
        "exit": r.get("exit"),
        "seconds": r.get("seconds"),
        "last": r.get("last", ""),
        "roots": len(r.get("graphs", [])),
        "resources": resources,
        "providers": sorted({t.split("_")[0] for t in types}),
        "uncatalogued": uncatalogued,
        "unknown_modules": dict(unknown),
        "notes": notes[:50],
    }


def _note_kind(note: str) -> str:
    """A note without its specifics, to group them: file names and numbers out."""
    n = re.sub(r"[\w./-]+\.(tf|json|tofu|tfvars|hcl)\b", "<file>", note)
    return re.sub(r"\d+", "N", n)[:140]


def markdown(rows: list[dict]) -> str:
    ran = [r for r in rows if r["status"] not in ("skipped", "clone-failed")]
    by = Counter(r["status"] for r in rows)
    lines = [
        "# terrahunter robustness sweep",
        "",
        f"{len(rows)} repositories · {len(ran)} run · {sum(r['roots'] for r in ran)} roots · "
        f"{sum(r['resources'] for r in ran)} resources · "
        + " · ".join(f"{k} {v}" for k, v in sorted(by.items()))
        + f" · {sum(r['seconds'] or 0 for r in ran):.0f}s in all",
        "",
    ]
    bad = [r for r in rows if r["status"] in ("crash", "error", "timeout")]
    if bad:
        lines += ["## Crashes, errors and timeouts", "", "| Repository | Status | Last line |", "|---|---|---|"]
        for r in sorted(bad, key=lambda x: (x["status"], x["last"])):
            lines.append(f"| {r['repo']} | {r['status']} | `{r['last'][:160]}` |")
        lines.append("")
    lines += ["## Slowest", "", "| Repository | Seconds | Roots | Resources |", "|---|---:|---:|---:|"]
    for r in sorted(ran, key=lambda x: -(x["seconds"] or 0))[:10]:
        lines.append(f"| {r['repo']} | {r['seconds']} | {r['roots']} | {r['resources']} |")
    lines.append("")
    gaps: dict[str, list] = defaultdict(lambda: [0, 0])
    for r in ran:
        for t, n in r["uncatalogued"].items():
            gaps[t][0] += 1
            gaps[t][1] += n
    if gaps:
        lines += [
            "## Resource types with no catalogue entry",
            "",
            (
                "By how many repositories use them (then instances). Each is drawn as unknown and can't take part in "
                "paths."
            ),
            "",
            "| Type | Repositories | Resources |",
            "|---|---:|---:|",
        ]
        for t, (nrep, n) in sorted(gaps.items(), key=lambda x: (-x[1][0], -x[1][1], x[0]))[:60]:
            lines.append(f"| `{t}` | {nrep} | {n} |")
        lines.append("")
    unk: Counter = Counter()
    for r in ran:
        unk.update(r["unknown_modules"])
    if unk:
        lines += ["## Modules it couldn't read", "", "| Why | Calls |", "|---|---:|"]
        lines += [f"| {k} | {v} |" for k, v in unk.most_common()]
        lines.append("")
    kinds: Counter = Counter(_note_kind(n) for r in ran for n in r["notes"])
    if kinds:
        lines += ["## Notes (grouped)", "", "| Note | Times |", "|---|---:|"]
        lines += [f"| {k} | {v} |" for k, v in kinds.most_common(30)]
        lines.append("")
    skipped = [r for r in rows if r["status"] in ("skipped", "clone-failed")]
    if skipped:
        lines += ["## Not run", ""] + [f"- {r['repo']}: {r['last']}" for r in skipped] + [""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repos", type=Path, default=HERE / "sweep-repos.txt", help="owner/name per line")
    ap.add_argument("--repo", action="append", help="only these repositories (repeatable)")
    ap.add_argument(
        "--work",
        type=Path,
        default=Path.home() / "Documents" / "code-work" / "th-sweep",
        help="where clones and runs go",
    )
    ap.add_argument("--timeout", type=int, default=600, help="seconds per repository")
    ap.add_argument("--refresh", action="store_true", help="clone again instead of reusing clones")
    ap.add_argument("--report", type=Path, help="write the Markdown report here")
    ap.add_argument("--json", type=Path, help="write the full results here")
    a = ap.parse_args(argv)
    names = a.repo or repos_from(a.repos)
    rows = []
    for name in names:
        folder, sha = clone(name, a.work, a.refresh)
        if folder is None:
            rows.append(
                {
                    "repo": name,
                    "status": "skipped",
                    "last": sha,
                    "seconds": 0,
                    "roots": 0,
                    "resources": 0,
                    "uncatalogued": {},
                    "unknown_modules": {},
                    "notes": [],
                }
            )
            print(f"{name}: skipped ({sha})", file=sys.stderr)
            continue
        out = a.work / "runs" / name.replace("/", "__")
        out.mkdir(parents=True, exist_ok=True)
        row = summarise(name, sha, run(folder, out, a.timeout))
        rows.append(row)
        print(
            f"{name}: {row['status']} in {row['seconds']}s, {row['roots']} roots, {row['resources']} resources",
            file=sys.stderr,
        )
    md = markdown(rows)
    print(md)
    if a.report:
        a.report.write_text(md)
    if a.json:
        a.json.write_text(json.dumps(rows, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
