"""The command line: `terrahunter <folder>`. Stages 1 (the folder in) and 2 (what's missing) are built."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from terrahunter import __version__, deps, roots, sandbox

EXIT_OK, EXIT_INCOMPLETE, EXIT_ERROR = 0, 2, 3
NEXT = "the next stages (the diagram, vulnerabilities, attack paths) aren't built yet: this run stops here"


class TerrahunterError(Exception):
    pass


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="terrahunter",
        description="Point it at a folder of Terraform: it finds the root modules in it (and, as the rebuild "
        "lands, maps the infrastructure and the paths an attacker could chain through it).",
    )
    ap.add_argument("--version", action="version", version=f"terrahunter {__version__}")
    ap.add_argument("folder", help="the folder to analyse: a repository checkout, or any directory of Terraform")
    pick = ap.add_mutually_exclusive_group()
    pick.add_argument(
        "--root", help="the root module to analyse, relative to the folder (default: ask, or the only one)"
    )
    pick.add_argument("--all-roots", action="store_true", help="analyse every root module found")
    ap.add_argument(
        "--with",
        dest="with_folders",
        action="append",
        default=[],
        metavar="PATH",
        help="another folder the analysis may read (another repository: modules it calls, stacks whose state it "
        "reads); repeatable",
    )
    ap.add_argument(
        "--fetch-modules",
        action="store_true",
        help="download remote modules that haven't been yet (tofu/terraform get: modules only), without asking",
    )
    return ap


def _interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty() and not os.environ.get("CI")


def _show(d: roots.Discovery) -> None:
    rs = d.roots
    print(f"{len(rs)} root module{'s' if len(rs) != 1 else ''} in {sandbox.one_line(d.folder)}")
    for i, r in enumerate(rs, 1):
        print(f"  {i:>2}. {sandbox.one_line(r.path)}  ({sandbox.one_line(', '.join(r.reasons), 160)})")
    if d.standalone:
        print("Standalone configurations (no backend or provider, nothing here calls them):")
        for s in d.standalone:
            print(f"      {sandbox.one_line(s.path)}")
    if d.modules:
        print(f"{len(d.modules)} module director{'ies' if len(d.modules) != 1 else 'y'}:")
        for m in d.modules:
            print(f"      {sandbox.one_line(m.path)}  ({sandbox.one_line(', '.join(m.reasons), 160)})")
    for n in d.notes:
        print(f"  ! {sandbox.one_line(n, 300)}")


def _ask(rs: list[roots.TfDir]) -> list[roots.TfDir]:
    while True:
        ans = input(f"Which root module? [1-{len(rs)}, or a for all] ").strip().lower()
        if ans in ("a", "all"):
            return rs
        if ans.isdigit() and 1 <= int(ans) <= len(rs):
            return [rs[int(ans) - 1]]
        print("  not one of the numbers above", file=sys.stderr)


def select(d: roots.Discovery, root: str | None, all_roots: bool) -> list[roots.TfDir]:
    """The root module(s) to analyse."""
    if root is not None:
        want = Path(os.path.normpath(root.strip("/") or ".")).as_posix()
        if want.startswith(".."):
            raise TerrahunterError(f"--root {root}: must be inside the folder")
        hit = next((x for x in d.dirs if x.path == want), None)
        if hit is None:
            raise TerrahunterError(f"--root {root}: no Terraform files there")
        return [hit]
    rs = d.roots or d.standalone  # a folder of plain configurations, such as examples, has no "real" roots
    if not rs:
        raise TerrahunterError(f"no Terraform root modules found in {d.folder}")
    if all_roots or len(rs) == 1:
        return rs
    if _interactive():
        return _ask(rs)
    raise TerrahunterError(
        f"{len(rs)} root modules found: choose one with --root (e.g. --root {rs[0].path}), or pass --all-roots"
    )


STATUS = {  # how each status reads in the report
    "present": "✓",
    "matched": "✓",
    "download": "↓",
    "outside": "?",
    "missing": "✗",
    "unmatched": "?",
    "unresolved": "?",
}


def show_needs(s: deps.Survey) -> None:
    mods, states = s.of("module"), s.of("remote-state")
    ok_m, ok_s = s.of("module", "present"), s.of("remote-state", "matched")
    print(f"\nWhat {sandbox.one_line(s.root)} needs:")
    print(f"  modules       {len(ok_m)} of {len(mods)} available" if mods else "  modules       none")
    print(f"  remote state  {len(ok_s)} of {len(states)} matched to a stack" if states else "  remote state  none")
    for n in s.of("remote-state", "matched"):
        print(
            f"    ✓ {sandbox.one_line(n.name)} reads {sandbox.one_line(n.detail)} ({sandbox.one_line(n.source, 120)})"
        )
    if s.open:
        print("  Not available yet (shown as unknown later, unless you add them):")
        for n in s.open:
            where = f"  [{sandbox.one_line(n.via)}]" if n.via else ""
            src = f" {sandbox.one_line(n.source, 100)}" if n.source else ""
            print(f"    {STATUS[n.status]} {sandbox.one_line(n.name)}{src}{where}")
            print(f"        {sandbox.one_line(n.detail, 200)}  ({sandbox.one_line(n.where, 120)})")
    for note in s.notes:
        print(f"  ! {sandbox.one_line(note, 300)}")


def resolve(folder: Path, root: str, withs: list[Path], fetch: bool) -> deps.Survey:
    """Survey a root, and fetch its downloadable modules if the user wants them; → the survey after that."""
    s = deps.survey(folder, root, withs)
    downloadable = s.of("module", "download")
    if downloadable and not fetch and _interactive():
        print(
            f"\n{len(downloadable)} remote module(s) can be downloaded (tofu/terraform get: modules only, no "
            "providers or backend; it uses this machine's git and registry credentials)."
        )
        fetch = input("Download them now? Only for Terraform you trust [y/N] ").strip().lower() in ("y", "yes")
    if downloadable and fetch:
        ok, note = deps.fetch((folder / root).resolve())
        print(f"  {'✓' if ok else '✗'} {sandbox.one_line(note, 300)}")
        s = deps.survey(folder, root, withs)
    return s


def main(argv: list[str] | None = None) -> None:
    try:
        sys.exit(_main(argv))
    except TerrahunterError as e:
        sys.stdout.flush()  # what was found first, then why it stopped
        print(f"terrahunter: {sandbox.one_line(e, 400)}", file=sys.stderr)
        sys.exit(EXIT_ERROR)
    except KeyboardInterrupt:
        sys.exit(130)


def _main(argv: list[str] | None) -> int:
    a = build_parser().parse_args(argv)
    if not Path(a.folder).is_dir():
        raise TerrahunterError(f"not a directory: {a.folder}")
    d = roots.discover(a.folder)
    _show(d)
    chosen = select(d, a.root, a.all_roots)
    withs = []
    for w in a.with_folders:
        if not Path(w).is_dir():
            raise TerrahunterError(f"--with {w}: not a directory")
        withs.append(Path(w))
    complete = not d.notes
    for c in chosen:
        s = resolve(d.folder, c.path, withs, a.fetch_modules)
        show_needs(s)
        complete &= not s.open and not s.notes
    print(f"\n({NEXT})")
    return EXIT_OK if complete else EXIT_INCOMPLETE
