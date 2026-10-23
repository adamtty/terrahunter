"""The command line. While terrahunter is being rebuilt, it only knows its version and says so."""

from __future__ import annotations

import argparse
import sys

from terrahunter import __version__

REBUILDING = (
    "terrahunter is being rebuilt around a new pipeline: folder in, what's missing, the connection diagram, "
    "vulnerabilities, attack paths, results. See https://github.com/adamtty/terrahunter for progress."
)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="terrahunter", description=__doc__)
    ap.add_argument("--version", action="version", version=f"terrahunter {__version__}")
    ap.add_argument("folder", nargs="?", help="the Terraform folder (a repository checkout)")
    return ap


def main(argv: list[str] | None = None) -> None:
    build_parser().parse_args(argv)
    print(REBUILDING, file=sys.stderr)
    sys.exit(3)
