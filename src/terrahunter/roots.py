"""Stage 1, the folder in: find the Terraform root modules in a folder, wherever they sit.

A real repository rarely has its root module at the top. Roots live in `deploy/prod/infra`, `envs/dev`, `stacks/x`,
and call shared modules elsewhere in the repo (`../../modules/net`). So every directory with Terraform or OpenTofu
files is classified:

- **root**: it configures where state lives (a `backend` or `cloud` block), or configures providers, or a deployment
  tool names it as a project root (Spacelift `project_root`, Atlantis `dir`); and nothing in the folder calls it as a
  module;
- **module**: another directory in the folder calls it with a local `source`;
- **standalone**: it has resources but no backend or provider configuration, and nothing here calls it: a root that
  relies on default providers, or a module used from elsewhere. Listed, never chosen automatically.

Files are only scanned as text (cheap, and nothing in them is evaluated), and only regular files inside the folder.
"""

from __future__ import annotations

import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from terrahunter import sandbox

_BACKEND = re.compile(r'^\s*backend\s+"([A-Za-z0-9_-]+)"', re.MULTILINE)
_BACKEND_JSON = re.compile(r'"backend"\s*:\s*\{\s*"([A-Za-z0-9_-]+)"')
_CLOUD = re.compile(r"^\s*cloud\s*\{", re.MULTILINE)
_PROVIDER = re.compile(r'^\s*provider\s+"([A-Za-z0-9_-]+)"', re.MULTILINE)
_PROVIDER_JSON = re.compile(r'"provider"\s*:\s*\{\s*"([A-Za-z0-9_-]+)"')
_RESOURCE = re.compile(r'^\s*resource\s+"[A-Za-z0-9_-]+"\s+"', re.MULTILINE)
_RESOURCE_JSON = re.compile(r'"resource"\s*:')
_MODULE = re.compile(r'^\s*module\s+"[A-Za-z0-9_-]+"', re.MULTILINE)
# a module's local source: "./x", "../x" (a provider's required source is "hashicorp/aws", never relative)
_LOCAL_SOURCE = re.compile(r'\bsource"?\s*[=:]\s*"(\.{1,2}(?:/[^"]*)?)"')
_SPACELIFT_ROOT = re.compile(r"^\s*project_root\s*:\s*['\"]?([^'\"#\s]+)", re.MULTILINE)
_ATLANTIS_DIR = re.compile(r"^\s*-?\s*dir\s*:\s*['\"]?([^'\"#\s]+)", re.MULTILINE)
DECLARING_FILES = (".spacelift/config.yml", ".spacelift/config.yaml", "atlantis.yaml", "atlantis.yml")


@dataclass
class TfDir:
    path: str  # relative to the folder, posix; "." for the folder itself
    kind: str  # root | module | standalone
    reasons: list[str] = field(default_factory=list)  # why it's a root, or who calls it
    files: int = 0
    resources: int = 0
    module_calls: int = 0


@dataclass
class Discovery:
    folder: Path
    dirs: list[TfDir]
    notes: list[str]  # files left out, config that couldn't be read

    @property
    def roots(self) -> list[TfDir]:
        return [d for d in self.dirs if d.kind == "root"]

    @property
    def modules(self) -> list[TfDir]:
        return [d for d in self.dirs if d.kind == "module"]

    @property
    def standalone(self) -> list[TfDir]:
        return [d for d in self.dirs if d.kind == "standalone"]


def _rel(p: Path, folder: Path) -> str:
    r = os.path.relpath(p, folder)
    return Path(r).as_posix() if r != "." else "."


def _declared(folder: Path, notes: list[str]) -> dict[str, str]:
    """Directories a deployment tool names as project roots → which tool."""
    out: dict[str, str] = {}
    for name in DECLARING_FILES:
        p = folder / name
        if not p.exists():
            continue
        if not sandbox.is_regular_inside(p, folder):
            notes.append(f"{name}: not a regular file inside the folder, not read")
            continue
        try:
            text = sandbox.read_regular(p).decode("utf-8", "replace")
        except OSError as e:
            notes.append(f"{name}: couldn't be read ({sandbox.one_line(e, 120)})")
            continue
        tool = "Spacelift" if "spacelift" in name else "Atlantis"
        rx = _SPACELIFT_ROOT if tool == "Spacelift" else _ATLANTIS_DIR
        for m in rx.finditer(text):
            d = os.path.normpath(m.group(1).strip("/") or ".")
            if not d.startswith(".."):
                out.setdefault(Path(d).as_posix(), tool)
    return out


def discover(folder: str | Path) -> Discovery:
    folder = Path(folder).resolve()
    files, notes = sandbox.tf_files(folder)
    texts: dict[str, list[tuple[str, str]]] = defaultdict(list)  # dir → [(file name, text)]
    for p in files:
        if not p.name.endswith(sandbox.CONFIG_SUFFIXES):
            continue
        try:
            text = sandbox.read_regular(p).decode("utf-8", "replace")
        except OSError as e:
            notes.append(f"{_rel(p, folder)}: couldn't be read ({sandbox.one_line(e, 120)})")
            continue
        texts[_rel(p.parent, folder)].append((p.name, text))

    declared = _declared(folder, notes)
    callers: dict[str, list[str]] = defaultdict(list)  # module dir → dirs that call it
    info: dict[str, dict] = {}
    for d, items in texts.items():
        backends, providers, resources, calls = [], [], 0, 0
        cloud = False
        for name, text in items:
            is_json = name.endswith(".json")
            backends += (_BACKEND_JSON if is_json else _BACKEND).findall(text)
            providers += (_PROVIDER_JSON if is_json else _PROVIDER).findall(text)
            cloud |= not is_json and bool(_CLOUD.search(text))
            resources += len(_RESOURCE.findall(text)) if not is_json else len(_RESOURCE_JSON.findall(text))
            calls += len(_MODULE.findall(text)) if not is_json else text.count('"module"')
            for src in _LOCAL_SOURCE.findall(text):
                target = os.path.normpath(os.path.join(folder, d, src))
                if Path(target) == folder or folder in Path(target).parents:  # calls outside the folder are stage 2's
                    callers[_rel(Path(target), folder)].append(d)
        info[d] = {
            "backends": sorted(set(backends)),
            "providers": sorted(set(providers)),
            "cloud": cloud,
            "resources": resources,
            "calls": calls,
            "files": len(items),
        }

    dirs: list[TfDir] = []
    for d, i in sorted(info.items()):
        reasons = [f"backend {b}" for b in i["backends"]] + (["cloud block"] if i["cloud"] else [])
        if d in declared:
            reasons.append(f"{declared[d]} project root")
        reasons += [f"provider {p}" for p in i["providers"]]
        called_by = sorted(set(callers.get(d, [])) - {d})
        if called_by:
            kind, why = "module", [f"called from {c}" for c in called_by]
        elif reasons:
            kind, why = "root", reasons
        elif i["resources"] or i["calls"]:
            kind, why = "standalone", ["resources but no backend or provider configuration, and nothing here calls it"]
        else:
            continue  # variables or outputs only: nothing to analyse on its own
        dirs.append(TfDir(d, kind, why, i["files"], i["resources"], i["calls"]))
    for d, tool in sorted(declared.items()):
        if d not in info:
            notes.append(f"{tool} names {d} as a project root, but it has no Terraform files here")
    return Discovery(folder, dirs, notes)
