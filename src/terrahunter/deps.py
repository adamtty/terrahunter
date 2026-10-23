"""Stage 2, what's missing: before any analysis, everything a root module needs that terrahunter can't see yet.

Starting from the root, the module tree is followed (local modules, and remote ones that `init` / `get` downloaded),
and every dependency is classified:

- **modules**: present (on disk and readable), *download* (remote and not downloaded yet: `get` can fetch it),
  *outside* (a local path that leaves the folder: another repository, added with `--with`), *missing* (a local
  directory that doesn't exist) or *unresolved* (the source is an expression only a plan can evaluate);
- **remote state** (`terraform_remote_state`, `tfe_outputs`): *matched* to the stack that writes it, by comparing its
  location with the `backend` / `cloud` block of every root in the folder and in the `--with` folders, or *unmatched*
  (that stack isn't here), or *unresolved* (its location is an expression).

Nothing unresolved is dropped: later stages show it as unknown, so "no path found" never means "didn't look".
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

import hcl2

from terrahunter import roots, sandbox

GET_TIMEOUT = 600  # seconds for `get`
MAX_MODULE_DEPTH = 12
_PUBLIC_REGISTRIES = ("registry.terraform.io", "registry.opentofu.org")


@dataclass
class Need:
    kind: str  # module | remote-state
    name: str  # module.net, data.terraform_remote_state.core
    source: str  # the module source, or where the state lives (s3://bucket/key, tfc://org/workspace)
    where: str  # the file that declares it, relative to its folder
    status: str  # present | download | outside | missing | unresolved | matched | unmatched
    detail: str = ""  # what it matched, or what to do about it
    via: str = ""  # the module path it was found in ("" for the root itself)


@dataclass
class Survey:
    root: str  # relative to the folder
    needs: list[Need] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def of(self, kind: str, *statuses: str) -> list[Need]:
        return [n for n in self.needs if n.kind == kind and (not statuses or n.status in statuses)]

    @property
    def open(self) -> list[Need]:
        """What still stands between this root and a complete picture."""
        return [n for n in self.needs if n.status not in ("present", "matched")]


# --- reading -----------------------------------------------------------------------------------------------------
def unquote(v) -> str | None:
    """A literal string from the parser ('"x"' → 'x'); None for an expression, or anything that isn't a string."""
    if not isinstance(v, str):
        return None
    if len(v) >= 2 and v[0] == v[-1] == '"':
        inner = v[1:-1]
        return None if "${" in inner else inner
    return None


def _key(k) -> str:
    return k[1:-1] if isinstance(k, str) and len(k) >= 2 and k[0] == k[-1] == '"' else str(k)


def parse_dir(d: Path, notes: list[str], label: str) -> list[tuple[str, dict]]:
    """Every configuration file directly in d → [(file name, parsed document)]."""
    return [(name, doc) for name, doc, _ in load_dir(d, notes, label)]


def load_dir(d: Path, notes: list[str], label: str) -> list[tuple[str, dict, str]]:
    """Every configuration file directly in d → [(file name, parsed document, text)]. JSON files are read as JSON
    (their strings get quotes added, so both look the same to the rest); files that won't parse become notes."""
    out = []
    files, skipped = sandbox.tf_files(d, recursive=False)
    notes += [f"{label}/{s}" for s in skipped]
    started = time.monotonic()
    for p in files:
        if not p.name.endswith(sandbox.CONFIG_SUFFIXES):
            continue
        left = sandbox.PARSE_BUDGET - (time.monotonic() - started)
        if left <= 0:
            notes.append(f"{label}: the parse time budget ran out; the rest of its files weren't read")
            break
        try:
            text = sandbox.read_regular(p).decode("utf-8", "replace")
            with sandbox.time_limit(min(sandbox.parse_limit(), left)):
                doc = _requote(json.loads(text)) if p.name.endswith(".json") else hcl2.loads(text)
        except sandbox.ParseTimeout:
            notes.append(f"{label}/{p.name}: too slow to parse, not read")
            continue
        except Exception as e:  # noqa: BLE001 - a file the parser rejects is reported, never fatal
            notes.append(f"{label}/{p.name}: couldn't be parsed ({sandbox.one_line(type(e).__name__)})")
            continue
        if isinstance(doc, dict):
            out.append((p.name, doc, text))
    return out


def _requote(v):
    """JSON configuration → the parser's shape: string values quoted, block labels quoted."""
    if isinstance(v, str):
        return v if "${" in v else f'"{v}"'
    if isinstance(v, list):
        return [_requote(x) for x in v]
    if isinstance(v, dict):
        return {k: _requote(x) for k, x in v.items()}
    return v


def _groups(v) -> list:
    """A top-level section as a list of objects: HCL gives a list, JSON a single object."""
    return v if isinstance(v, list) else [v] if isinstance(v, dict) else []


def _blocks(doc: dict, kind: str):
    """(label, body) for each `kind "label" { }` block (module), in both the HCL and the JSON shape."""
    for group in _groups(doc.get(kind)):
        for label, body in group.items() if isinstance(group, dict) else []:
            for b in body if isinstance(body, list) else [body]:
                if isinstance(b, dict):
                    yield _key(label), b


def _data(doc: dict, dtype: str):
    """(name, body) for each `data "dtype" "name" { }`."""
    for group in _groups(doc.get("data")):
        for t, named in group.items() if isinstance(group, dict) else []:
            if _key(t) != dtype or not isinstance(named, dict):
                continue
            for name, body in named.items():
                for b in body if isinstance(body, list) else [body]:
                    if isinstance(b, dict):
                        yield _key(name), b


# --- where state lives --------------------------------------------------------------------------------------------
def state_location(backend: str, cfg: dict) -> str | None:
    """A comparable address for state, from a backend / remote-state config; None when any part is an expression."""

    def g(*keys):
        vals = [unquote(cfg.get(k)) for k in keys]
        return None if any(v is None for v in vals) else vals

    if backend == "s3" and (v := g("bucket", "key")):
        return f"s3://{v[0]}/{v[1]}"
    if backend == "gcs" and (v := g("bucket")):
        prefix = unquote(cfg.get("prefix")) or ""
        return f"gcs://{v[0]}/{prefix}".rstrip("/")
    if backend == "azurerm" and (v := g("storage_account_name", "container_name", "key")):
        return f"azurerm://{v[0]}/{v[1]}/{v[2]}"
    if backend in ("remote", "cloud"):
        org = unquote(cfg.get("organization"))
        ws = cfg.get("workspaces")
        ws = ws[0] if isinstance(ws, list) and ws else ws
        name = unquote(ws.get("name")) if isinstance(ws, dict) else None
        return f"tfc://{org}/{name}" if org and name else None
    if backend == "local" and (v := g("path")):
        return f"local://{v[0]}"
    return None


def backends_of(folder: Path, d: roots.Discovery, notes: list[str], prefix: str = "") -> dict[str, str]:
    """Where each root in a folder keeps its state → the root (`path`, or `repo:path` for a --with folder)."""
    out: dict[str, str] = {}
    for r in d.roots + d.standalone:
        where = folder / r.path
        label = f"{prefix}{r.path}"
        for _, doc in parse_dir(where, notes, label):
            for tb in _groups(doc.get("terraform")):
                if not isinstance(tb, dict):
                    continue
                for kind in ("backend", "cloud"):
                    entries = tb.get(kind) or []
                    for entry in entries if isinstance(entries, list) else [entries]:
                        if kind == "cloud" and isinstance(entry, dict):
                            loc = state_location("cloud", entry)
                            if loc:
                                out.setdefault(loc, label)
                            continue
                        for btype, cfg in entry.items() if isinstance(entry, dict) else []:
                            loc = state_location(_key(btype), cfg if isinstance(cfg, dict) else {})
                            if loc:
                                out.setdefault(loc, label)
    return out


# --- the survey ---------------------------------------------------------------------------------------------------
def _inside_any(p: Path, folders: list[Path]) -> Path | None:
    for f in folders:
        if p == f or f in p.parents:
            return f
    return None


def _has_config(d: Path) -> bool:
    try:
        return d.is_dir() and any(x.name.endswith(sandbox.CONFIG_SUFFIXES) for x in d.iterdir())
    except OSError:
        return False


def _registry_host(source: str) -> str | None:
    """The host of a private registry address (host/namespace/name/system), else None."""
    parts = source.split("//")[0].split("/")
    if len(parts) == 4 and "." in parts[0] and "::" not in source and parts[0] not in _PUBLIC_REGISTRIES:
        return parts[0]
    return None


def _downloads(root_dir: Path) -> dict[str, Path]:
    """modules.json Key → its directory, only for entries whose directory exists inside the root."""
    mj = sandbox.downloaded_modules(root_dir) / "modules.json"
    if not sandbox.is_regular_inside(mj, root_dir):
        return {}
    try:
        data = json.loads(sandbox.read_regular(mj).decode("utf-8", "replace"))
    except (OSError, ValueError, RecursionError):
        return {}
    out = {}
    for m in data.get("Modules") or [] if isinstance(data, dict) else []:
        if isinstance(m, dict) and isinstance(m.get("Key"), str) and isinstance(m.get("Dir"), str):
            d = (root_dir / m["Dir"]).resolve()  # the real path: a symlinked download can't lead out of the root
            if not os.path.isabs(m["Dir"]) and (d == root_dir or root_dir in d.parents) and d.is_dir():
                out[m["Key"]] = d
    return out


def locate_module(
    d: Path, src: str, key: str, folder: Path, allowed: list[Path], downloads: dict[str, Path]
) -> tuple[str, Path | None, str]:
    """Where a module call's code is. d: the calling directory; src: its literal source; key: its modules.json key
    (`a.b`). → (present | outside | missing | download, the directory when present, a note on what to do)."""
    if src.startswith(("./", "../")) or src in (".", ".."):
        # the real path: a symlinked directory pointing outside the folder must count as outside
        target = (d / src).resolve()
        if not _inside_any(target, allowed):
            rel = Path(os.path.relpath(target, folder)).as_posix()
            return "outside", None, f"{rel} is outside the folder: add that repository with --with <path>"
        if not _has_config(target):
            return "missing", None, "that directory doesn't exist or has no Terraform files"
        return "present", target, ""
    got = downloads.get(key)
    if got is not None:
        return "present", got, "downloaded"
    host = _registry_host(src)
    hint = "not downloaded yet: `get` fetches it"
    if host:
        hint += f" (private registry {host}: set TF_TOKEN_{host.replace('.', '_').replace('-', '__')})"
    return "download", None, hint


def survey(folder: Path, root: str, with_folders: list[Path] | None = None) -> Survey:
    folder = folder.resolve()
    allowed = [folder] + [w.resolve() for w in with_folders or []]
    root_dir = (folder / root).resolve()
    s = Survey(root)
    states: dict[str, str] = {}
    for f in allowed:
        found = backends_of(f, roots.discover(f), s.notes, "" if f == folder else f"{f.name}:")
        states.update({k: v for k, v in found.items() if k not in states})
    downloads = _downloads(root_dir)
    seen: set[Path] = set()

    def label(d: Path) -> str:
        base = _inside_any(d, allowed) or folder
        rel = os.path.relpath(d, base)
        return (base.name + ":" if base != folder else "") + (Path(rel).as_posix() if rel != "." else ".")

    def walk(d: Path, path: tuple[str, ...], depth: int):
        if d in seen and path:
            return
        seen.add(d)
        via = ".".join(f"module.{p}" for p in path)
        for fname, doc in parse_dir(d, s.notes, label(d)):
            where = f"{label(d)}/{fname}"
            for name, body in _blocks(doc, "module"):
                src_raw = body.get("source")
                src = unquote(src_raw)
                full = f"module.{name}"
                if src is None:
                    s.needs.append(
                        Need(
                            "module",
                            full,
                            sandbox.one_line(src_raw, 120),
                            where,
                            "unresolved",
                            "the source is an expression: only a plan can say which module it is",
                            via,
                        )
                    )
                    continue
                status, target, note = locate_module(d, src, ".".join(path + (name,)), folder, allowed, downloads)
                if status == "present":
                    shown = label(target) if note != "downloaded" else "downloaded"
                    s.needs.append(Need("module", full, src, where, "present", shown, via))
                    if depth < MAX_MODULE_DEPTH:
                        walk(target, path + (name,), depth + 1)
                else:
                    s.needs.append(Need("module", full, src, where, status, note, via))
            for dtype in ("terraform_remote_state", "tfe_outputs"):
                for name, body in _data(doc, dtype):
                    full = f"data.{dtype}.{name}"
                    if dtype == "terraform_remote_state":
                        backend = unquote(body.get("backend"))
                        cfg = body.get("config")
                        loc = state_location(backend, cfg) if backend and isinstance(cfg, dict) else None
                    else:
                        org, ws = unquote(body.get("organization")), unquote(body.get("workspace"))
                        loc = f"tfc://{org}/{ws}" if org and ws else None
                    if loc is None:
                        s.needs.append(
                            Need(
                                "remote-state",
                                full,
                                "",
                                where,
                                "unresolved",
                                "where it reads from is an expression: only a plan can say",
                                via,
                            )
                        )
                    elif loc in states:
                        s.needs.append(Need("remote-state", full, loc, where, "matched", states[loc], via))
                    else:
                        s.needs.append(
                            Need(
                                "remote-state",
                                full,
                                loc,
                                where,
                                "unmatched",
                                "the stack that writes this state isn't here: add its repository with "
                                "--with <path>, or skip it",
                                via,
                            )
                        )

    walk(root_dir, (), 0)
    return s


# --- fetching -----------------------------------------------------------------------------------------------------
def tool_for(root_dir: Path) -> str | None:
    """OpenTofu for a root with .tofu files (Terraform can't read them), else whichever is installed."""
    has_tofu = any(p.name.endswith((".tofu", ".tofu.json")) for p in root_dir.iterdir() if p.is_file())
    order = ("tofu", "terraform") if has_tofu else ("terraform", "tofu")
    return next((shutil.which(t) for t in order if shutil.which(t)), None)


def fetch(root_dir: Path) -> tuple[bool, str]:
    """Run `get` in the root: modules only, no providers, no backend. It fetches code with this machine's git and
    registry credentials, so it only runs when the user asks. → (ok, a short note)."""
    tool = tool_for(root_dir)
    if not tool:
        return False, "neither tofu nor terraform is on PATH"
    env = dict(os.environ, TF_IN_AUTOMATION="1", TF_INPUT="0", GIT_TERMINAL_PROMPT="0")
    name = Path(tool).name
    try:
        r = subprocess.run(
            [tool, "get", "-no-color"],
            cwd=root_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=GET_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, f"{name} get took longer than {GET_TIMEOUT}s"
    except OSError as e:
        return False, f"{name} get couldn't run ({sandbox.one_line(e, 120)})"
    if r.returncode != 0:
        tail = [ln for ln in (r.stderr or r.stdout).splitlines() if ln.strip()][-3:]
        return False, f"{name} get failed: " + sandbox.one_line(" / ".join(tail), 400)
    return True, f"{name} get finished"
