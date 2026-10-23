"""Stage 4, vulnerabilities: trivy and checkov on the root and every module it calls, each finding pinned to the
resource it's about.

Contained. The Terraform under review is untrusted, and both scanners act on config found next to it (checkov's
`.checkov.yaml` can name external checks to clone and import, trivy's `trivy.yaml` can skip every file). So they scan
a staged copy holding only regular Terraform files (the directories the graph read, in the same layout, so relative
module sources still work), from an empty working directory, with a throwaway HOME, a minimal environment and no
network. A module source that would take them outside the folders under review stops the scan before it starts.

Fail closed. A scanner that's missing, times out, exits non-zero, prints something that isn't JSON or says it
couldn't parse a file is a failure the run reports (exit 2), never an empty list: "no findings" means the scanner
ran and found nothing.

Placed. Each finding is mapped back to a graph address: checkov names the full address; trivy names the resource in
the root and only the module call inside a module, so its file and line pick the resource block (in every instance
of the module, when it's called more than once).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path

from terrahunter import graph, sandbox

SCANNER_TIMEOUT = 900
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")  # most severe first; anything else is unrated
# trivy exits 0 and reports nothing for a file it could not parse; the only sign is an ERROR log line on stderr
# (`ERROR [terraform parser] Error parsing file ... file_path="bad.tf" cause="<file content>"`), so such a line is a
# failure naming the file (never quoting `cause`, which is file content)
_TRIVY_PARSE_ERROR = re.compile(r"\bERROR\b.*\bpars(?:e|ing)\b", re.IGNORECASE)
_TRIVY_FILE = re.compile(r'\bfile_path="((?:[^"\\]|\\.)*)"')
# logged at ERROR level but harmless: with no cached checks bundle, trivy scans with the checks built into it. Anchored
# to the start of the line so the phrase appearing in another error's details doesn't hide that error.
_TRIVY_BENIGN = re.compile(r"^(?:\S+\s+)?ERROR\s+\[misconfig\]\s+Falling back to embedded checks(?:\s|$)")
# any other ERROR line means part of the configuration wasn't evaluated. Only the category and the message before the
# first key=value field are kept: the fields can carry repository text.
_TRIVY_ERROR = re.compile(r"\bERROR\b\s*(\[[^\]]{1,60}\])?\s*(.*?)(?=\s+[A-Za-z_]+=|$)")
# a module trivy couldn't load: expected when stage 2 already reported it missing, so a note, not a failure
_TRIVY_MODULE = re.compile(r"\bmodule\b", re.IGNORECASE)
# checkov's secret checks put an unsalted SHA-1 of the secret in `resource`: a password-guessing oracle, so it's
# replaced before the finding reaches a report
_SECRET_CHECK = re.compile(r"^CKV_SECRET_\d+$")
REDACTED_SECRET = "<redacted secret>"  # noqa: S105 - a placeholder, not a credential
# oldest versions whose JSON shape this module understands; older → a warning (the parse may still work)
SCANNER_MIN = {"trivy": (0, 50, 0), "checkov": (3, 0, 0)}
_VER = re.compile(r"(\d+)\.(\d+)\.(\d+)")
_INDEX = re.compile(r"\[[^\]]*\]")
_TOP_BLOCK = re.compile(
    r'^(resource|data|module|variable|output|locals|provider|terraform|check|import|moved)\b\s*"?([A-Za-z0-9_-]*)'
)


class ScannerError(RuntimeError):
    """A scanner did not produce a usable result."""


@dataclass
class Finding:
    id: str
    title: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | "" (unrated: checkov without a platform key)
    source: str  # trivy | checkov
    file: str  # as the graph names files (relative to the folder, `repo:` for a --with folder)
    line: int
    resource: str  # as the scanner named it
    message: str
    url: str = ""
    address: str = ""  # the graph resource it's about; "" when it couldn't be placed


@dataclass
class Scan:
    findings: list[Finding] = field(default_factory=list)
    status: dict[str, dict] = field(default_factory=dict)  # name → {version, ok, error, findings}
    notes: list[str] = field(default_factory=list)  # files left out of the copy, modules a scanner couldn't load

    @property
    def failed(self) -> list[str]:
        return [n for n, s in self.status.items() if not s["ok"]]

    def to_dict(self) -> dict:
        return {"status": self.status, "findings": [asdict(f) for f in self.findings], "notes": self.notes}


def rank(severity: str) -> int:
    return SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES)


# --- running


def _run(cmd: list[str], cwd: str, env: dict) -> sandbox.Bounded:
    try:
        p = sandbox.run_bounded(cmd, cwd=cwd, env=env, timeout=SCANNER_TIMEOUT)
    except FileNotFoundError:
        raise ScannerError(f"{cmd[0]} isn't installed (not on PATH)") from None
    except subprocess.TimeoutExpired:
        raise ScannerError(f"{cmd[0]} timed out after {SCANNER_TIMEOUT}s") from None
    if p.too_large:
        raise ScannerError(f"{cmd[0]} wrote more than {sandbox.MAX_OUTPUT_BYTES // (1024 * 1024)} MB of output")
    return p


def _json(name: str, p: sandbox.Bounded):
    tail = sandbox.one_line((p.stderr or p.stdout).strip()[-300:])
    if p.returncode != 0:
        raise ScannerError(f"{name} exited {p.returncode}: {tail or 'no output'}")
    try:
        return json.loads(p.stdout or "")
    except (json.JSONDecodeError, RecursionError):
        raise ScannerError(f"{name} printed no JSON: {tail or 'empty output'}") from None


def scanner_version(name: str, home: str) -> str | None:
    """`<scanner> --version`, from an empty private dir with the scan's environment (checkov reads .checkov.yaml
    from its working directory even for --version)."""
    try:
        p = subprocess.run(
            [name, "--version"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            stdin=subprocess.DEVNULL,
            cwd=home,
            env=sandbox.clean_env(home, offline=True),
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    m = _VER.search(p.stdout or p.stderr or "")
    return m.group(0) if m else None


def version_warning(name: str, version: str | None) -> str | None:
    m = _VER.search(version or "")
    if m and tuple(int(x) for x in m.groups()) < SCANNER_MIN[name]:
        return f"{name} {version} is older than the oldest supported {'.'.join(map(str, SCANNER_MIN[name]))}"
    return None


def trivy_cache(work: str) -> str:
    """terrahunter's own trivy cache (the downloaded checks bundle), kept between runs when its directory is private,
    else a throwaway one inside `work`: someone else could plant a checks bundle in a shared one."""
    base = Path(
        os.environ.get("TH_CACHE_DIR")
        or Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "terrahunter"
    )
    path = base / "trivy"
    if sandbox.private_dir(base) and sandbox.private_dir(path):
        return str(path)
    tmp = Path(work) / "trivy-cache"
    tmp.mkdir(mode=0o700, exist_ok=True)
    return str(tmp)


def _warm_trivy_checks(cache: str, work: str) -> None:
    """Let trivy fetch its latest checks bundle into the cache by scanning an empty directory: no untrusted input is
    involved, so this run may use the network. The real scan then runs offline with --skip-check-update. A failure
    here is fine: trivy falls back to the cached or built-in checks."""
    empty = Path(work) / "empty"
    empty.mkdir(exist_ok=True)
    cmd = ["trivy", "config", "--quiet", "--format", "json", "--config", "", "--ignorefile", "", "--cache-dir", cache]
    try:
        subprocess.run(
            [*cmd, str(empty)],
            capture_output=True,
            timeout=180,
            check=False,
            cwd=work,
            env=sandbox.clean_env(work),
            stdin=subprocess.DEVNULL,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass


def trivy_log(stderr: str) -> tuple[list[str], list[str], list[str]]:
    """trivy's ERROR lines → (files it couldn't parse, modules it couldn't load, other errors), each without the
    key=value fields, which can carry repository text."""
    unparsed: list[str] = []
    modules: list[str] = []
    errors: list[str] = []
    for line in stderr.splitlines():
        if _TRIVY_BENIGN.match(line):
            continue
        if _TRIVY_PARSE_ERROR.search(line):
            m = _TRIVY_FILE.search(line)
            name = sandbox.one_line(m.group(1), 200) if m else "(unnamed)"
            if name not in unparsed:
                unparsed.append(name)
            continue
        m = _TRIVY_ERROR.search(line)
        if m:
            text = sandbox.one_line(" ".join(x for x in m.groups() if x), 120) or "ERROR"
            bucket = modules if _TRIVY_MODULE.search(text) else errors
            if text not in bucket:
                bucket.append(text)
    return unparsed, modules, errors


def run_trivy(scan_dir: str, work: str) -> tuple[list[dict], list[str]]:
    """trivy config, contained: no trivy.yaml, .trivyignore or WASM modules are loaded, the checks are the cached or
    built-in ones (no update download), and it can't reach the network to fetch remote modules."""
    cache = trivy_cache(work)
    _warm_trivy_checks(cache, work)
    cmd = ["trivy", "config", "--format", "json", "--config", "", "--ignorefile", ""]  # not --quiet: errors are logs
    cmd += ["--skip-check-update", "--module-dir", work, "--cache-dir", cache, scan_dir]
    p = _run(cmd, work, sandbox.clean_env(work, offline=True))
    data = _json("trivy", p)
    unparsed, modules, errors = trivy_log(p.stderr or "")
    if unparsed:
        more = f" (+{len(unparsed) - 10} more)" if len(unparsed) > 10 else ""
        raise ScannerError(
            f"trivy couldn't parse {len(unparsed)} file(s), so they weren't scanned: " + ", ".join(unparsed[:10]) + more
        )
    if errors:
        more = f" (+{len(errors) - 5} more)" if len(errors) > 5 else ""
        raise ScannerError(
            "trivy reported errors, so part of the configuration wasn't evaluated: " + "; ".join(errors[:5]) + more
        )
    out = []
    for r in (data if isinstance(data, dict) else {}).get("Results") or []:
        if not isinstance(r, dict):
            continue
        for m in r.get("Misconfigurations") or []:
            if not isinstance(m, dict):
                continue
            cm = m.get("CauseMetadata") if isinstance(m.get("CauseMetadata"), dict) else {}
            out.append(
                {
                    "id": m.get("ID") or m.get("AVDID"),
                    "title": m.get("Title"),
                    "severity": m.get("Severity"),
                    "resource": cm.get("Resource"),
                    "file": r.get("Target"),
                    "line": cm.get("StartLine"),
                    "message": m.get("Message"),
                    "url": m.get("PrimaryURL"),
                    "source": "trivy",
                }
            )
    return out, [f"trivy: {e}" for e in modules]


def run_checkov(scan_dir: str, work: str) -> tuple[list[dict], list[str]]:
    """checkov, contained: from an empty dir with a throwaway HOME (so no .checkov.yaml is found), nothing downloaded
    from Prisma Cloud or for external modules, no credentials from the environment."""
    # --soft-fail: exit 0 even when checks fail, so a non-zero exit is a real scanner failure
    cmd = ["checkov", "-d", scan_dir, "-o", "json", "--compact", "--quiet", "--soft-fail"]
    cmd += ["--skip-download", "--download-external-modules", "false"]
    data = _json("checkov", _run(cmd, work, sandbox.clean_env(work, offline=True)))
    blocks = data if isinstance(data, list) else [data]
    # checkov exits 0 and skips a file it can't parse; the only sign is this counter in each block's summary
    unparsed = sum(
        b["summary"].get("parsing_errors") or 0
        for b in blocks
        if isinstance(b, dict)
        and isinstance(b.get("summary"), dict)
        and isinstance(b["summary"].get("parsing_errors"), int)
    )
    if unparsed:
        raise ScannerError(f"checkov couldn't parse {unparsed} file(s), so they weren't scanned")
    out = []
    for b in blocks:
        results = b.get("results") if isinstance(b, dict) and isinstance(b.get("results"), dict) else {}
        for c in results.get("failed_checks") or []:
            if not isinstance(c, dict):
                continue
            lr = c.get("file_line_range") if isinstance(c.get("file_line_range"), list) else []
            out.append(
                {
                    "id": c.get("check_id"),
                    "title": c.get("check_name"),
                    "severity": c.get("severity"),
                    "resource": c.get("resource"),
                    "file": (c.get("file_path") or "").lstrip("/"),  # relative to -d, but starting with "/"
                    "line": lr[0] if lr else 0,
                    "message": c.get("check_name"),
                    "url": c.get("guideline"),
                    "source": "checkov",
                }
            )
    return out, []


RUNNERS = {"trivy": run_trivy, "checkov": run_checkov}


# --- the staged copy


@dataclass
class Staged:
    base: Path  # the copy: every folder under review at its path relative to their common ancestor
    scan_dir: Path  # the root module inside it
    real: dict[str, Path]  # staged path (relative to base, posix) → the real file
    notes: list[str]


def _staged_name(name: str) -> str:
    """The scanners read .tf and .tf.json only: an OpenTofu file is staged with that suffix added."""
    if name.endswith(".tofu"):
        return name + ".tf"
    if name.endswith(".tofu.json"):
        return name[: -len(".json")] + ".tf.json"
    return name


def stage(g: graph.Graph, folder: Path, allowed: list[Path], dest: Path) -> Staged:
    """Copy the directories the graph read into dest. Raises sandbox.UnsafeConfig when a module source (or the
    modules.json index) would take a scanner outside the allowed folders: then nothing is scanned."""
    folder = folder.resolve()
    allowed = [a.resolve() for a in allowed]
    common = Path(os.path.commonpath([str(a) for a in allowed]))
    root_dir = g.dirs[0]
    budget = [sandbox.MAX_TOTAL_BYTES]
    files: list[Path] = []
    notes: list[str] = []
    for d in g.dirs:
        found, skipped = sandbox.tf_files(d, recursive=False, budget=budget)
        files += found
        notes += [f"{graph.dir_label(d, folder, allowed)}/{s}" for s in skipped]
    index = sandbox.downloaded_modules(root_dir) / "modules.json"
    problems = []
    if sandbox.is_regular_inside(index, root_dir):
        files.append(index)
        problems += sandbox.check_modules_json(index, root_dir, allowed)

    def label(p: Path) -> str:
        return f"{graph.dir_label(p.resolve().parent, folder, allowed)}/{p.name}".removeprefix("./")

    problems += sandbox.check_module_sources(files, allowed, label)
    if problems:
        raise sandbox.UnsafeConfig(
            "; ".join(problems[:5]) + (f" (+{len(problems) - 5} more)" if len(problems) > 5 else "")
        )
    real: dict[str, Path] = {}
    for p in files:
        rel = p.resolve().relative_to(common)
        target = dest / rel.parent / _staged_name(p.name)
        try:
            data = sandbox.read_regular(p)
        except OSError:
            notes.append(f"{label(p)}: changed or not a regular file while staging, skipped")
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "xb") as out:
            out.write(data)
        real[target.relative_to(dest).as_posix()] = p.resolve()
    return Staged(dest, dest / root_dir.relative_to(common), real, notes)


# --- placing findings on resources


def _clean(raw: dict, file: str, address: str = "") -> Finding:
    """One finding, every string scanner output about untrusted files: controls and newlines removed here, once."""
    line = raw.get("line")
    secret = isinstance(raw.get("id"), str) and bool(_SECRET_CHECK.match(raw["id"]))
    url = raw.get("url") if isinstance(raw.get("url"), str) and raw["url"].startswith("https://") else ""
    return Finding(
        sandbox.one_line(raw.get("id") or "", 120),
        sandbox.one_line(raw.get("title") or "", 300),
        sandbox.one_line(raw.get("severity") or "", 20).upper(),
        raw["source"],
        sandbox.one_line(file, 300),
        line if isinstance(line, int) and not isinstance(line, bool) and line >= 0 else 0,
        REDACTED_SECRET if secret else sandbox.one_line(raw.get("resource") or "", 300),
        sandbox.one_line(raw.get("message") or "", 300),
        sandbox.one_line(url, 300),
        address,
    )


def place(raws: list[dict], g: graph.Graph, staged: Staged, folder: Path, allowed: list[Path]) -> list[Finding]:
    """Scanner findings → Findings on graph addresses, one per (address, scanner, check). A finding located outside
    the staged copy proves a scanner read from elsewhere on this machine: the scan fails rather than report it."""
    folder = folder.resolve()
    allowed = [a.resolve() for a in allowed]
    base = Path(os.path.normpath(staged.base))
    by_file: dict[str, list[tuple[int, str]]] = {}
    for a, r in g.resources.items():
        by_file.setdefault(r.file, []).append((r.line, a))
    blocks: dict[str, list[tuple[int, str, str]]] = {}  # file label → its top-level blocks (line, kind, name)

    def blocks_in(real: Path, lbl: str) -> list[tuple[int, str, str]]:
        if lbl not in blocks:
            try:
                text = sandbox.read_regular(real).decode("utf-8", "replace")
            except OSError:
                text = ""
            blocks[lbl] = [
                (i, m.group(1), m.group(2) or "")
                for i, ln in enumerate(text.splitlines(), 1)
                if (m := _TOP_BLOCK.match(ln))
            ]
        return blocks[lbl]

    def locate(f: str) -> Path | None:
        """The real file a scanner path names. trivy names a downloaded module's file after the module's source
        (`terraform-aws-modules/vpc/aws/.terraform/modules/vpc/main.tf`), so the longest tail that's a staged file
        inside the root counts."""
        p = Path(os.path.normpath(staged.scan_dir / f))
        if p != base and base not in p.parents:
            raise ScannerError("a finding outside the scanned copy")
        if (hit := staged.real.get(p.relative_to(base).as_posix())) is not None:
            return hit
        parts = Path(f).parts
        for i in range(1, len(parts)):
            q = Path(os.path.normpath(staged.scan_dir.joinpath(*parts[i:])))
            if base in q.parents and (hit := staged.real.get(q.relative_to(base).as_posix())) is not None:
                return hit
        return None

    out: list[Finding] = []
    seen: set[tuple[str, str, str, str]] = set()
    for raw in raws:
        f = raw.get("file") if isinstance(raw.get("file"), str) else ""
        try:
            if "://" in f or os.path.isabs(f):
                raise ScannerError("a finding outside the scanned copy")
            real = locate(f)
        except ScannerError:
            raise ScannerError(
                f"{raw['source']} reported a finding outside the scanned copy; refusing its results"
            ) from None
        if real is None:  # a file the scanner made up or found by itself: report it, unplaced
            out.append(_clean(raw, f))
            continue
        lbl = f"{graph.dir_label(real.parent, folder, allowed)}/{real.name}".removeprefix("./")
        res = _INDEX.sub("", raw.get("resource") or "") if isinstance(raw.get("resource"), str) else ""
        line = raw.get("line") if isinstance(raw.get("line"), int) else 0
        named = [x for x in (res, "data." + res) if x in g.resources and g.resources[x].file == lbl]
        if named:  # checkov names a data source without its `data.`
            addrs = named[:1]
        else:
            # the block the line is in: the last top-level block starting at or before it. A resource block names
            # its resource (in every instance of the module the file is in); a module block names the call.
            at = max((b for b in blocks_in(real, lbl) if b[0] <= line), default=None) if line else None
            addrs = []
            if at and at[1] in ("resource", "data"):
                addrs = [a for ln, a in by_file.get(lbl, []) if ln == at[0]]
            elif at and at[1] == "module":
                addrs = [
                    (prefix + "." if prefix else "") + f"module.{at[2]}"
                    for prefix, d in g.module_dirs.items()
                    if d == real.parent
                ]
            if res.startswith("module.") and any(a.startswith(res + ".") for a in addrs):
                addrs = [a for a in addrs if a.startswith(res + ".")]  # trivy names the module instance
        for a in addrs or [""]:
            key = (a, raw["source"], str(raw.get("id")), "" if a else f"{lbl}:{line}")
            if key not in seen:
                seen.add(key)
                out.append(_clean(raw, lbl, a))
    out.sort(key=lambda x: (rank(x.severity), x.address == "", x.address, x.id))
    return out


# --- the stage


def scan(g: graph.Graph, folder: Path, with_folders: list[Path] | None = None) -> Scan:
    """Run both scanners concurrently on a staged copy of what the graph read. Never raises for a scanner: each
    failure is recorded in `status`, and the other scanner's findings are still returned."""
    res = Scan()
    allowed = [folder.resolve()] + [w.resolve() for w in with_folders or []]
    work = os.path.realpath(tempfile.mkdtemp(prefix="terrahunter-scan-"))  # 0700
    try:
        homes = {}
        for name in RUNNERS:
            homes[name] = str(Path(work) / name)
            Path(homes[name]).mkdir()
        try:
            staged = stage(g, folder, allowed, Path(work) / "target")
        except sandbox.UnsafeConfig as e:
            msg = f"not scanned: the configuration points the scanners outside the folder ({e})"
            for name in RUNNERS:
                res.status[name] = {"version": None, "ok": False, "error": msg, "findings": 0}
            return res
        res.notes += staged.notes
        raws: list[dict] = []
        with ThreadPoolExecutor(max_workers=2 * len(RUNNERS)) as ex:
            futs = {n: ex.submit(fn, str(staged.scan_dir), homes[n]) for n, fn in RUNNERS.items()}
            versions = {n: ex.submit(scanner_version, n, homes[n]) for n in RUNNERS}
            for name, fut in futs.items():
                st = {"version": versions[name].result(), "ok": True, "error": None, "findings": 0}
                try:
                    found, notes = fut.result()
                    placed = place(found, g, staged, folder, allowed)  # checked before any of it is kept
                    raws += found
                    res.notes += notes
                    st["findings"] = len(placed)
                except ScannerError as e:
                    st["ok"], st["error"] = False, str(e)
                warn = version_warning(name, st["version"])
                if warn:
                    res.notes.append(warn)
                res.status[name] = st
        res.findings = place(raws, g, staged, folder, allowed)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return res
