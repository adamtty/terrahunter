"""Containment for reading Terraform you don't trust.

The folder under review may be a pull request from a stranger, so nothing in it is trusted: files are only read when
they are regular files inside the folder, or symlinks to one (a shared variables file linked into each root; a
symlink to ~/.ssh, or anywhere outside the folders under review, is never followed), every read has a size limit, and
text that came from the folder has control characters removed before it reaches a terminal or a report. The
scanners run on a staged copy, from an empty directory, with a throwaway HOME, a minimal environment, no network
and a cap on what they may write (see `scanners`).
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import hcl2


def _mb_from_env(name: str, default_mb: int) -> int:
    """A size limit in bytes from $name (in MB, a positive whole number), else the default."""
    try:
        mb = int(os.environ.get(name, ""))
    except ValueError:
        mb = 0
    return (mb if mb > 0 else default_mb) * 1024 * 1024


MAX_FILE_BYTES = 5 * 1024 * 1024  # a Terraform file bigger than this is skipped, not parsed
MAX_FILES = 20_000
MAX_TOTAL_BYTES = 200 * 1024 * 1024  # all the Terraform files of one run together
# configuration files (Terraform and OpenTofu), then variable files
CONFIG_SUFFIXES = (".tf", ".tf.json", ".tofu", ".tofu.json")
TF_SUFFIXES = CONFIG_SUFFIXES + (".tfvars", ".tfvars.json")
# what a scanner may write: stdout and stderr together (they go to files, then are read back into memory), and any
# single file, which RLIMIT_FSIZE enforces by stopping the process when it writes past it
MAX_OUTPUT_BYTES = _mb_from_env("TH_MAX_OUTPUT_MB", 64)
# the environment the scanners get: enough to run, nothing that identifies or authenticates the user
_ENV_KEEP = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ")
# a proxy that refuses every connection, so a scanner can't fetch remote modules (SSRF, beacons, credentialed git
# clones) while scanning untrusted code
DEAD_PROXY = "http://127.0.0.1:9"

# C0 and C1 controls except tab and newline: ESC starts terminal escape sequences (OSC 8 links, OSC 52 clipboard
# writes, title changes), the rest can hide or reorder text
_CONTROLS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def strip_controls(text: object) -> str:
    return _CONTROLS.sub("", str(text))


def one_line(text: object, limit: int | None = None) -> str:
    """Folder-derived text for a single line of output: no controls, no newlines."""
    s = " ".join(strip_controls(text).split())
    return s[:limit] if limit else s


def linked_inside(link: Path, folders: list[Path]) -> Path | None:
    """The real path of a symlinked file, when it's a regular file (not another link, a FIFO or a device) inside one
    of the folders; None otherwise (a link to ~/.ssh, to a directory, or that dangles)."""
    try:
        real = link.resolve(strict=True)
        st = real.lstat()
    except (OSError, RuntimeError):
        return None
    if not stat.S_ISREG(st.st_mode):
        return None
    for f in folders:
        try:
            real.relative_to(f.resolve())
            return real
        except (OSError, ValueError):
            continue
    return None


def is_regular_inside(path: Path, root: Path) -> bool:
    """True for a regular file (not a symlink, FIFO or device) whose real path is inside root."""
    try:
        st = path.lstat()
    except OSError:
        return False
    if not stat.S_ISREG(st.st_mode):
        return False
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def read_regular(path: Path, limit: int = MAX_FILE_BYTES) -> bytes:
    """A file's bytes, opened so that a symlink, FIFO or device swapped in after a check is refused (O_NOFOLLOW,
    O_NONBLOCK, then fstat on the open file), and never more than `limit` bytes. Raises OSError otherwise."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(f"{path}: not a regular file")
        if st.st_size > limit:
            raise OSError(f"{path}: larger than {limit} bytes")
        with os.fdopen(fd, "rb", closefd=False) as fh:
            data = fh.read(limit + 1)
    finally:
        os.close(fd)
    if len(data) > limit:
        raise OSError(f"{path}: larger than {limit} bytes")
    return data


def tf_files(
    root: Path,
    recursive: bool = True,
    budget: list[int] | None = None,
    inside: list[Path] | None = None,
    where: list[Path] | None = None,
) -> tuple[list[Path], list[str]]:
    """The Terraform files under root that are safe to read, and a note for each one left out. Hidden directories
    (.git, .terraform, …) and symlinked directories are not entered. A symlinked file is read when its real path is a
    regular file inside root or one of the `inside` folders (the folders under analysis: a shared variables-common.tf
    linked into each root); its real path is what's returned. `budget` ([bytes left]) lets several calls share one
    MAX_TOTAL_BYTES allowance; it's updated in place. `where`, when given, gets each file's path as it is in the folder
    (a link's own path, whose directory it belongs to), in the same order."""
    found, skipped = [], []
    budget = budget if budget is not None else [MAX_TOTAL_BYTES]
    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith(".")) if recursive else []
        for name in sorted(filenames):
            if not name.endswith(TF_SUFFIXES) or name.startswith("."):
                continue
            p = at = Path(dirpath) / name
            rel = p.relative_to(root).as_posix()
            if p.is_symlink() and (real := linked_inside(p, [root, *(inside or [])])):
                p = real
            elif not is_regular_inside(p, root):
                skipped.append(f"{rel}: not a regular file inside the folder (symlink or special file), skipped")
                continue
            size = p.lstat().st_size
            if size > MAX_FILE_BYTES:
                skipped.append(f"{rel}: larger than {MAX_FILE_BYTES // (1024 * 1024)} MB, skipped")
                continue
            if size > budget[0]:
                skipped.append(
                    f"Terraform files over {MAX_TOTAL_BYTES // (1024 * 1024)} MB in total; the rest were skipped"
                )
                return found, skipped
            budget[0] -= size
            found.append(p)
            if where is not None:
                where.append(at)
            if len(found) >= MAX_FILES:
                skipped.append(f"more than {MAX_FILES} Terraform files; the rest were skipped")
                return found, skipped
    return found, skipped


def downloaded_modules(root: Path) -> Path:
    """Where `init` / `get` put the modules a configuration uses."""
    return Path(root) / ".terraform" / "modules"


class ParseTimeout(BaseException):  # BaseException, so a broad `except Exception` can't swallow it
    """Parsing one file took longer than its time limit."""


def parse_limit() -> float:
    """Seconds one Terraform file may take to parse ($TH_PARSE_TIMEOUT, default 60)."""
    try:
        v = float(os.environ.get("TH_PARSE_TIMEOUT", "60"))
    except ValueError:
        v = 60.0
    return v if v > 0 else 60.0


PARSE_BUDGET = 600.0  # seconds for all the files of one parse together


@contextlib.contextmanager
def time_limit(seconds: float):
    """Raise ParseTimeout in this thread after `seconds` (SIGALRM; a no-op off the main thread or without it)."""
    if not hasattr(signal, "setitimer") or threading.current_thread() is not threading.main_thread():
        yield
        return

    def fire(signum, frame):
        raise ParseTimeout

    old = signal.signal(signal.SIGALRM, fire)
    signal.setitimer(signal.ITIMER_REAL, max(seconds, 0.001))
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


class UnsafeConfig(RuntimeError):
    """The configuration would make a scanner read from outside the folders under review."""


_ABS_SOURCE = re.compile(r"^(?:/|~|\\|[A-Za-z]:[\\/])")
_FILE_GETTER = re.compile(r"file:", re.IGNORECASE)
_MENTIONS_MODULE = re.compile(r"\bmodule\b")
# for a file the parser rejects: every `source =` (HCL) or `"source":` (JSON) in it, quoted or heredoc. Broader than
# module blocks on purpose: such a file is reported as unparseable anyway, so a false alarm costs nothing.
_ANY_SOURCE = re.compile(r'\bsource"?\s*[=:]\s*(?:"((?:[^"\\]|\\.)*)"|(<<))')


def _unquote(v: object) -> str | None:
    if not isinstance(v, str):
        return None
    return v[1:-1] if len(v) >= 2 and v[0] == v[-1] == '"' else v


def module_sources(name: str, text: str, limit: float | None = None) -> list[str]:
    """Every `source` of a `module` block in one file. A file that never says `module` has none (no parse needed);
    otherwise python-hcl2 / json, under `limit` seconds (ParseTimeout past it); and when the parser rejects the file,
    every `source` in it, so a file the parser can't read is still checked."""
    if not _MENTIONS_MODULE.search(text):
        return []
    out: list[str] = []
    try:
        with time_limit(limit) if limit else contextlib.nullcontext():
            data = json.loads(text) if name.endswith(".json") else hcl2.loads(text)
    except Exception:  # noqa: BLE001 - any parse failure falls back to the regex below (ParseTimeout passes through)
        data = None
    if isinstance(data, dict):
        mods = data.get("module")
        for group in mods if isinstance(mods, list) else [mods]:
            for body in (group or {}).values() if isinstance(group, dict) else []:
                for b in body if isinstance(body, list) else [body]:
                    if isinstance(b, dict) and "source" in b:
                        src = _unquote(b["source"])
                        out.append(src if src is not None else "<not a string>")
        return out
    return [quoted if heredoc == "" else "<<heredoc" for quoted, heredoc in _ANY_SOURCE.findall(text)]


def _inside(target: Path, allowed: list[Path]) -> bool:
    return any(target == a or a in target.parents for a in allowed)


def module_source_problem(source: str, file_dir: Path, allowed: list[Path]) -> str | None:
    """Why a module source would make a scanner read outside the folders under review, or None when it's safe (a
    registry or remote address, which the dead proxy blocks, or a relative path that stays inside them)."""
    s = source.strip()
    if "${" in s or s == "<not a string>" or s.startswith("<<") or "\n" in source:
        return "isn't a literal string"
    if _FILE_GETTER.search(s):
        return "uses a file: getter"
    if _ABS_SOURCE.match(s):
        return "is an absolute path"
    relative = s in (".", "..") or s.startswith(("./", "../", ".\\", "..\\"))
    if relative and not _inside(Path(os.path.normpath(Path(file_dir) / s.replace("\\", "/"))), allowed):
        return "points outside the folders under review"
    return None


def check_module_sources(files: list[Path], allowed: list[Path], label) -> list[str]:
    """Every module source in files that would take a scanner outside the allowed folders, as notes. The text is
    read again here (regular files only, size-capped), so this checks exactly what gets staged."""
    allowed = [Path(os.path.normpath(a.resolve())) for a in allowed]
    problems = []
    started = time.monotonic()
    for p in files:
        if not p.name.endswith(CONFIG_SUFFIXES):
            continue
        try:
            text = read_regular(p, MAX_FILE_BYTES).decode("utf-8", "replace")
        except OSError:
            continue
        # bounded like the graph's own parse: a file too slow to check can't be scanned (fail closed)
        left = PARSE_BUDGET - (time.monotonic() - started)
        if left <= 0:
            problems.append(f"module sources could not all be checked within {PARSE_BUDGET:.0f}s")
            break
        limit = min(parse_limit(), left)
        try:
            sources = module_sources(p.name, text, limit)
        except ParseTimeout:
            problems.append(f"{label(p)}: module sources could not be checked within {limit:.0f}s")
            continue
        for src in sources:
            why = module_source_problem(src, Path(os.path.normpath(p.resolve().parent)), allowed)
            if why:
                problems.append(f'{label(p)}: module source "{one_line(src, 120)}" {why}')
    return problems


def check_modules_json(path: Path, root: Path, allowed: list[Path]) -> list[str]:
    """`.terraform/modules/modules.json` maps modules to directories (relative to the root module); every Dir must
    stay inside the allowed folders."""
    try:
        data = json.loads(read_regular(path, MAX_FILE_BYTES).decode("utf-8", "replace"))
    except (OSError, ValueError, RecursionError):
        return [".terraform/modules/modules.json: could not be read"]
    allowed = [Path(os.path.normpath(a.resolve())) for a in allowed]
    root = Path(os.path.normpath(Path(root).resolve()))
    problems = []
    entries = data.get("Modules") if isinstance(data, dict) else None
    for m in entries if isinstance(entries, list) else []:
        d = m.get("Dir") if isinstance(m, dict) else None
        if not isinstance(d, str):
            continue
        target = Path(os.path.normpath(d if os.path.isabs(d) else root / d))
        if _FILE_GETTER.search(d) or not _inside(target, allowed):
            problems.append(f'.terraform/modules/modules.json: Dir "{one_line(d, 120)}" points outside the folder')
    return problems


@dataclass
class Bounded:
    returncode: int
    stdout: str
    stderr: str
    too_large: bool = False  # the process was stopped for writing more than MAX_OUTPUT_BYTES


def run_bounded(
    cmd: list[str], *, cwd: str | None, env: dict | None, timeout: float, limit: int = MAX_OUTPUT_BYTES
) -> Bounded:
    """Run cmd (an argv list) with stdout / stderr captured in private temp files instead of memory, a file-size
    limit on everything the process writes (RLIMIT_FSIZE via `ulimit -f`, applied by /bin/sh to the exec'd
    command; the command is passed as positional arguments, never as shell text) and a timeout.
    Raises FileNotFoundError when the program isn't on PATH and subprocess.TimeoutExpired on timeout."""
    path = (env or os.environ).get("PATH", os.defpath)
    if not shutil.which(cmd[0], path=path):
        raise FileNotFoundError(cmd[0])
    blocks = max(1, limit // 512)  # POSIX sh counts in 512-byte blocks
    wrapped = ["/bin/sh", "-c", 'ulimit -f "$1" && shift && exec "$@"', "sh", str(blocks), *cmd]
    with tempfile.TemporaryDirectory(prefix="terrahunter-out-") as tmp:
        out_p, err_p = Path(tmp) / "out", Path(tmp) / "err"
        with open(out_p, "wb") as out, open(err_p, "wb") as err:
            p = subprocess.run(
                wrapped,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                cwd=cwd,
                env=env,
                timeout=timeout,
                check=False,
            )
        out_n, err_n = out_p.stat().st_size, err_p.stat().st_size
        # the cap is on stdout and stderr together: both are read back into memory
        too_large = out_n + err_n > limit or p.returncode in (-25, 128 + 25, 153)  # SIGXFSZ
        stdout = _read_capped(out_p, limit)
        stderr = _read_capped(err_p, max(0, limit - len(stdout.encode())))
        return Bounded(p.returncode, stdout, stderr, too_large)


def _read_capped(path: Path, limit: int) -> str:
    with open(path, "rb") as fh:
        return fh.read(limit).decode("utf-8", "replace")


def clean_env(home: str, offline: bool = False) -> dict[str, str]:
    """A minimal environment: PATH and locale and a throwaway HOME; `offline` adds a dead proxy and no git."""
    env = {k: os.environ[k] for k in _ENV_KEEP if k in os.environ}
    env.update(HOME=home, TMPDIR=home, XDG_CONFIG_HOME=home, XDG_CACHE_HOME=home)
    if offline:
        env.update(
            HTTP_PROXY=DEAD_PROXY,
            HTTPS_PROXY=DEAD_PROXY,
            http_proxy=DEAD_PROXY,
            https_proxy=DEAD_PROXY,
            NO_PROXY="",
            # no git protocol at all: not even `file`, which would let a `git::file:///…` module source clone a
            # repository from elsewhere on this machine into the scan
            GIT_ALLOW_PROTOCOL="none",
            GIT_TERMINAL_PROMPT="0",
            GIT_CONFIG_NOSYSTEM="1",
        )
    return env


def private_dir(path: Path) -> bool:
    """Make sure a cache directory is private before trusting it: created 0700 if missing; an existing one must be a
    real directory (not a symlink) owned by this user, and is tightened to 0700. A directory someone else owns, or
    a symlink, is refused: whoever can write there could plant a trivy checks bundle."""
    try:
        Path(path).mkdir(parents=True, exist_ok=True, mode=0o700)
        st = os.lstat(path)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
            return False
        if st.st_mode & 0o077:
            os.chmod(path, 0o700)
        return True
    except OSError:
        return False
