"""Containment for reading Terraform you don't trust.

The folder under review may be a pull request from a stranger, so nothing in it is trusted: files are only read when
they are regular files inside the folder (a symlink to ~/.ssh is never followed), every read has a size limit, and
text that came from the folder has control characters removed before it reaches a terminal or a report.
"""

from __future__ import annotations

import contextlib
import os
import re
import signal
import stat
import threading
from pathlib import Path

MAX_FILE_BYTES = 5 * 1024 * 1024  # a Terraform file bigger than this is skipped, not parsed
MAX_FILES = 20_000
MAX_TOTAL_BYTES = 200 * 1024 * 1024  # all the Terraform files of one run together
# configuration files (Terraform and OpenTofu), then variable files
CONFIG_SUFFIXES = (".tf", ".tf.json", ".tofu", ".tofu.json")
TF_SUFFIXES = CONFIG_SUFFIXES + (".tfvars", ".tfvars.json")

# C0 and C1 controls except tab and newline: ESC starts terminal escape sequences (OSC 8 links, OSC 52 clipboard
# writes, title changes), the rest can hide or reorder text
_CONTROLS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def strip_controls(text: object) -> str:
    return _CONTROLS.sub("", str(text))


def one_line(text: object, limit: int | None = None) -> str:
    """Folder-derived text for a single line of output: no controls, no newlines."""
    s = " ".join(strip_controls(text).split())
    return s[:limit] if limit else s


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


def tf_files(root: Path, recursive: bool = True, budget: list[int] | None = None) -> tuple[list[Path], list[str]]:
    """The Terraform files under root that are safe to read, and a note for each one left out. Hidden directories
    (.git, .terraform, …) and symlinked directories are not entered. `budget` ([bytes left]) lets several calls share
    one MAX_TOTAL_BYTES allowance; it's updated in place."""
    found, skipped = [], []
    budget = budget if budget is not None else [MAX_TOTAL_BYTES]
    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith(".")) if recursive else []
        for name in sorted(filenames):
            if not name.endswith(TF_SUFFIXES) or name.startswith("."):
                continue
            p = Path(dirpath) / name
            rel = p.relative_to(root).as_posix()
            if not is_regular_inside(p, root):
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
