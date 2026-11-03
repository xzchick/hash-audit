"""Locate and run John Jumbo's ``*2john`` helpers to pull a password hash out
of an encrypted file, so it can be recovered locally.

The helpers ship with John the Ripper Jumbo. They read the file and print a
``path:$name$…`` hash line; nothing is decrypted and nothing leaves the machine.
This module only discovers the right helper and runs it without a shell, with a
bounded output size and a time limit. Recovery of the extracted hash is handled
by the ``recover`` command through John, which auto-detects the exact variant.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

_UNSAFE_LABEL = re.compile(r"[^A-Za-z0-9._-]")

# Cap the helper's captured output. Supported container hashes are short; a
# runaway or unexpected helper must not fill memory.
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
DEFAULT_TIMEOUT = 120


@dataclass(frozen=True)
class Extractor:
    key: str                     # matches the container format key in formats.py
    label: str
    tool: str                    # the *2john helper's base filename
    kind: str                    # "native", "python" or "perl"
    extensions: tuple[str, ...]  # lowercase suffixes, including the dot
    magics: tuple[bytes, ...] = ()  # byte signatures expected at offset 0


# v1 ships the native helpers, which work on a stock John Jumbo install. The
# Python helpers (office2john.py, ssh2john.py) are Python 2 on older John builds
# such as 1.9.0, so they are left for a follow-up that pins a Python-3 helper.
EXTRACTORS: dict[str, Extractor] = {
    "zip": Extractor("zip", "ZIP archive", "zip2john", "native", (".zip",), (b"PK\x03\x04",)),
    "rar": Extractor("rar", "RAR archive", "rar2john", "native", (".rar",), (b"Rar!\x1a\x07",)),
    "keepass": Extractor("keepass", "KeePass database", "keepass2john", "native",
                         (".kdbx",), (b"\x03\xd9\xa2\x9a",)),
}


def john_tool_dir() -> Path | None:
    """The directory holding John Jumbo and its ``*2john`` helpers, if found."""
    john = shutil.which("john")
    if not john:
        return None
    return Path(os.path.realpath(john)).parent


def _candidate_paths(name: str) -> list[Path]:
    paths: list[Path] = []
    found = shutil.which(name)
    if found:
        paths.append(Path(found))
    run_dir = john_tool_dir()
    if run_dir is not None:
        paths.append(run_dir / name)
        if os.name == "nt":
            paths.append(run_dir / (name + ".exe"))
    # De-duplicate while preserving order.
    seen: set[str] = set()
    unique: list[Path] = []
    for path in paths:
        key = str(path)
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def locate(extractor: Extractor) -> list[str] | None:
    """Return the argv prefix that runs the helper, or None if it is missing.

    Native helpers run directly; ``.py`` helpers run under this same Python and
    ``.pl`` helpers under ``perl``. No shell is involved at any point.
    """
    tool_path = next((p for p in _candidate_paths(extractor.tool) if p.is_file()), None)
    if tool_path is None:
        return None
    if extractor.kind == "python":
        return [sys.executable, str(tool_path)]
    if extractor.kind == "perl":
        perl = shutil.which("perl")
        if perl is None:
            return None
        return [perl, str(tool_path)]
    if not os.access(tool_path, os.X_OK) and os.name != "nt":
        return None
    return [str(tool_path)]


def read_head(path: Path, size: int = 4096) -> bytes:
    """Read the first bytes of a regular file without blocking on a FIFO."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as source:
        return source.read(size)


def detect(path: Path, head: bytes) -> list[str]:
    """Return candidate extractor keys for a file, by extension then magic bytes.

    Extension wins when it is recognized (a .docx is a ZIP by magic but an Office
    document in practice); magic bytes are the fallback for extensionless files
    such as an SSH ``id_rsa``.
    """
    suffix = path.suffix.lower()
    by_ext = [e.key for e in EXTRACTORS.values() if suffix and suffix in e.extensions]
    if by_ext:
        return by_ext
    return [e.key for e in EXTRACTORS.values() if e.magics and head.startswith(e.magics)]


def hash_lines(output: bytes) -> list[str]:
    """De-duplicated ``label:hash`` lines from a helper's stdout.

    A ``*2john`` helper prefixes each hash with a ``path:`` label naming the file
    or archive member, and John needs that label to load the hash. The label is
    sanitized to plain ASCII — which also trims the real filename out of the
    stored result — while the hash after the colon is left exactly as emitted.
    """
    lines: list[str] = []
    for raw in output.decode("utf-8", errors="replace").split("\n"):
        line = raw.rstrip("\r").strip()
        if not line:
            continue
        head, separator, rest = line.partition(":")
        if separator and rest and "$" not in head and "*" not in head:
            label = _UNSAFE_LABEL.sub("_", head)[:64] or "file"
            line = f"{label}:{rest}"
        lines.append(line)
    return list(dict.fromkeys(lines))


def run_helper(argv: list[str], timeout: int = DEFAULT_TIMEOUT) -> tuple[int, bytes, bytes]:
    """Run the helper with no shell, a time limit and a bounded stdout.

    Returns (returncode, stdout, stderr). Raises ValueError on timeout or
    oversize output.
    """
    options: dict = {"start_new_session": True} if os.name == "posix" else {
        "creationflags": subprocess.CREATE_NEW_PROCESS_GROUP,
    }
    proc = subprocess.Popen(
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, shell=False, **options,
    )
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise ValueError(f"extractor timed out after {timeout}s") from None
    if len(out) > MAX_OUTPUT_BYTES:
        raise ValueError(f"extractor produced more than {MAX_OUTPUT_BYTES} bytes of output")
    return proc.returncode, out, err
