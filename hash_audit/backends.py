"""Argument-list adapters and bounded, terminal-safe local process execution.

Command references: https://hashcat.net/wiki/doku.php?id=hashcat and
https://github.com/openwall/john/blob/bleeding-jumbo/doc/OPTIONS
"""

from __future__ import annotations

import codecs
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import queue
import shutil
import signal
import subprocess
import sys
import threading
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .formats import HashFormat


@dataclass(frozen=True)
class RunResult:
    returncode: int
    timed_out: bool
    interrupted: bool
    elapsed: float


def safe_text(value: str) -> str:
    """Keep printable text and line feeds; escape terminal/bidi controls."""
    out: list[str] = []
    for char in value:
        if char == "\n" or char.isprintable():
            out.append(char)
        elif ord(char) <= 0xFF:
            out.append(f"\\x{ord(char):02x}")
        elif ord(char) <= 0xFFFF:
            out.append(f"\\u{ord(char):04x}")
        else:
            out.append(f"\\U{ord(char):08x}")
    return "".join(out)


def find_backend(name: str) -> str:
    if name not in {"hashcat", "john"}:
        raise ValueError("Backend must be hashcat or john.")
    executable = shutil.which(name)
    if executable is None:
        detail = "John the Ripper Jumbo" if name == "john" else "Hashcat"
        raise ValueError(f"{detail} was not found on PATH. See README.md installation instructions.")
    # Do not resolve symlinks: some package launchers rely on their invocation path.
    return os.path.abspath(executable)


def _path(value: Path) -> str:
    return str(value.expanduser().resolve())


def _hashcat_session(job_dir: Path) -> str:
    # Hashcat's session option is a name, not a path (slashes are rejected).
    return "hash-audit-" + hashlib.sha256(_path(job_dir).encode()).hexdigest()[:20]


def _check_backend(backend: str, fmt: HashFormat) -> None:
    if backend not in {"hashcat", "john"}:
        raise ValueError("Backend must be hashcat or john.")
    if backend == "john" and not fmt.john_format:
        raise ValueError(f"Format {fmt.key} is supported through Hashcat only.")


def build_command(
    backend: str,
    executable: str,
    fmt: HashFormat,
    hashes: Path,
    wordlist: Path | None,
    mask: str | None,
    job_dir: Path,
    status_interval: int,
    rules: Path | None = None,
) -> list[str]:
    """Build a fixed option allowlist. User strings are never shell commands."""
    _check_backend(backend, fmt)
    if not 1 <= status_interval <= 3600:
        raise ValueError("Status interval must be between 1 and 3600 seconds.")
    if (wordlist is None) == (mask is None):
        raise ValueError("Choose exactly one wordlist or mask.")
    if mask is not None:
        if not mask or len(mask) > 256 or mask.startswith("-") or not all(c.isprintable() for c in mask):
            raise ValueError("A mask must be 1–256 printable characters and cannot begin with '-'.")
        if rules is not None:
            raise ValueError("Rules require a wordlist.")
    pot = _path(job_dir / "recovered.pot")
    session = _path(job_dir / "session")
    if backend == "john":
        if mask is not None or rules is not None:
            raise ValueError("The John adapter supports wordlists only; use Hashcat for masks or rule files.")
        return [
            executable,
            f"--format={fmt.john_format}",
            f"--wordlist={_path(wordlist)}",
            f"--pot={pot}",
            f"--session={session}",
            f"--progress-every={status_interval}",
            "--no-log",
            _path(hashes),
        ]
    argv = [
        executable,
        "-m", str(fmt.hashcat_mode),
        "-a", "0" if wordlist is not None else "3",
        "--status", f"--status-timer={status_interval}",
        f"--session={_hashcat_session(job_dir)}",
        "--restore-disable", "--logfile-disable",
        f"--potfile-path={pot}",
        f"--outfile={_path(job_dir / 'recovered.txt')}",
        "--outfile-format=1,2",
    ]
    if rules is not None:
        argv += ["-r", _path(rules)]
    argv += [_path(hashes), _path(wordlist) if wordlist is not None else mask]
    return argv


def show_command(
    backend: str,
    executable: str,
    fmt: HashFormat,
    hashes: Path,
    job_dir: Path,
) -> list[str]:
    _check_backend(backend, fmt)
    pot = _path(job_dir / "recovered.pot")
    if backend == "john":
        return [executable, "--show", f"--format={fmt.john_format}", f"--pot={pot}", "--no-log", _path(hashes)]
    return [
        executable, "--show", "-m", str(fmt.hashcat_mode),
        f"--potfile-path={pot}", "--outfile-format=1,2",
        f"--session={_hashcat_session(job_dir)}-show", "--logfile-disable", "--restore-disable",
        _path(hashes),
    ]


def _signal_group(proc: subprocess.Popen, sig: int) -> None:
    try:
        if os.name == "posix":
            os.killpg(proc.pid, sig)
        elif sig == signal.SIGINT:
            proc.send_signal(signal.CTRL_BREAK_EVENT)
        elif sig == signal.SIGTERM:
            proc.terminate()
        else:
            proc.kill()
    except (ProcessLookupError, PermissionError):
        pass


def run_command(
    argv: list[str],
    cwd: Path,
    status_interval: int,
    max_seconds: int | None,
) -> RunResult:
    """Stream output with bounded buffering, and stop the process group on cancel.

    The time limit includes backend startup. Shutdown gets a two-second SIGINT
    grace period and a two-second SIGTERM grace period before forced cleanup.
    No keyboard input is forwarded; Ctrl-C stops the job from this wrapper.
    """
    if max_seconds is not None and max_seconds <= 0:
        raise ValueError("Maximum seconds must be positive.")
    if status_interval <= 0:
        raise ValueError("Status interval must be positive.")
    started = time.monotonic()
    options: dict = {"start_new_session": True, "umask": 0o077} if os.name == "posix" else {
        "creationflags": subprocess.CREATE_NEW_PROCESS_GROUP,
    }
    proc = subprocess.Popen(
        argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, shell=False, bufsize=0, **options,
    )
    chunks: queue.Queue[bytes | None] = queue.Queue(maxsize=32)
    stop_reader = threading.Event()

    def read_output() -> None:
        try:
            while not stop_reader.is_set():
                chunk = proc.stdout.read(4096)
                while not stop_reader.is_set():
                    try:
                        chunks.put(chunk if chunk else None, timeout=0.1)
                        break
                    except queue.Full:
                        continue
                if not chunk:
                    break
        except (OSError, ValueError):
            pass

    reader = threading.Thread(target=read_output, name="hash-audit-output", daemon=True)
    reader.start()
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    timed_out = interrupted = eof = False
    shutdown_at: float | None = None
    shutdown_stage = 0
    exited_at: float | None = None
    last_output = started
    heartbeat_interval = max(status_interval, 5)
    try:
        while True:
            try:
                now = time.monotonic()
                if max_seconds is not None and now - started >= max_seconds and shutdown_at is None and proc.poll() is None:
                    timed_out = True
                    shutdown_at = now
                    _signal_group(proc, signal.SIGINT)
                    print("\n[hash-audit] Time limit reached; stopping backend.", flush=True)
                if shutdown_at is not None:
                    if now - shutdown_at >= 4 and shutdown_stage < 2:
                        _signal_group(proc, getattr(signal, "SIGKILL", signal.SIGTERM))
                        shutdown_stage = 2
                    elif now - shutdown_at >= 2 and shutdown_stage < 1:
                        _signal_group(proc, signal.SIGTERM)
                        shutdown_stage = 1
                try:
                    chunk = chunks.get(timeout=0.1)
                    if chunk is None:
                        eof = True
                    else:
                        # Drain all buffered final output even through a slow
                        # terminal. Only an idle pipe can indicate orphaned
                        # descendants keeping the descriptor open.
                        exited_at = None
                        sys.stdout.write(safe_text(decoder.decode(chunk)))
                        sys.stdout.flush()
                        last_output = now
                except queue.Empty:
                    if proc.poll() is None and now - last_output >= heartbeat_interval:
                        print(f"\n[hash-audit] Backend running ({int(now - started)}s elapsed).", flush=True)
                        last_output = now
                if proc.poll() is not None:
                    if eof:
                        break
                    if exited_at is None:
                        exited_at = now
                    # Descendants must not keep our stdout pipe open forever.
                    if now - exited_at >= 1:
                        _signal_group(proc, getattr(signal, "SIGKILL", signal.SIGTERM))
                        break
            except KeyboardInterrupt:
                interrupted = True
                if shutdown_at is None:
                    shutdown_at = time.monotonic()
                    _signal_group(proc, signal.SIGINT)
                    print("\n[hash-audit] Interrupted; stopping backend.", flush=True)
                else:
                    _signal_group(proc, getattr(signal, "SIGKILL", signal.SIGTERM))
                    shutdown_stage = 2
        sys.stdout.write(safe_text(decoder.decode(b"", final=True)))
        sys.stdout.flush()
    finally:
        stop_reader.set()
        # Also clean descendants if a parent exited before them.
        _signal_group(proc, getattr(signal, "SIGKILL", signal.SIGTERM))
        proc.wait()
        reader.join(timeout=1)
        proc.stdout.close()
    return RunResult(proc.returncode, timed_out, interrupted, time.monotonic() - started)
