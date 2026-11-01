"""CLI orchestration; hashes and candidate words stay on the local machine."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import uuid

from . import __version__
from .backends import build_command, find_backend, run_command, safe_text, show_command
from .formats import FORMATS, HashFormat, candidates, normalize, validate

MAX_HASH_BYTES = 16 * 1024 * 1024
MAX_HASH_LINES = 100_000
MAX_LINE_BYTES = 4096


def positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if not 1 <= value <= 2_147_483_647:
        raise argparse.ArgumentTypeError("must be between 1 and 2147483647")
    return value


def clean_path(value: str | Path) -> Path:
    text = str(value)
    if any(not ch.isprintable() for ch in text):
        raise ValueError("file paths must not contain control characters")
    return Path(text).expanduser().absolute()


def regular_file(value: str | Path) -> Path:
    path = clean_path(value).resolve(strict=True)
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError(f"expected a regular file: {path}")
    return path


def bounded_read(value: str | Path, limit: int) -> bytes:
    path = regular_file(value)
    # O_NONBLOCK also prevents a changed path from hanging on a FIFO at open.
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("input changed to a non-regular file")
        if info.st_size > limit:
            raise ValueError(f"file exceeds {limit} bytes: {path}")
        data = source.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"file exceeds {limit} bytes: {path}")
    return data


def read_hashes(path: str | Path) -> list[tuple[int, str]]:
    data = bounded_read(path, MAX_HASH_BYTES)
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("hash files must be ASCII; use backend-native encoded salts") from exc
    rows = []
    for number, line in enumerate(text.split("\n"), 1):
        if line.endswith("\r"):
            line = line[:-1]
        if not line:
            continue
        if len(line) > MAX_LINE_BYTES:
            raise ValueError(f"line {number} exceeds {MAX_LINE_BYTES} bytes")
        if any(ord(ch) < 32 or ord(ch) > 126 for ch in line):
            raise ValueError(f"line {number} contains control characters")
        rows.append((number, line))
        if len(rows) > MAX_HASH_LINES:
            raise ValueError(f"hash file exceeds {MAX_HASH_LINES} nonempty lines")
    if not rows:
        raise ValueError("hash file is empty")
    return rows


def select_format(rows: list[tuple[int, str]], requested: str) -> HashFormat:
    if requested != "auto":
        fmt = FORMATS[requested]
        invalid = [str(number) for number, value in rows if not validate(value, fmt)]
        if invalid:
            raise ValueError(f"invalid {fmt.key} input at line(s) {', '.join(invalid[:8])}; "
                             "use one hash per line without usernames or comments")
        return fmt
    common = set(FORMATS)
    for number, value in rows:
        matches = candidates(value)
        if not matches:
            raise ValueError(f"unknown or malformed hash at line {number}")
        common.intersection_update(fmt.key for fmt in matches)
    if len(common) != 1:
        hint = ", ".join(sorted(common)) or "no common format (split mixed-format files)"
        raise ValueError(f"format is ambiguous: {hint}; select --format explicitly")
    # Length is never proof of an algorithm, even for a single registry match.
    if not all(value.startswith(("$", "*")) for _, value in rows):
        raise ValueError("bare and digest:salt hashes require --format; length alone cannot identify an algorithm")
    return FORMATS[common.pop()]


def _is_reparse_or_symlink(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junc = getattr(path, "is_junction", None)
    if callable(is_junc) and is_junc():
        return True
    try:
        st = os.lstat(path)
    except OSError:
        return False
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(st, "st_file_attributes", 0) & reparse)


def windows_user_sid() -> str:
    if os.name != "nt":
        raise PermissionError("Windows SID queries require Windows")
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    TOKEN_QUERY = 0x0008
    TokenUser = 1

    class SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Sid", wintypes.LPVOID), ("Attributes", wintypes.DWORD)]

    class TOKEN_USER(ctypes.Structure):
        _fields_ = [("User", SID_AND_ATTRIBUTES)]

    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)):
        raise PermissionError(f"OpenProcessToken failed: {ctypes.get_last_error()}")
    try:
        needed = wintypes.DWORD(0)
        advapi32.GetTokenInformation(token, TokenUser, None, 0, ctypes.byref(needed))
        if not needed.value:
            raise PermissionError("GetTokenInformation failed to return buffer size")
        buf = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(token, TokenUser, buf, needed, ctypes.byref(needed)):
            raise PermissionError(f"GetTokenInformation failed: {ctypes.get_last_error()}")
        user = ctypes.cast(buf, ctypes.POINTER(TOKEN_USER)).contents
        sid_str = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(user.User.Sid, ctypes.byref(sid_str)):
            raise PermissionError(f"ConvertSidToStringSidW failed: {ctypes.get_last_error()}")
        try:
            value = sid_str.value
        finally:
            kernel32.LocalFree(sid_str)
        if not value or not value.startswith("S-1-"):
            raise PermissionError("Invalid Windows user SID")
        return value
    finally:
        kernel32.CloseHandle(token)


def windows_sddl(path: str | Path) -> str:
    if os.name != "nt":
        raise PermissionError("Windows SDDL queries require Windows")
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    SE_FILE_OBJECT = 1
    OWNER_SECURITY_INFORMATION = 0x00000001
    DACL_SECURITY_INFORMATION = 0x00000004
    SDDL_REVISION_1 = 1

    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
    ]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(wintypes.ULONG),
    ]
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL

    sd = wintypes.LPVOID()
    err = advapi32.GetNamedSecurityInfoW(
        str(path), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        None, None, None, None, ctypes.byref(sd),
    )
    if err != 0:
        raise PermissionError(f"GetNamedSecurityInfoW failed with error {err}")
    try:
        sddl_ptr = wintypes.LPWSTR()
        if not advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd, SDDL_REVISION_1, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            ctypes.byref(sddl_ptr), None,
        ):
            raise PermissionError(f"ConvertSecurityDescriptorToStringSecurityDescriptorW failed: {ctypes.get_last_error()}")
        try:
            return sddl_ptr.value or ""
        finally:
            kernel32.LocalFree(sddl_ptr)
    finally:
        kernel32.LocalFree(sd)


def resolve_windows_sid(trustee: str) -> str:
    trustee = trustee.strip().upper()
    if trustee.startswith("S-1-") or os.name != "nt":
        return trustee
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.ConvertStringSidToSidW.argtypes = [wintypes.LPWSTR, ctypes.POINTER(wintypes.LPVOID)]
    advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL

    sid = wintypes.LPVOID()
    if not advapi32.ConvertStringSidToSidW(trustee, ctypes.byref(sid)):
        return trustee
    try:
        sid_str = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(sid_str)):
            return trustee
        try:
            return (sid_str.value or trustee).upper()
        finally:
            kernel32.LocalFree(sid_str)
    finally:
        kernel32.LocalFree(sid)


def verify_windows_sddl(sddl: str, expected_sid: str, is_dir: bool = False) -> bool:
    import re
    if "D:P" not in sddl:
        raise PermissionError(f"Windows DACL is not protected against inheritance: {sddl}")
    dacl_idx = sddl.index("D:P")
    owner_part = sddl[:dacl_idx]
    dacl_part = sddl[dacl_idx:]
    allowed = {expected_sid.upper(), "SY", "BA", "S-1-5-18", "S-1-5-32-544"}
    owner_match = re.search(r"O:([^D(]+)", owner_part)
    if not owner_match:
        raise PermissionError(f"Windows security descriptor missing owner: {sddl}")
    owner_trustee = owner_match.group(1).strip().upper()
    if owner_trustee not in allowed and resolve_windows_sid(owner_trustee) not in allowed:
        raise PermissionError(f"Unexpected Windows owner in security descriptor: {owner_trustee}")
    aces = re.findall(r"\(([^)]+)\)", dacl_part)
    if not aces:
        raise PermissionError(f"Windows DACL has no ACEs: {sddl}")
    user_granted = False
    expected_upper = expected_sid.upper()
    for ace in aces:
        fields = ace.split(";")
        if len(fields) != 6:
            raise PermissionError(f"Malformed ACE in Windows DACL: {ace}")
        ace_type, ace_flags, rights, obj_guid, inherit_guid, trustee = [f.strip().upper() for f in fields]
        resolved = trustee if trustee in allowed else resolve_windows_sid(trustee)
        if ace_type != "A" or obj_guid or inherit_guid or resolved not in allowed:
            raise PermissionError(f"Disallowed ACE in Windows DACL: {ace}")
        if resolved == expected_upper or (
            expected_upper.startswith("S-1-5-21-") and expected_upper.endswith("-500") and trustee == "LA"
        ):
            if rights != "FA":
                raise PermissionError(f"Insufficient rights for user in Windows DACL: {ace}")
            if is_dir and ("OI" not in ace_flags or "CI" not in ace_flags):
                raise PermissionError(f"Directory ACE missing OICI inheritance flags: {ace}")
            user_granted = True
    if not user_granted:
        raise PermissionError(f"Current user SID {expected_sid} missing from Windows DACL: {sddl}")
    return True


def _enforce_windows_acl(path: Path, is_dir: bool = False) -> None:
    if _is_reparse_or_symlink(path):
        raise PermissionError(f"Refusing to set permissions on symlink or reparse point: {path}")
    sid = windows_user_sid()
    inherit = "OICI;" if is_dir else ";"
    sddl = f"D:P(A;{inherit}FA;;;{sid})(A;{inherit}FA;;;SY)(A;{inherit}FA;;;BA)"
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    SDDL_REVISION_1 = 1
    SE_FILE_OBJECT = 1
    DACL_SECURITY_INFORMATION = 0x00000004
    PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000

    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.ULONG),
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorDacl.argtypes = [
        wintypes.LPVOID, ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi32.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
        wintypes.LPVOID, wintypes.LPVOID, wintypes.LPVOID, wintypes.LPVOID,
    ]
    advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL

    sd = wintypes.LPVOID()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, ctypes.byref(sd), None):
        raise PermissionError(f"ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {ctypes.get_last_error()}")
    try:
        present = wintypes.BOOL()
        dacl = wintypes.LPVOID()
        defaulted = wintypes.BOOL()
        if not advapi32.GetSecurityDescriptorDacl(sd, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)) or not present.value:
            raise PermissionError(f"GetSecurityDescriptorDacl failed: {ctypes.get_last_error()}")
        err = advapi32.SetNamedSecurityInfoW(
            str(path), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None, None, dacl, None,
        )
        if err != 0:
            raise PermissionError(f"SetNamedSecurityInfoW failed with error {err}")
    finally:
        kernel32.LocalFree(sd)
    if _is_reparse_or_symlink(path):
        raise PermissionError(f"Path became a symlink or reparse point during ACL enforcement: {path}")
    verify_windows_sddl(windows_sddl(path), sid, is_dir=is_dir)


def private_dir(path: Path) -> Path:
    if _is_reparse_or_symlink(path):
        raise ValueError(f"refusing symbolic link or reparse point: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if _is_reparse_or_symlink(path) or not path.is_dir():
        raise ValueError(f"expected a private directory: {path}")
    if os.name == "nt":
        _enforce_windows_acl(path, is_dir=True)
    else:
        os.chmod(path, 0o700)
        if stat.S_IMODE(path.lstat().st_mode) != 0o700:
            raise PermissionError(f"Could not enforce 0700 permissions on {path}")
    return path


def private_file(path: Path) -> Path:
    if _is_reparse_or_symlink(path) or not path.is_file():
        raise ValueError(f"expected a regular private file: {path}")
    if os.name == "nt":
        _enforce_windows_acl(path, is_dir=False)
    else:
        os.chmod(path, 0o600)
        if stat.S_IMODE(path.lstat().st_mode) != 0o600:
            raise PermissionError(f"Could not enforce 0600 permissions on {path}")
    return path


def private_write(path: Path, data: bytes) -> None:
    if _is_reparse_or_symlink(path):
        raise ValueError(f"refusing symbolic link or reparse point: {path}")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        private_file(path)
    except Exception:
        os.close(descriptor)
        path.unlink(missing_ok=True)
        raise
    with os.fdopen(descriptor, "wb") as target:
        target.write(data)


def write_manifest(job: Path, value: dict, replace: bool = False) -> None:
    data = (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode()
    if replace:
        temp = job / (".run-" + uuid.uuid4().hex + ".json")
        private_write(temp, data)
        os.replace(temp, job / "run.json")
    else:
        private_write(job / "run.json", data)


def proposed_job(output: str | None) -> Path:
    if output:
        path = clean_path(output)
    else:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = Path.cwd() / "hash-audit-runs" / f"run-{stamp}-{uuid.uuid4().hex[:8]}"
    if path.exists() or path.is_symlink():
        raise ValueError(f"output directory already exists; choose a new path: {path}")
    return path


def validate_mask(mask: str) -> None:
    if not mask or len(mask) > 256 or any(ord(ch) < 32 or ord(ch) > 126 for ch in mask):
        raise ValueError("mask must contain 1–256 printable ASCII characters")
    if mask.startswith("-") or "/" in mask or "\\" in mask:
        raise ValueError("mask must be an inline pattern, without leading '-' or path separators")
    index = 0
    has_charset = False
    while index < len(mask):
        if mask[index] == "?":
            index += 1
            if index >= len(mask) or mask[index] not in "ludsahHb?":
                raise ValueError("supported mask tokens: ?l ?u ?d ?s ?a ?h ?H ?b and ??")
            has_charset = has_charset or mask[index] != "?"
        index += 1
    if not has_charset:
        raise ValueError("mask must include a character-set token such as ?d; use a wordlist for literal passwords")
    # Hashcat treats an existing file in this position as a mask file.
    if Path(mask).exists():
        raise ValueError("mask matches a local filename; use an unambiguous inline pattern")


def recover(args: argparse.Namespace) -> int:
    source = regular_file(args.hash_file)
    rows = read_hashes(source)
    fmt = select_format(rows, args.format)
    wordlist = regular_file(args.wordlist) if args.wordlist else None
    rules = regular_file(args.rules) if args.rules else None
    if wordlist is not None and wordlist.stat().st_size == 0:
        raise ValueError("wordlist is empty")
    if args.mask is not None:
        validate_mask(args.mask)
    if rules is not None and (args.backend != "hashcat" or wordlist is None):
        raise ValueError("--rules requires Hashcat with --wordlist")
    if args.backend == "john" and args.mask is not None:
        raise ValueError("John supports --wordlist in this CLI; use Hashcat for --mask")
    normalized = list(dict.fromkeys(normalize(value, fmt, args.backend) for _, value in rows))
    job = proposed_job(args.output_dir)
    executable = (shutil.which(args.backend) or args.backend) if args.dry_run else find_backend(args.backend)
    argv = build_command(args.backend, executable, fmt, job / "hashes.txt", wordlist,
                         args.mask, job, args.status_interval, rules)
    if args.dry_run:
        print(json.dumps({"dry_run": True, "backend": args.backend, "format": fmt.key,
                          "input_lines": len(rows), "unique_hashes": len(normalized),
                          "output_directory": str(job), "argv": argv,
                          "max_seconds": args.max_seconds}, indent=2, ensure_ascii=True))
        return 0
    if not args.output_dir:
        private_dir(job.parent)
    elif not job.parent.is_dir():
        raise ValueError("the output directory's parent must already exist")
    job.mkdir(mode=0o700)
    private_dir(job)
    # Keep all persistent input/result files private, independently of user umask.
    snapshot = ("\n".join(normalized) + "\n").encode("ascii")
    private_write(job / "hashes.txt", snapshot)
    private_write(job / "recovered.pot", b"")
    if args.backend == "hashcat":
        private_write(job / "recovered.txt", b"")
    manifest = {"schema_version": 1, "version": __version__, "backend": args.backend,
                "format": fmt.key, "source": str(source), "input_lines": len(rows),
                "unique_hashes": len(normalized), "snapshot_sha256": hashlib.sha256(snapshot).hexdigest(),
                "started_utc": datetime.now(timezone.utc).isoformat(), "state": "running",
                "argv": argv, "max_seconds": args.max_seconds, "status_interval": args.status_interval}
    write_manifest(job, manifest)
    print(safe_text(f"{fmt.label}: {len(normalized)} unique hash(es). Results: {job}"), flush=True)
    print("Starting local recovery. Press Ctrl-C to stop.", flush=True)
    try:
        result = run_command(argv, job, args.status_interval, args.max_seconds)
    except (OSError, ValueError):
        manifest.update(state="failed", ended_utc=datetime.now(timezone.utc).isoformat())
        write_manifest(job, manifest, replace=True)
        raise
    if result.interrupted:
        state, code = "interrupted", 130
    elif result.timed_out:
        state, code = "timed_out", 124
    elif args.backend == "hashcat" and result.returncode == 1:
        state, code = "exhausted", 3
    elif result.returncode == 0:
        state, code = "completed", 0
    else:
        state, code = "failed", 2
    manifest.update(state=state, result=asdict(result), ended_utc=datetime.now(timezone.utc).isoformat())
    write_manifest(job, manifest, replace=True)
    print(safe_text(f"Run {state}. Results: {job}"))
    print("Use 'hash-audit show JOB_DIR' to display any recovered passwords.")
    if state == "completed":
        print("A completed run does not guarantee every password was recovered.")
    return code


def detect(args: argparse.Namespace) -> int:
    rows = read_hashes(args.hash_file)
    results = [{"line": number, "candidates": [fmt.key for fmt in candidates(value)],
                "explicit_format_required": not value.startswith(("$", "*"))}
               for number, value in rows]
    if args.json:
        print(json.dumps({"note": "Candidates are structural hints, not proof of the original algorithm.",
                          "lines": results}, indent=2))
    else:
        for item in results:
            choices = ", ".join(item["candidates"]) or "unknown / malformed"
            suffix = " (select --format)" if item["explicit_format_required"] else ""
            print(f"Line {item['line']}: {choices}{suffix}")
        print("Candidates are structural hints. Confirm the format from the source system.")
    return 0 if all(item["candidates"] for item in results) else 2


def doctor(_args: argparse.Namespace) -> int:
    found = 0
    for name in ("hashcat", "john"):
        path = shutil.which(name)
        if path is None:
            print(f"{name}: not found on PATH")
            continue
        found += 1
        print(safe_text(f"{name}: {path}"))
        probe = "--version" if name == "hashcat" else "--list=build-info"
        try:
            result = subprocess.run([path, probe], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=10, check=False)
            for line in result.stdout.decode("utf-8", errors="replace").splitlines()[:8]:
                print("  " + safe_text(line))
            if result.returncode:
                print("  Probe failed; verify installation and use John Jumbo for John support.")
        except (OSError, subprocess.TimeoutExpired) as exc:
            print("  Probe failed: " + safe_text(str(exc)))
    print("Hashcat also needs a working compute device/driver; inspect it with 'hashcat -I'.")
    print("John needs a Jumbo build. Check compiled formats with 'john --list=formats'.")
    return 0 if found else 2


def show(args: argparse.Namespace) -> int:
    job = clean_path(args.job_dir).resolve(strict=True)
    if not job.is_dir():
        raise ValueError("job path must be a directory")
    for name in ("run.json", "hashes.txt", "recovered.pot"):
        if _is_reparse_or_symlink(job / name):
            raise ValueError(f"job file must not be a symbolic link: {name}")
    manifest = json.loads(bounded_read(job / "run.json", 1024 * 1024))
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise ValueError("unsupported job manifest")
    backend = manifest.get("backend")
    key = manifest.get("format")
    if backend not in ("hashcat", "john") or not isinstance(key, str) or key not in FORMATS:
        raise ValueError("invalid backend or format in job manifest")
    snapshot = bounded_read(job / "hashes.txt", MAX_HASH_BYTES)
    if hashlib.sha256(snapshot).hexdigest() != manifest.get("snapshot_sha256"):
        raise ValueError("hash snapshot changed since this job was created")
    regular_file(job / "recovered.pot")
    argv = show_command(backend, find_backend(backend), FORMATS[key], job / "hashes.txt", job)
    result = run_command(argv, job, 5, 30)
    if result.timed_out:
        return 124
    if result.interrupted:
        return 130
    return 0 if result.returncode == 0 else 2


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="hash-audit", description=(
        "Local hash auditing and password recovery for owned or authorized hashes. "
        "Hashes are one-way; recovery is never guaranteed."))
    root.add_argument("--version", action="version", version=__version__)
    commands = root.add_subparsers(dest="command", required=True)
    formats = commands.add_parser("formats", help="list supported formats and engine mappings")
    formats.add_argument("--json", action="store_true")
    detection = commands.add_parser("detect", help="show candidate formats without exposing hashes")
    detection.add_argument("hash_file")
    detection.add_argument("--json", action="store_true")
    commands.add_parser("doctor", help="find installed engines and print diagnostic hints")
    recovery = commands.add_parser("recover", help="run a local wordlist or mask recovery")
    recovery.add_argument("hash_file")
    recovery.add_argument("--format", choices=["auto", *FORMATS], default="auto")
    recovery.add_argument("--backend", choices=("hashcat", "john"), default="hashcat")
    attack = recovery.add_mutually_exclusive_group(required=True)
    attack.add_argument("--wordlist")
    attack.add_argument("--mask", help="quoted inline Hashcat mask, e.g. '?d?d?d?d'")
    recovery.add_argument("--rules", help="Hashcat rules file; requires --wordlist")
    recovery.add_argument("--output-dir", help="new private job directory; parent must exist")
    recovery.add_argument("--status-interval", type=positive_int, default=5)
    recovery.add_argument("--max-seconds", type=positive_int, help="wall-clock budget including engine startup")
    recovery.add_argument("--dry-run", action="store_true", help="print JSON argument list without creating files or running engine")
    showing = commands.add_parser("show", help="display recovered secrets from a previous job")
    showing.add_argument("job_dir")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "formats":
            if args.json:
                print(json.dumps([asdict(fmt) for fmt in FORMATS.values()], indent=2))
            else:
                print(f"{'FORMAT':<25} {'HASHCAT':<9} {'JOHN':<20} DESCRIPTION")
                for fmt in FORMATS.values():
                    print(f"{fmt.key:<25} {fmt.hashcat_mode:<9} {fmt.john_format or '—':<20} {fmt.label}")
            return 0
        return {"detect": detect, "doctor": doctor, "recover": recover, "show": show}[args.command](args)
    except (OSError, ValueError) as exc:
        print("Error: " + safe_text(str(exc)), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
