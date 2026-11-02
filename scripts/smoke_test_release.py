"""Clean-machine installation and execution smoke test for Hash Audit release artifacts."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile

from hash_audit import __version__, cli

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
FORBIDDEN_SUFFIXES = (".pot", ".restore", ".log", ".gguf", ".db", ".sqlite3")


def verify_checksums(work_dir: Path) -> list[str]:
    sums_file = work_dir / "SHA256SUMS.txt"
    raw = sums_file.read_bytes()
    if b"\r\n" in raw:
        raise AssertionError("SHA256SUMS.txt must use LF line endings")
    verified = []
    for line in raw.decode("utf-8").splitlines():
        if not line.strip():
            continue
        expected_hash, name = line.split("  ", 1)
        target = work_dir / name
        if not target.is_file():
            raise FileNotFoundError(f"Artifact listed in SHA256SUMS.txt is missing: {name}")
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual != expected_hash:
            raise AssertionError(f"SHA-256 mismatch for {name}: {actual} != {expected_hash}")
        verified.append(name)
    if not verified:
        raise AssertionError("No artifacts found in SHA256SUMS.txt")
    return verified


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="hash-audit-clean-machine-") as tmp:
        clean_root = Path(tmp).resolve()
        staging = clean_root / "downloads"
        staging.mkdir(parents=True, exist_ok=True)
        for item in DIST.iterdir():
            if item.is_file():
                shutil.copy2(item, staging / item.name)

        verified = verify_checksums(staging)
        print(f"Verified SHA256SUMS.txt for: {', '.join(verified)}")

        is_win = os.name == "nt"
        archives = list(staging.glob("hash-audit-v*.zip" if is_win else "hash-audit-v*.tar.gz"))
        if len(archives) != 1:
            raise AssertionError(f"Expected exactly 1 native OS archive in {staging}, found: {archives}")
        archive = archives[0]

        extract_dir = clean_root / "extracted"
        extract_dir.mkdir()
        if is_win:
            with zipfile.ZipFile(archive, "r") as zf:
                zf.extractall(extract_dir)
        else:
            with tarfile.open(archive, "r:gz") as tf:
                tf.extractall(extract_dir, filter="data")

        bundles = [p for p in extract_dir.iterdir() if p.is_dir()]
        if len(bundles) != 1:
            raise AssertionError(f"Expected single top-level bundle directory, found: {bundles}")
        bundle = bundles[0]

        for f in bundle.rglob("*"):
            if f.is_file() and f.suffix in FORBIDDEN_SUFFIXES:
                raise AssertionError(f"Forbidden file found inside extracted archive: {f}")

        # Install into clean prefix using the bundled installer script
        install_prefix = clean_root / "installed-prefix"
        if is_win:
            subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(bundle / "install.ps1"), "-Prefix", str(install_prefix)],
                cwd=bundle,
                check=True,
            )
            installed_exe = install_prefix / "bin" / "hash-audit.exe"
        else:
            env = dict(os.environ, PREFIX=str(install_prefix))
            subprocess.run(["sh", str(bundle / "install.sh")], cwd=bundle, env=env, check=True)
            installed_exe = install_prefix / "bin" / "hash-audit"

        if not installed_exe.is_file():
            raise AssertionError(f"Installer did not create executable at {installed_exe}")

        # Run standalone binary from clean temporary working directory (outside repo)
        run_cwd = clean_root / "work"
        run_cwd.mkdir()
        ver_out = subprocess.check_output([str(installed_exe), "--version"], cwd=run_cwd, text=True).strip()
        if ver_out != __version__:
            raise AssertionError(f"Unexpected version output: {ver_out} != {__version__}")

        fmt_out = subprocess.check_output([str(installed_exe), "formats", "--json"], cwd=run_cwd, text=True)
        if len(json.loads(fmt_out)) != 23:
            raise AssertionError("Standalone binary did not report 23 supported hash formats")

        det_out = subprocess.check_output(
            [str(installed_exe), "detect", str(bundle / "examples" / "md5.txt"), "--json"],
            cwd=run_cwd,
            text=True,
        )
        if "md5" not in json.loads(det_out)["lines"][0]["candidates"]:
            raise AssertionError("Standalone binary failed detect smoke check")

        dry_out = subprocess.check_output(
            [
                str(installed_exe), "recover", str(bundle / "examples" / "md5.txt"),
                "--format", "md5", "--backend", "hashcat",
                "--wordlist", str(bundle / "examples" / "words.txt"),
                "--output-dir", str(run_cwd / "dry-job"), "--dry-run",
            ],
            cwd=run_cwd,
            text=True,
        )
        if not json.loads(dry_out)["dry_run"]:
            raise AssertionError("Standalone binary failed recover --dry-run smoke check")
        if (run_cwd / "dry-job").exists():
            raise AssertionError("--dry-run must not create output directory")

        print("Clean-machine standalone bundle installation and smoke tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
