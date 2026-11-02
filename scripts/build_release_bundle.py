"""Build standalone native OS release bundles, Python wheel/sdist, and SHA256SUMS.txt."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import zipfile

from hash_audit import __version__

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
BUILD = ROOT / "build"

FORBIDDEN_SUFFIXES = (".pot", ".restore", ".log", ".gguf", ".db", ".sqlite3")


def platform_tag() -> tuple[str, str]:
    if sys.platform == "darwin":
        os_name = "macos"
    elif os.name == "nt":
        os_name = "windows"
    elif sys.platform.startswith("linux"):
        os_name = "linux"
    else:
        os_name = sys.platform
    machine = platform.machine().lower()
    if machine in ("amd64", "x86_64", "x64"):
        arch = "x86_64"
    elif machine in ("arm64", "aarch64"):
        arch = "arm64"
    else:
        arch = machine or "unknown"
    return os_name, arch


def verify_repo_hygiene() -> None:
    tracked = subprocess.check_output(["git", "ls-files"], cwd=ROOT, text=True).splitlines()
    bad = [
        p for p in tracked
        if p.endswith(FORBIDDEN_SUFFIXES)
        or p.startswith("hash-audit-runs/")
        or Path(p).name in (".env", "run.json", "recovered.txt")
    ]
    if bad:
        raise RuntimeError(f"Refusing to build release with forbidden tracked files: {bad}")


def write_install_scripts(bundle_dir: Path, is_windows: bool) -> None:
    if is_windows:
        ps1 = bundle_dir / "install.ps1"
        ps1.write_text(
            "param(\n"
            "    [string]$Prefix = (Join-Path $env:LOCALAPPDATA 'Programs\\hash-audit')\n"
            ")\n"
            "$ErrorActionPreference = 'Stop'\n"
            "$BinDir = Join-Path $Prefix 'bin'\n"
            "New-Item -ItemType Directory -Force -Path $BinDir | Out-Null\n"
            "Copy-Item -Force (Join-Path $PSScriptRoot 'hash-audit.exe') (Join-Path $BinDir 'hash-audit.exe')\n"
            "Write-Host \"Installed hash-audit.exe to: $(Join-Path $BinDir 'hash-audit.exe')\"\n"
            "Write-Host \"Add $BinDir to your user PATH if not already present.\"\n",
            encoding="utf-8",
        )
    else:
        sh = bundle_dir / "install.sh"
        sh.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            "script_dir=$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\n"
            "prefix=${PREFIX:-$HOME/.local}\n"
            "bindir=\"$prefix/bin\"\n"
            "mkdir -p \"$bindir\"\n"
            "cp \"$script_dir/hash-audit\" \"$bindir/hash-audit\"\n"
            "chmod 755 \"$bindir/hash-audit\"\n"
            "echo \"Installed hash-audit to: $bindir/hash-audit\"\n",
            encoding="utf-8",
        )
        sh.chmod(0o755)


def main() -> int:
    verify_repo_hygiene()
    if DIST.exists():
        shutil.rmtree(DIST)
    DIST.mkdir(parents=True, exist_ok=True)

    # 1. Build standard Python wheel and sdist (preserved for pip/uv users)
    subprocess.run([sys.executable, "-m", "build", "--outdir", str(DIST)], cwd=ROOT, check=True)

    # 2. Build standalone single-file native executable via PyInstaller
    pyi_dist = BUILD / "pyi-dist"
    pyi_work = BUILD / "pyi-work"
    pyi_spec = BUILD / "pyi-spec"
    for d in (pyi_dist, pyi_work, pyi_spec):
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True, exist_ok=True)

    subprocess.run(
        [
            sys.executable, "-m", "PyInstaller",
            "--noconfirm", "--clean", "--onefile",
            "--name", "hash-audit",
            "--paths", str(ROOT),
            "--distpath", str(pyi_dist),
            "--workpath", str(pyi_work),
            "--specpath", str(pyi_spec),
            str(ROOT / "hash_audit" / "__main__.py"),
        ],
        cwd=ROOT,
        check=True,
    )

    os_name, arch = platform_tag()
    is_win = os.name == "nt"
    exe_name = "hash-audit.exe" if is_win else "hash-audit"
    built_exe = pyi_dist / exe_name
    if not built_exe.is_file():
        raise FileNotFoundError(f"Expected standalone binary not found: {built_exe}")

    bundle_name = f"hash-audit-v{__version__}-{os_name}-{arch}"
    staging_root = BUILD / "release-staging"
    if staging_root.exists():
        shutil.rmtree(staging_root)
    bundle_dir = staging_root / bundle_name
    bundle_dir.mkdir(parents=True, exist_ok=True)

    target_exe = bundle_dir / exe_name
    shutil.copy2(built_exe, target_exe)
    if not is_win:
        target_exe.chmod(0o755)

    write_install_scripts(bundle_dir, is_win)
    shutil.copytree(ROOT / "examples", bundle_dir / "examples")
    for doc in ("README.md", "VALIDATION.md", "RELEASE_NOTES.md", "LICENSE"):
        src = ROOT / doc
        if src.is_file():
            shutil.copy2(src, bundle_dir / doc)

    # Verify no forbidden files slipped into bundle_dir
    for item in bundle_dir.rglob("*"):
        if item.is_file() and item.suffix in FORBIDDEN_SUFFIXES:
            raise RuntimeError(f"Forbidden file in release bundle: {item}")

    if is_win:
        archive_path = DIST / f"{bundle_name}.zip"
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for item in sorted(bundle_dir.rglob("*")):
                if item.is_file():
                    zf.write(item, item.relative_to(staging_root))
    else:
        archive_path = DIST / f"{bundle_name}.tar.gz"
        with tarfile.open(archive_path, "w:gz") as tf:
            tf.add(bundle_dir, arcname=bundle_name)

    # 3. Generate LF-normalized SHA256SUMS.txt covering all release artifacts
    lines = []
    for artifact in sorted(DIST.iterdir()):
        if artifact.is_file() and artifact.name != "SHA256SUMS.txt":
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            lines.append(f"{digest}  {artifact.name}")
    sums_path = DIST / "SHA256SUMS.txt"
    sums_path.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    print(sums_path.read_text(encoding="utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
