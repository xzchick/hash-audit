# Hash Audit v0.1.0 Release Notes (Draft / Pre-Release)

## Overview
Hash Audit is an offline, terminal-based hash auditing and password recovery CLI for owned or authorized hashes. It supports 23 hash formats across **Hashcat** and **John the Ripper Jumbo** on **macOS, Windows, and Linux**.

## Release Artifacts

Each GitHub Release provides two distribution formats:

1. **Standalone Native OS Bundles (No Python Required):**
   - `hash-audit-v0.1.0-macos-arm64.tar.gz` — macOS Apple Silicon (`arm64`) standalone binary + installer + examples
   - `hash-audit-v0.1.0-windows-x86_64.zip` — Windows 10/11 (`x86_64`) standalone `hash-audit.exe` + PowerShell installer + examples
   - `hash-audit-v0.1.0-linux-x86_64.tar.gz` — Linux (`x86_64`) standalone binary + installer + examples
2. **Universal Python Packages (For Existing Python 3.10+ / `pip` / `uv` Environments):**
   - `hash_audit-0.1.0-py3-none-any.whl` — Pure-Python wheel
   - `hash_audit-0.1.0.tar.gz` — Source distribution
3. **Checksums:**
   - `SHA256SUMS.txt` — SHA-256 digests for every archive and package above

> **External Recovery Engines:** Hash Audit orchestrates locally installed recovery engines (`hashcat` and/or John Jumbo `john`) on your `PATH`. Neither engine binaries nor wordlists/personal hashes are bundled.

## Verify Checksums Before Installing

### macOS and Linux
```sh
shasum -a 256 -c SHA256SUMS.txt
```

### Windows PowerShell
```powershell
Get-FileHash .\hash-audit-v0.1.0-windows-x86_64.zip -Algorithm SHA256
Get-Content .\SHA256SUMS.txt
```

## Quick Install

### macOS / Linux (Standalone Archive)
```sh
tar -xzf hash-audit-v0.1.0-<os>-<arch>.tar.gz
cd hash-audit-v0.1.0-<os>-<arch>
sh ./install.sh
~/.local/bin/hash-audit doctor
```

### Windows PowerShell (Standalone Archive)
```powershell
Expand-Archive .\hash-audit-v0.1.0-windows-x86_64.zip -DestinationPath .
cd .\hash-audit-v0.1.0-windows-x86_64
powershell -ExecutionPolicy Bypass -File .\install.ps1
```
