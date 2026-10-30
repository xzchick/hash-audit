# Project summary

Hash Audit is a terminal-only Python CLI for local, authorized password recovery. It validates hash files, provides conservative format detection, and invokes Hashcat or John Jumbo without a shell.

## Features

- 23 registered formats, including MD5, SHA-1/256/512, NTLM, legacy MySQL, phpass, bcrypt, crypt, and salted digests.
- Dictionary recovery, Hashcat masks and rule files.
- Live progress, dry-run previews, time limits, and interruption handling.
- Isolated result directories, private permissions on POSIX, and safe terminal output.
- No Python runtime dependencies; recovery engines are installed separately.

## Validation

39 automated tests passed. Real John recovery was verified across 10 formats. Hashcat compute recovery was not verified in the build environment because no usable compute device was exposed. See VALIDATION.md for details.

## Limits

Hashes are one-way. Matching candidates can recover passwords, but success is never guaranteed. Use only with hashes you own or are authorized to audit. This project does not collect credentials or target online accounts.
