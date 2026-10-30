# Validation

Checked on October 29, 2026 with Python 3.14.4 on macOS.

- All 39 automated tests passed. These cover format validation, ambiguous inputs, shell metacharacters in paths, private output permissions, timeout and interruption cleanup, terminal escape handling, slow output consumers, and job integrity.
- Built and installed the Python package in an isolated temporary environment; verified the installed command.
- Compiled official John Jumbo source locally (1.9.0-jumbo-1+bleeding-5184bc0b8c1, CPU build). Real recovery with fresh pot files succeeded for MD5, SHA-1, SHA-256, SHA-512, NTLM, MySQL323, MySQL41, phpass, bcrypt, and Django PBKDF2-SHA256 using synthetic or published demonstration hashes and a small candidate list.
- Hashcat 7.1.2 accepted the generated commands but could not perform recovery because this environment exposed no usable Metal/OpenCL compute device. Hashcat result parsing with `--show` was verified for MD5 and salted SHA-256 using deliberately pre-seeded demonstration pot files. This is a parsing check, not evidence of Hashcat recovery.

Other registered formats have validation and mapping checks but were not all exercised in real recovery runs. Modern WordPress mode 35500 needs a compatible newer Hashcat. Native Windows behavior was not tested; use WSL as documented.

Reproduce automated tests from the project directory:

```sh
python3 -m unittest discover -s tests -v
```

The README includes a small recovery demo for either installed engine. Backend executables, downloaded sources, test result directories, and personal hashes are not bundled with this project.
