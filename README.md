# Hash Audit

![Hash Audit — Local. Terminal. Authorized.](assets/cover.png)

**23 hash formats · Hashcat + John Jumbo · Python · MIT license**

A fully terminal-based, local password recovery and hash auditing CLI for hashes you own or are authorized to test. It validates hash files, identifies plausible formats, and runs an installed Hashcat or John the Ripper Jumbo with explicit settings, progress output, and a separate results directory for each run.

**Hashes are one-way.** Recovery works by hashing candidate passwords and looking for a match. A successful match does not establish that the candidate is the only possible original input. Strong passwords, slow password hashing, and large search spaces can make recovery impractical. There is no unlimited decryption mode or recovery guarantee.

This project performs offline recovery from local files. It has no online lookup service, account login testing, credential collection, or automatic wordlist downloads.

## Install

Python 3.10 or newer is required. The CLI has no third-party Python runtime dependencies. Install at least one recovery engine separately.

On macOS with Homebrew:

```sh
brew install python hashcat john-jumbo
```

These are the official Homebrew formulas for [Hashcat](https://formulae.brew.sh/formula/hashcat) and [John Jumbo](https://formulae.brew.sh/formula/john-jumbo). Installing both is optional.

On Ubuntu or Debian, install Python and Hashcat using your package manager:

```sh
sudo apt update
sudo apt install python3 python3-venv hashcat
```

Hashcat documents this [package installation route](https://hashcat.net/wiki/doku.php?id=frequently_asked_questions#how_do_i_install_hashcat), but distribution packages can lag upstream. For John, install **Jumbo**, which supports more formats and options than core John; a package named `john` does not necessarily provide Jumbo. Follow the [Openwall downloads and build instructions](https://www.openwall.com/john/) when your distribution does not provide a suitable build. Openwall recommends its current development snapshot over the older 1.9.0-jumbo-1 source release.

On Windows (PowerShell), install Python 3.10+ and place `hashcat.exe` and/or John Jumbo (`john.exe`) on your `PATH`, or use WSL:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
hash-audit doctor
hash-audit --help
```

From this project's directory on macOS or Linux:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
hash-audit doctor
hash-audit --help
```

You can also run `python3 -m hash_audit` directly from the project directory without installing the package. Substitute it for `hash-audit` in the examples below.

Hashcat requires a compatible compute runtime. Use `hashcat -I` to inspect available devices; a listed device is not a guarantee that a recovery run will work. Follow the [Hashcat driver guidance](https://hashcat.net/wiki/doku.php?id=frequently_asked_questions#how_does_one_install_the_correct_driver_for_the_gpu_s). John Jumbo offers CPU implementations for the supported formats. The CLI does not install drivers, enable `--force`, or disable engine safety checks.

## Try the included local demo

The example files are synthetic. `examples/md5.txt`, `examples/sha256.txt`, and `examples/sha256-salted.txt` all use the known password `AuditDemo42!`. `examples/words.txt` includes that password.

```sh
hash-audit formats
hash-audit detect examples/md5.txt
hash-audit recover examples/md5.txt --format md5 --backend hashcat \
  --wordlist examples/words.txt --output-dir demo-md5 --dry-run
hash-audit recover examples/md5.txt --format md5 --backend hashcat \
  --wordlist examples/words.txt --output-dir demo-md5 --max-seconds 300
hash-audit show demo-md5
```

The first real run can spend time compiling engine kernels. Detection should list MD5 and NTLM as possibilities for this 32-character hexadecimal digest. `--format md5` supplies the known format rather than treating its appearance as proof.

To use John Jumbo instead:

```sh
hash-audit recover examples/sha256.txt --format sha256 --backend john \
  --wordlist examples/words.txt --output-dir demo-john --max-seconds 300
hash-audit show demo-john
```

For a salted SHA-256 example, the construction is SHA-256 of the password bytes followed by the literal salt bytes `demo-salt`:

```sh
hash-audit recover examples/sha256-salted.txt --format sha256-pass-salt \
  --backend hashcat --wordlist examples/words.txt \
  --output-dir demo-salted --max-seconds 300
```

The included `examples/pin-md5.txt` hashes the toy PIN `0427`. A four-digit Hashcat mask covers 10,000 candidates:

```sh
hash-audit recover examples/pin-md5.txt --format md5 --backend hashcat \
  --mask '?d?d?d?d' --output-dir demo-pin --max-seconds 300
```

Keep the mask in quotes so your shell does not interpret its question marks. Choose a fresh output directory for every real run.

Masks must contain a character-set token such as `?d`, and are limited to 256 printable ASCII characters. Supported tokens are `?l`, `?u`, `?d`, `?s`, `?a`, `?h`, `?H`, `?b`, and `??` for a literal question mark. Use a wordlist for a single literal password.

## Input and format selection

Pass a local ASCII text file containing one hash per line. LF and CRLF line endings are accepted, and empty lines are ignored. Keep a single format in each file. Do not include usernames, email addresses, shadow-file records, or CSV columns. Separate those fields before using this CLI. An email address is possible password input, not a distinct hash algorithm. Hash files are limited to 16 MiB, 100,000 nonempty lines, and 4,096 bytes per line.

```sh
hash-audit detect my-hashes.txt
hash-audit detect my-hashes.txt --json
hash-audit formats --json
```

Detection reports **candidates**, not certainty. Bare hexadecimal digests can represent many algorithms; use an explicit `--format` even when the registry offers only one candidate. For a recognized, unambiguous format beginning with `$` or `*`, `--format auto` can select its registered format. Django inputs require `--format django-pbkdf2-sha256`. Every record is validated before an engine starts; mixed, malformed, unknown, or ambiguous inputs are rejected.

The registry includes:

| Format family | CLI format keys | Engine availability |
| --- | --- | --- |
| Raw digests | `md5`, `sha1`, `sha256`, `sha512`, `ntlm` | Hashcat and John Jumbo |
| Legacy MySQL | `mysql323`, `mysql41` | Hashcat and John Jumbo |
| Portable phpass / older WordPress | `phpass` | Hashcat and John Jumbo |
| Modern WordPress bcrypt wrapper | `wordpress-bcrypt` | Hashcat; requires mode `35500` |
| bcrypt | `bcrypt` | Hashcat and John Jumbo |
| Unix and Apache crypt | `md5crypt`, `apr1`, `sha256crypt`, `sha512crypt` | Hashcat and John Jumbo |
| Django PBKDF2-SHA256 | `django-pbkdf2-sha256` | Hashcat and John Jumbo |
| Digest of password then salt | `md5-pass-salt`, `sha1-pass-salt`, `sha256-pass-salt`, `sha512-pass-salt` | Hashcat |
| Digest of salt then password | `md5-salt-pass`, `sha1-salt-pass`, `sha256-salt-pass`, `sha512-salt-pass` | Hashcat |

Generic salted digests use `hex_digest:literal_salt`. The salt must contain 1–256 printable ASCII characters with no colon. Spaces in the salt are significant and preserved; salts are not interpreted as hexadecimal. Both concatenation orders have the same appearance, so the caller must select the correct one. This does not cover arbitrary application-specific encoding, HMAC, or repeated hashing.

MySQL 4.1/5 hashes can have an initial `*`; the CLI converts their representation for the chosen engine. `mysql323` and `mysql41` describe legacy schemes, not all current MySQL authentication schemes. NTLM here means the stored NT hash, not a network challenge-response capture. `phpass` handles `$P$` and `$H$` hashes. Modern WordPress `$wp$2...` wrappers use `wordpress-bcrypt` and need a Hashcat version that lists mode `35500` in its full help. They are not ordinary bcrypt and must not be stripped and treated as such. Older Hashcat releases may not support this mode.

Django PBKDF2-SHA256 input uses `pbkdf2_sha256$iterations$salt$digest`. The Hashcat adapter uses mode `10000` and accepts at most 999,999 iterations because some supported Hashcat versions impose a six-digit limit. Use John for higher iteration counts; its adapter adds the prefix John expects. Django salts are limited to a portable 1–31-character subset accepted by both engines.

Use `hash-audit formats` for the installed registry's exact engine identifiers. A recognized format still needs support in your installed engine version. Format references: [Hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) and [John Jumbo format documentation](https://github.com/openwall/john/tree/bleeding-jumbo/doc).

## Recovery, progress, and results

`recover` requires either `--wordlist PATH` or a Hashcat `--mask`. Use your own candidate list based on the password you are trying to recover. Wordlists are read in place, so keep the file unchanged during a run. The engines determine candidate encoding and any format-specific password-length limits.

Hashcat dictionary recovery also accepts `--rules PATH` for a local Hashcat rule file. John recovery in this wrapper supports wordlists only; Hashcat masks and rule files are not passed to John.

`--status-interval 5` controls periodic engine progress. `--max-seconds 300` bounds a run, including startup; without it there is no time limit. Press **Ctrl-C** to stop. Timeout or interruption triggers a graceful shutdown followed by bounded termination if needed. A percentage or ETA reflects the selected candidate search, not the probability of recovering the password.

`--dry-run` validates and previews the engine invocation without starting recovery or creating files; it also works without an installed engine. No shell evaluates the invocation. Hash contents are supplied through a normalized local file rather than command-line arguments. Paths still appear in the process list and run metadata.

Each run uses a new output directory, with a private normalized hash snapshot and `run.json` metadata. By default, the CLI creates a uniquely named directory under `hash-audit-runs`. An explicit `--output-dir` must be new and its parent directory must already exist. The engine writes recovered passwords to a separate `recovered.pot` file; Hashcat also writes `recovered.txt`. Empty or absent recovery files can mean no password was recovered. Results are not automatically displayed after recovery; display them using:

```sh
hash-audit show my-run-directory
```

The pot file is isolated per run, so results are not silently taken from a global password cache. There is no automatic resume command; start a new run with a new output directory. Interrupted engines may leave their own checkpoint files.

Results, pot files, and terminal output can contain plaintext passwords. On POSIX systems the run directory is created with mode `0700` and files with mode `0600`; on Windows, explicit protected NTFS DACLs (`D:P`) restrict the run directory and wrapper-created job files to the current user SID, `SYSTEM`, and `Administrators`. These permissions do not encrypt the data. Keep results out of shared folders and version control. Engine or driver caches can still be stored in their standard system locations.

| CLI exit code | Meaning |
| --- | --- |
| `0` | The engine completed successfully; this does not necessarily mean every password was recovered |
| `2` | Invalid input, missing/unsupported engine, or backend failure |
| `3` | Hashcat exhausted the selected candidates with hashes remaining |
| `124` | The requested time limit was reached |
| `130` | Interrupted by the user |

John can exit successfully after exhausting its wordlist. Inspect its final progress and `show` output to determine what was recovered.

## Troubleshooting and checks

- **Ambiguous format:** supply the algorithm documented by the system that created the hashes. Digest length alone cannot establish it.
- **No devices or compilation error:** check `hashcat -I` and the actual run's diagnostics, then follow the driver documentation. Try John Jumbo for a supported CPU format.
- **Unknown John option or format:** inspect `john --list=build-info` and `john --list=formats`; install a suitable Jumbo build.
- **No match:** confirm the complete hash and salt, construction, input encoding, and candidate list. Exhausting a list is not evidence the hash is invalid.
- **Output directory already exists:** choose a new name. Existing results are never overwritten by `recover`.

Run the local test suite from the project directory:

```sh
python3 -m unittest discover -s tests -v
```

Engine behavior and options are documented in the [Hashcat command reference](https://hashcat.net/wiki/doku.php?id=hashcat) and [John Jumbo options](https://github.com/openwall/john/blob/bleeding-jumbo/doc/OPTIONS).
