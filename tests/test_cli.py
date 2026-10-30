"""Boundary and workflow tests; fake engines only exercise orchestration."""

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

from hash_audit import cli


class CLITest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.hashes = self.root / "hashes.txt"
        self.digest = hashlib.md5(b"local-demo").hexdigest()
        self.hashes.write_text(self.digest + "\n", encoding="ascii")
        self.words = self.root / "words.txt"
        self.words.write_text("local-demo\n", encoding="ascii")
        self.job = self.root / "job"

    def invoke(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main([str(arg) for arg in args])
        return code, stdout.getvalue(), stderr.getvalue()

    def recover_args(self, *extra):
        return ("recover", self.hashes, "--format", "md5", "--wordlist", self.words,
                "--output-dir", self.job, *extra)

    def make_engine(self, returncode=0):
        engine = self.root / "engine"
        # This stub records a real subprocess invocation, without using a shell.
        engine.write_text(
            f"#!{sys.executable}\n"
            "import json, pathlib, sys\n"
            "pathlib.Path('called.json').write_text(json.dumps(sys.argv[1:]))\n"
            "print('stub progress: 100%')\n"
            f"sys.exit({returncode})\n", encoding="utf-8")
        engine.chmod(0o700)
        return str(engine)

    def test_detection_does_not_print_hash_and_retains_ambiguity(self):
        code, output, _ = self.invoke("detect", self.hashes, "--json")
        self.assertEqual(code, 0)
        data = json.loads(output)
        self.assertEqual(data["lines"][0]["candidates"], ["md5", "ntlm"])
        self.assertNotIn(self.digest, output)

    def test_all_bare_digests_require_explicit_algorithm(self):
        for name in ("md5", "sha1", "sha256", "sha512"):
            digest = hashlib.new(name, b"test").hexdigest()
            with self.subTest(name=name), self.assertRaises(ValueError):
                cli.select_format([(1, digest)], "auto")

    def test_structured_auto_and_mixed_rejection(self):
        bcrypt = "$2b$05$" + "a" * 53
        self.assertEqual(cli.select_format([(1, bcrypt)], "auto").key, "bcrypt")
        with self.assertRaises(ValueError):
            cli.select_format([(1, bcrypt), (2, self.digest)], "auto")

    def test_salted_whitespace_is_preserved(self):
        salt = "  demo salt "
        value = self.digest + ":" + salt
        self.hashes.write_bytes((value + "\r\n\n").encode())
        self.assertEqual(cli.read_hashes(self.hashes), [(1, value)])

    def test_control_characters_and_non_ascii_rejected(self):
        for data in (b"\x1b[2J", b"abc\x00", b"abc\t", b"abc\rdef", b"\xff"):
            with self.subTest(data=data):
                self.hashes.write_bytes(data)
                code, _, _ = self.invoke("detect", self.hashes)
                self.assertEqual(code, 2)

    def test_size_line_count_and_empty_limits(self):
        self.hashes.write_text("a" * (cli.MAX_LINE_BYTES + 1))
        self.assertEqual(self.invoke("detect", self.hashes)[0], 2)
        self.hashes.write_text(self.digest + "\n" + self.digest)
        with patch.object(cli, "MAX_HASH_LINES", 1):
            self.assertEqual(self.invoke("detect", self.hashes)[0], 2)
        with patch.object(cli, "MAX_HASH_BYTES", 5):
            self.assertEqual(self.invoke("detect", self.hashes)[0], 2)
        self.hashes.write_bytes(b"\r\n\n")
        self.assertEqual(self.invoke("detect", self.hashes)[0], 2)

    @unittest.skipUnless(os.name == "posix", "POSIX FIFO")
    def test_fifo_is_rejected_without_opening(self):
        fifo = self.root / "pipe"
        os.mkfifo(fifo)
        self.assertEqual(self.invoke("detect", fifo)[0], 2)

    def test_dry_run_needs_no_engine_and_creates_no_files(self):
        before = set(self.root.iterdir())
        with patch.object(cli.shutil, "which", return_value=None):
            code, output, _ = self.invoke(*self.recover_args("--dry-run"))
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(output)["dry_run"])
        self.assertEqual(before, set(self.root.iterdir()))
        self.assertNotIn(self.digest, output)

    def test_missing_engine_does_not_create_job(self):
        with patch.object(cli, "find_backend", side_effect=ValueError("missing")):
            self.assertEqual(self.invoke(*self.recover_args())[0], 2)
        self.assertFalse(self.job.exists())

    def test_existing_output_is_never_overwritten(self):
        self.job.mkdir()
        sentinel = self.job / "run.json"
        sentinel.write_text("precious")
        self.assertEqual(self.invoke(*self.recover_args("--dry-run"))[0], 2)
        self.assertEqual(sentinel.read_text(), "precious")

    def test_untrusted_masks_cannot_be_engine_options_or_files(self):
        for value in ("--help", "hashes.txt", "run.json", "recovered.pot", "?1", "?", "??", "../?d", "?d\n", "a" * 257):
            with self.subTest(value=value), self.assertRaises(ValueError):
                cli.validate_mask(value)
        for value in ("?d?d", "Demo?l?H", "??hello?d", "`touch pwned`?d"):
            cli.validate_mask(value)

    @unittest.skipUnless(os.name == "posix", "executable script fixture")
    def test_end_to_end_private_snapshot_literal_paths_and_manifest(self):
        unusual = self.root / "words $(touch pwned); `whoami`.txt"
        self.words.rename(unusual)
        self.words = unusual
        self.hashes.write_text(self.digest + "\n" + self.digest.upper() + "\n")
        engine = self.make_engine()
        with patch.object(cli, "find_backend", return_value=engine):
            code, _, error = self.invoke(*self.recover_args())
        self.assertEqual(code, 0, error)
        manifest = json.loads((self.job / "run.json").read_text())
        self.assertEqual(manifest["state"], "completed")
        self.assertEqual(manifest["input_lines"], 2)
        self.assertEqual(manifest["unique_hashes"], 1)
        self.assertEqual((self.job / "hashes.txt").read_text(), self.digest + "\n")
        self.assertEqual(json.loads((self.job / "called.json").read_text())[-1], str(unusual.resolve()))
        self.assertNotIn(self.digest, json.dumps(manifest["argv"]))
        self.assertFalse((self.job / "pwned").exists())
        self.assertEqual(stat.S_IMODE(self.job.stat().st_mode), 0o700)
        for name in ("hashes.txt", "run.json", "recovered.pot", "recovered.txt", "called.json"):
            self.assertEqual(stat.S_IMODE((self.job / name).stat().st_mode), 0o600)
        self.hashes.write_text("modified source")
        with patch.object(cli, "find_backend", return_value=engine):
            self.assertEqual(self.invoke("show", self.job)[0], 0)
        (self.job / "hashes.txt").write_text("modified snapshot")
        self.assertEqual(self.invoke("show", self.job)[0], 2)

    @unittest.skipUnless(os.name == "posix", "executable script fixture")
    def test_hashcat_exit_states_are_preserved(self):
        for result, expected_code, state in ((1, 3, "exhausted"), (255, 2, "failed")):
            with self.subTest(result=result):
                self.job = self.root / f"job-{result}"
                with patch.object(cli, "find_backend", return_value=self.make_engine(result)):
                    self.assertEqual(self.invoke(*self.recover_args())[0], expected_code)
                manifest = json.loads((self.job / "run.json").read_text())
                self.assertEqual(manifest["state"], state)

    def test_unsupported_john_combinations_fail_before_job_creation(self):
        code, _, _ = self.invoke("recover", self.hashes, "--format", "md5", "--backend", "john",
                                  "--mask", "?d?d", "--output-dir", self.job, "--dry-run")
        self.assertEqual(code, 2)
        self.assertFalse(self.job.exists())

    def test_show_rejects_untrusted_manifest_without_execution(self):
        self.job.mkdir()
        (self.job / "hashes.txt").write_text(self.digest)
        (self.job / "recovered.pot").write_text("")
        for manifest in ([], {"schema_version": 1, "backend": "/tmp/untrusted", "format": "md5"},
                         {"schema_version": 1, "backend": "hashcat", "format": []}):
            with self.subTest(manifest=manifest):
                (self.job / "run.json").write_text(json.dumps(manifest))
                with patch.object(cli, "find_backend") as find:
                    self.assertEqual(self.invoke("show", self.job)[0], 2)
                    find.assert_not_called()


if __name__ == "__main__":
    unittest.main()
