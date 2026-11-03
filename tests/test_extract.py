"""Extraction tests. Helpers are mocked, so no engine needs to be installed."""

import contextlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from hash_audit import cli, extractors
from hash_audit.backends import build_command, show_command
from hash_audit.formats import CONTAINERS, validate

# A real zip2john line, including the archive member label it prefixes.
ZIP_LINE = ("demo.zip/secret.txt:$pkzip2$1*2*2*0*1b*f*e65a8667*0*44*0*1b*"
            "e65a*58ba*4421833042a2876d351e59e82fe85feb5dddea75169c964f1c*$/pkzip2$")


class ContainerFormatTest(unittest.TestCase):
    def test_labeled_and_bare_lines_validate(self):
        zip_fmt = CONTAINERS["zip"]
        self.assertTrue(validate(ZIP_LINE, zip_fmt))
        self.assertTrue(validate(ZIP_LINE.split(":", 1)[1], zip_fmt))

    def test_raw_hash_is_not_a_container(self):
        self.assertFalse(validate("d41d8cd98f00b204e9800998ecf8427e", CONTAINERS["zip"]))
        self.assertFalse(validate(ZIP_LINE, CONTAINERS["keepass"]))

    def test_john_autodetects_container_without_a_format_flag(self):
        fmt = CONTAINERS["zip"]
        root = Path(tempfile.mkdtemp(prefix="ha-")).resolve()
        self.addCleanup(__import__("shutil").rmtree, root)
        cmd = build_command("john", "/bin/john", fmt, root / "h.txt",
                            root / "w.txt", None, root, 5)
        self.assertFalse(any(a.startswith("--format=") for a in cmd))
        self.assertNotIn("--format=None", cmd)
        show = show_command("john", "/bin/john", fmt, root / "h.txt", root)
        self.assertIn("--show", show)
        self.assertFalse(any(a.startswith("--format=") for a in show))

    def test_container_is_rejected_by_hashcat(self):
        root = Path(tempfile.mkdtemp(prefix="ha-")).resolve()
        self.addCleanup(__import__("shutil").rmtree, root)
        with self.assertRaises(ValueError):
            build_command("hashcat", "/bin/hashcat", CONTAINERS["zip"], root / "h.txt",
                          root / "w.txt", None, root, 5)


class HashLinesTest(unittest.TestCase):
    def test_label_is_sanitized_and_lines_dedupe(self):
        out = (ZIP_LINE + "\n" + ZIP_LINE + "\n").encode()
        lines = extractors.hash_lines(out)
        self.assertEqual(len(lines), 1)
        label, _, body = lines[0].partition(":")
        self.assertTrue(body.startswith("$pkzip2$"))
        self.assertTrue(all(c.isascii() and (c.isalnum() or c in "._-") for c in label))

    def test_non_ascii_label_becomes_ascii(self):
        line = "sécret.zip/café.txt:$pkzip2$1*1*2*0*deadbeef*$/pkzip2$"
        lines = extractors.hash_lines(line.encode("utf-8"))
        self.assertTrue(lines[0].isascii())
        self.assertIn(":$pkzip2$", lines[0])


class DetectTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="ha-")).resolve()
        self.addCleanup(__import__("shutil").rmtree, self.root)

    def test_detect_by_extension(self):
        path = self.root / "archive.zip"
        self.assertEqual(extractors.detect(path, b""), ["zip"])
        self.assertEqual(extractors.detect(self.root / "db.kdbx", b""), ["keepass"])

    def test_detect_by_magic_without_extension(self):
        self.assertEqual(extractors.detect(self.root / "noext", b"Rar!\x1a\x07\x00"), ["rar"])

    def test_unknown_file_detects_nothing(self):
        self.assertEqual(extractors.detect(self.root / "mystery.bin", b"garbage"), [])


class ExtractCommandTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="ha-")).resolve()
        self.addCleanup(__import__("shutil").rmtree, self.root)
        self.file = self.root / "demo.zip"
        self.file.write_bytes(b"PK\x03\x04 not really a zip, the helper is mocked")
        self.out = self.root / "ex"

    def invoke(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main([str(a) for a in args])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_dry_run_locates_without_running(self):
        with patch.object(extractors, "locate", return_value=["/bin/zip2john"]), \
             patch.object(extractors, "run_helper") as run:
            code, out, _ = self.invoke("extract", self.file, "--dry-run")
        self.assertEqual(code, 0)
        run.assert_not_called()
        data = json.loads(out)
        self.assertEqual(data["type"], "zip")
        self.assertIn("--backend john", data["suggested_recovery"])

    def test_extract_writes_private_hash_and_manifest(self):
        with patch.object(extractors, "locate", return_value=["/bin/zip2john"]), \
             patch.object(extractors, "run_helper", return_value=(0, (ZIP_LINE + "\n").encode(), b"")):
            code, out, _ = self.invoke("extract", self.file, "--output-dir", self.out)
        self.assertEqual(code, 0)
        extracted = (self.out / "extracted.txt").read_text()
        self.assertIn("$pkzip2$", extracted)
        self.assertNotIn("\n\n", extracted)
        manifest = json.loads((self.out / "extract.json").read_text())
        self.assertEqual(manifest["type"], "zip")
        self.assertEqual(manifest["hash_count"], 1)
        self.assertIn("--format zip", out)
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE((self.out / "extracted.txt").lstat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(self.out.lstat().st_mode), 0o700)

    def test_missing_helper_is_a_clear_error(self):
        with patch.object(extractors, "locate", return_value=None):
            code, _, err = self.invoke("extract", self.file, "--output-dir", self.out)
        self.assertEqual(code, 2)
        self.assertIn("John the Ripper Jumbo", err)

    def test_helper_failure_is_reported(self):
        with patch.object(extractors, "locate", return_value=["/bin/zip2john"]), \
             patch.object(extractors, "run_helper", return_value=(1, b"", b"zip2john: cannot read file\n")):
            code, _, err = self.invoke("extract", self.file, "--output-dir", self.out)
        self.assertEqual(code, 2)
        self.assertIn("failed", err)

    def test_file_with_no_hash_is_reported(self):
        with patch.object(extractors, "locate", return_value=["/bin/zip2john"]), \
             patch.object(extractors, "run_helper", return_value=(0, b"", b"")):
            code, _, err = self.invoke("extract", self.file, "--output-dir", self.out)
        self.assertEqual(code, 2)
        self.assertIn("password-protected", err)

    def test_unknown_type_asks_for_type(self):
        mystery = self.root / "mystery.bin"
        mystery.write_bytes(b"not a known container")
        code, _, err = self.invoke("extract", mystery, "--output-dir", self.out)
        self.assertEqual(code, 2)
        self.assertIn("--type", err)


if __name__ == "__main__":
    unittest.main()
