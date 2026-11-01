from __future__ import annotations

import contextlib
import io
import os
from pathlib import Path
import signal
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from hash_audit.backends import build_command, find_backend, run_command, safe_text, show_command


class CommandsTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="hash-audit-test-")).resolve()
        self.addCleanup(__import__("shutil").rmtree, self.root)
        self.fmt = SimpleNamespace(key="md5", hashcat_mode=0, john_format="raw-md5")
        self.hashes = self.root / "hashes.txt"
        self.words = self.root / "words ; $(touch BAD).txt"

    def test_hashcat_paths_and_rule_file_are_single_arguments(self):
        rule = self.root / "rules ; name.rule"
        cmd = build_command("hashcat", "/bin/hashcat", self.fmt, self.hashes, self.words, None, self.root, 5, rule)
        self.assertEqual(cmd[-2:], [str(self.hashes), str(self.words)])
        self.assertIn(str(rule), cmd)
        self.assertIn("--outfile-format=1,2", cmd)
        self.assertIn(f"--potfile-path={self.root / 'recovered.pot'}", cmd)
        session = next(arg for arg in cmd if arg.startswith("--session="))
        self.assertRegex(session, r"^--session=hash-audit-[0-9a-f]{20}$")
        self.assertNotIn("--force", cmd)

    def test_mask_stays_literal(self):
        cmd = build_command("hashcat", "/bin/hashcat", self.fmt, self.hashes, None, "?l?l$(touch BAD)", self.root, 5)
        self.assertEqual(cmd[-1], "?l?l$(touch BAD)")
        self.assertEqual(cmd[cmd.index("-a") + 1], "3")

    def test_unsafe_mask_is_rejected(self):
        for mask in ["-r", "abc\n?d", "\x1b?d", "", "a" * 257]:
            with self.subTest(mask=mask), self.assertRaises(ValueError):
                build_command("hashcat", "hashcat", self.fmt, self.hashes, None, mask, self.root, 5)

    def test_john_dictionary_and_show(self):
        cmd = build_command("john", "john", self.fmt, self.hashes, self.words, None, self.root, 5)
        self.assertIn(f"--wordlist={self.words}", cmd)
        self.assertIn("--progress-every=5", cmd)
        self.assertIn("--no-log", cmd)
        shown = show_command("john", "john", self.fmt, self.hashes, self.root)
        self.assertIn(f"--pot={self.root / 'recovered.pot'}", shown)
        self.assertIn("--show", shown)

    def test_no_implicit_attack_and_unsupported_combinations(self):
        for words, mask in [(None, None), (self.words, "?d")]:
            with self.assertRaises(ValueError):
                build_command("hashcat", "hashcat", self.fmt, self.hashes, words, mask, self.root, 5)
        with self.assertRaises(ValueError):
            build_command("john", "john", self.fmt, self.hashes, None, "?d", self.root, 5)
        with self.assertRaises(ValueError):
            build_command("john", "john", self.fmt, self.hashes, self.words, None, self.root, 5, self.words)
        self.fmt.john_format = None
        with self.assertRaises(ValueError):
            show_command("john", "john", self.fmt, self.hashes, self.root)

    def test_backend_discovery_error(self):
        with patch("hash_audit.backends.shutil.which", return_value=None), self.assertRaisesRegex(ValueError, "Jumbo"):
            find_backend("john")
        with self.assertRaises(ValueError):
            find_backend("sh")

    def test_terminal_controls_escaped(self):
        self.assertEqual(safe_text("a\x1b[31m\r\t\x00\u202eb\n"), "a\\x1b[31m\\x0d\\x09\\x00\\u202eb\n")
        self.assertEqual(safe_text("café 😀"), "café 😀")


class ProcessTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="hash-audit-proc-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def run_script(self, source, extra=(), max_seconds=10):
        script = self.root / "backend fixture.py"
        script.write_text(source, encoding="utf-8")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = run_command([sys.executable, str(script), *extra], self.root, 1, max_seconds)
        return result, output.getvalue()

    def test_real_process_never_invokes_shell_and_escapes_output(self):
        payload = "; touch INJECTED; $(touch INJECTED)"
        result, output = self.run_script("import sys\nsys.stdout.reconfigure(encoding='utf-8')\nprint(sys.argv[1])\nprint('\\x1b[31mcolored\\u202e')\n", [payload])
        self.assertEqual(result.returncode, 0)
        self.assertIn(payload, output)
        self.assertIn("\\x1b[31m", output)
        self.assertIn("\\u202e", output)
        self.assertFalse((self.root / "INJECTED").exists())

    @unittest.skipUnless(os.name == "posix", "POSIX permission contract")
    def test_child_files_are_private(self):
        result, _ = self.run_script("from pathlib import Path\nPath('secret').write_text('demo')\n")
        self.assertEqual(result.returncode, 0)
        self.assertEqual((self.root / "secret").stat().st_mode & 0o777, 0o600)

    def test_timeout_stops_process(self):
        result, output = self.run_script("import time\ntime.sleep(60)\n", max_seconds=1)
        self.assertTrue(result.timed_out)
        self.assertFalse(result.interrupted)
        self.assertLess(result.elapsed, 7)
        self.assertIn("Time limit", output)

    @unittest.skipUnless(os.name == "posix", "POSIX signal test")
    def test_timeout_kills_process_ignoring_signals(self):
        result, _ = self.run_script("import signal, time\nsignal.signal(signal.SIGINT, signal.SIG_IGN)\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\ntime.sleep(60)\n", max_seconds=1)
        self.assertTrue(result.timed_out)
        self.assertEqual(result.returncode, -signal.SIGKILL)
        self.assertLess(result.elapsed, 7)

    @unittest.skipUnless(os.name == "posix", "POSIX signal test")
    def test_ctrl_c_is_caught_and_child_stopped(self):
        timer = threading.Timer(0.3, lambda: os.kill(os.getpid(), signal.SIGINT))
        timer.start()
        try:
            result, output = self.run_script("import time\ntime.sleep(60)\n")
        finally:
            timer.cancel()
            timer.join()
        self.assertTrue(result.interrupted)
        self.assertFalse(result.timed_out)
        self.assertIn("Interrupted", output)
        self.assertLess(result.elapsed, 6)

    def test_stream_large_output_without_line_buffering(self):
        result, output = self.run_script("import sys\nsys.stdout.write('x' * 200000)\n")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(output, "x" * 200000)

    def test_slow_terminal_receives_all_final_output(self):
        class SlowTerminal(io.StringIO):
            def write(self, value):
                time.sleep(0.1)
                return super().write(value)

        script = self.root / "backend.py"
        script.write_text("import sys\nsys.stdout.write('x' * 65536)\n")
        output = SlowTerminal()
        with contextlib.redirect_stdout(output):
            result = run_command([sys.executable, str(script)], self.root, 1, 10)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(output.getvalue(), "x" * 65536)


if __name__ == "__main__":
    unittest.main()
