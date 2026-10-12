"""End-to-end tests: run the CLI against the bundled sample log."""

import contextlib
import io
import json
import unittest
from pathlib import Path

from logilog.cli import main

SAMPLE = str(Path(__file__).resolve().parent.parent / "sample_logs" / "auth.log")


def run(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(args))
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_text_report_on_sample(self):
        code, out, _ = run(SAMPLE, "--year", "2026")
        self.assertEqual(code, 0)
        self.assertIn("CRITICAL Success after failures  |  IP 198.51.100.23", out)
        self.assertIn("HIGH     Brute force  |  IP 203.0.113.45", out)
        self.assertIn("Unusual hours", out)

    def test_json_report_on_sample(self):
        code, out, _ = run(SAMPLE, "--year", "2026", "--json")
        data = json.loads(out)
        categories = {(f["category"], f["ip"]) for f in data["findings"]}
        self.assertIn(("Success after failures", "198.51.100.23"), categories)
        self.assertIn(("Brute force", "203.0.113.45"), categories)
        # Low-and-slow IP (3 failures hours apart) and bob's single typo stay quiet.
        flagged_ips = {f["ip"] for f in data["findings"]}
        self.assertNotIn("203.0.113.99", flagged_ips)
        self.assertNotIn("192.0.2.11", flagged_ips)

    def test_fail_on_sets_exit_code(self):
        code, _, _ = run(SAMPLE, "--year", "2026", "--fail-on", "CRITICAL")
        self.assertEqual(code, 1)

    def test_missing_file(self):
        code, _, err = run("does/not/exist.log")
        self.assertEqual(code, 2)
        self.assertIn("cannot read", err)

    def test_bad_hours_rejected(self):
        code, _, _ = run(SAMPLE, "--work-start", "25")
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
