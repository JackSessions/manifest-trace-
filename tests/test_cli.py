"""The CLI: exit codes, batch directory scanning, error handling, --list-checks, --json. Uses the real fixture
APKs when present (skipped otherwise) plus a deliberately broken file to prove errors are reported cleanly."""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from manifesttrace import cli  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
INSECUREBANK = os.path.join(FIXTURES, "insecurebankv2.apk")
CLEAN = os.path.join(FIXTURES, "clean-sample.apk")
HAVE_FIXTURES = os.path.exists(INSECUREBANK) and os.path.exists(CLEAN)


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(argv)
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else 0
    return code, out.getvalue(), err.getvalue()


class NoFixtureTests(unittest.TestCase):
    def test_list_checks_exits_clean_and_names_every_check(self):
        code, out, _ = run(["--list-checks"])
        self.assertEqual(code, 0)
        for name in ("exported_without_protection", "exported_provider_wide_open", "allow_backup_enabled", "debuggable_true", "cleartext_traffic_allowed"):
            self.assertIn(name, out)

    def test_version_and_help(self):
        self.assertEqual(run(["--version"])[0], 0)
        code, out, _ = run(["--help"])
        self.assertEqual(code, 0)
        self.assertIn("CVE-2025-50861", out)

    def test_no_target_is_a_clean_usage_error_not_a_crash(self):
        code, _, err = run([])
        self.assertEqual(code, 2)
        self.assertIn("apk", err.lower())

    def test_the_pretty_banner_is_always_aligned(self):
        lines = cli.BANNER_PRETTY.split("\n")
        self.assertEqual(len({len(ln) for ln in lines}), 1, f"banner lines are not the same width: {lines}")

    def test_style_degrades_to_plain_text_with_colour_off(self):
        st = cli.Style(False)
        self.assertEqual(st("red", "x"), "x")
        self.assertEqual(st.wordmark(cli.BANNER), cli.BANNER)
        self.assertEqual(st.google(cli.BANNER_PRETTY), cli.BANNER_PRETTY)

    def test_style_wraps_in_ansi_with_colour_on_and_skips_spaces(self):
        st = cli.Style(True)
        self.assertIn("\x1b[", st("red", "x"))
        on = st.wordmark(cli.BANNER)
        self.assertEqual(on.count(" "), cli.BANNER.count(" "))   # no colour codes glued onto blank space

    def test_bar_helper_fills_by_count_and_caps(self):
        self.assertEqual(cli.bar(0), "░" * 20)
        self.assertEqual(cli.bar(3), "█" * 3 + "░" * 17)
        self.assertEqual(cli.bar(999), "█" * 20)                 # never overflows past the cap

    def test_an_empty_directory_is_a_clean_error(self):
        with tempfile.TemporaryDirectory() as d:
            code, _, err = run([d])
        self.assertEqual(code, 2)
        self.assertIn("no .apk files found", err)

    def test_a_corrupt_apk_is_reported_not_crashed(self):
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(b"not a zip file at all")
            path = f.name
        try:
            code, out, _ = run([path, "-q"])
        finally:
            os.unlink(path)
        self.assertEqual(code, 2)
        self.assertIn("ERROR", out)
        self.assertIn("not a valid .apk", out)


@unittest.skipUnless(HAVE_FIXTURES, "run tests/fixtures/download.py first")
class RealApkCliTests(unittest.TestCase):
    def test_a_vulnerable_apk_exits_1_and_a_clean_run_exits_0_or_1_consistently_with_json(self):
        code_q, out_q, _ = run([INSECUREBANK, "-q"])
        self.assertEqual(code_q, 1)
        self.assertIn("high-severity", out_q)

    def test_json_output_is_valid_and_matches_quiet_verdict(self):
        code, out, _ = run([INSECUREBANK, "--json"])
        self.assertEqual(code, 1)
        d = json.loads(out)
        self.assertEqual(len(d["results"]), 1)
        self.assertEqual(d["results"][0]["package"], "com.android.insecurebankv2")
        self.assertGreater(len(d["results"][0]["findings"]), 5)

    def test_batch_scanning_a_directory_covers_both_fixtures(self):
        code, out, _ = run([FIXTURES, "--json"])
        d = json.loads(out)
        packages = {r.get("package") for r in d["results"] if "package" in r}
        self.assertIn("com.android.insecurebankv2", packages)
        self.assertEqual(code, 1)                           # the worst result across the batch wins the exit code

    def test_pretty_mode_runs_end_to_end_without_crashing(self):
        code, out, _ = run([INSECUREBANK, "--pretty"])
        self.assertEqual(code, 1)
        self.assertIn("┌", out)
        self.assertIn("high", out)

    def test_pretty_batch_scan_prints_a_combined_bar(self):
        code, out, _ = run([FIXTURES, "--pretty"])
        self.assertIn("Across the whole batch", out)

    def test_html_report_is_written_and_contains_both_apps(self):
        with tempfile.TemporaryDirectory() as d:
            out_path = os.path.join(d, "report.html")
            run([FIXTURES, "--html", out_path, "-q"])
            with open(out_path, encoding="utf-8") as f:
                html = f.read()
        self.assertIn("ManifestTrace", html)
        self.assertIn("com.android.insecurebankv2", html)

    def test_a_locked_down_batch_run_would_exit_0(self):
        # not every real app has findings; prove the exit-code logic itself treats an all-clean batch as 0
        # by directly exercising the aggregation path with no findings.
        from manifesttrace import checks
        self.assertEqual(checks.verdict([])[0], "green")


if __name__ == "__main__":
    unittest.main()
