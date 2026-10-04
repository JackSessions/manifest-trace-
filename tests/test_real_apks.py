"""Runs the real parser and checks against two real, independently-built APKs (see tests/fixtures/README.md).
Skipped if the fixtures have not been downloaded. This is the test that actually proves the from-scratch AXML
parser reads real compiled binary XML correctly, not just the hand-built documents in test_axml.py, and that the
checks find the documented, well-known vulnerabilities in a real training app without being tuned to do so."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from manifesttrace import checks  # noqa: E402
from manifesttrace import manifest as M  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
INSECUREBANK = os.path.join(FIXTURES, "insecurebankv2.apk")
CLEAN = os.path.join(FIXTURES, "clean-sample.apk")


@unittest.skipUnless(os.path.exists(INSECUREBANK), "run tests/fixtures/download.py first")
class InsecureBankV2Tests(unittest.TestCase):
    """InsecureBankv2 is a well-known OWASP-style training app with documented vulnerabilities: several exported
    activities reachable without authentication, an exported content provider, allowBackup and debuggable both
    true. If this tool cannot find these on a famous, deliberately-vulnerable reference app, it is not working."""

    @classmethod
    def setUpClass(cls):
        cls.m = M.load(INSECUREBANK)
        cls.findings = checks.scan(cls.m)
        cls.by_check = {}
        for f in cls.findings:
            cls.by_check.setdefault(f.check, []).append(f)

    def test_package_and_sdk_parsed_correctly(self):
        self.assertEqual(self.m.package, "com.android.insecurebankv2")
        self.assertEqual(self.m.min_sdk, 15)
        self.assertEqual(self.m.target_sdk, 22)

    def test_known_vulnerable_activities_are_found(self):
        names = {f.component for f in self.by_check.get("exported_without_protection", [])}
        for known in ("com.android.insecurebankv2.PostLogin", "com.android.insecurebankv2.DoTransfer", "com.android.insecurebankv2.ViewStatement"):
            self.assertIn(known, names, f"expected {known} to be flagged exported-without-protection")

    def test_the_exported_content_provider_is_found(self):
        self.assertTrue(any("TrackUserContentProvider" in f.component for f in self.by_check.get("exported_provider_wide_open", [])))

    def test_allow_backup_and_debuggable_are_both_flagged(self):
        self.assertEqual(len(self.by_check.get("allow_backup_enabled", [])), 1)
        self.assertEqual(len(self.by_check.get("debuggable_true", [])), 1)

    def test_overall_verdict_is_high(self):
        color, msg = checks.verdict(self.findings)
        self.assertEqual(color, "red")

    def test_login_activity_itself_is_the_launcher_and_not_flagged(self):
        # LoginActivity carries the MAIN/LAUNCHER intent-filter in this app; it must not appear as a finding
        # even though it has no explicit exported attribute (it is implicitly exported, as every launcher is).
        names = {f.component for f in self.by_check.get("exported_without_protection", [])}
        self.assertNotIn("com.android.insecurebankv2.LoginActivity", names)


@unittest.skipUnless(os.path.exists(CLEAN), "run tests/fixtures/download.py first")
class CleanSampleTests(unittest.TestCase):
    """A real, modern, legitimately open-source app. Proves the parser handles a real APK Signing Block v2/v3
    manifest (a different, newer toolchain than InsecureBankv2's) without crashing, and that findings here are
    genuine entries in the manifest, not noise invented by the parser."""

    @classmethod
    def setUpClass(cls):
        cls.m = M.load(CLEAN)
        cls.findings = checks.scan(cls.m)

    def test_parses_a_modern_toolchain_manifest(self):
        self.assertTrue(self.m.package)
        self.assertGreater(self.m.target_sdk, 28)

    def test_every_finding_is_a_real_manifest_entry(self):
        # every flagged component must actually exist in the parsed manifest, and (for the exported check)
        # must genuinely have exported_attr True or a real intent-filter: no finding invented out of nothing.
        comps = {c.name: c for c in self.m.components}
        for f in self.findings:
            if f.check in ("exported_without_protection", "exported_provider_wide_open"):
                self.assertIn(f.component, comps)
                c = comps[f.component]
                self.assertTrue(c.exported_attr is True or c.intent_filters or (c.kind == "provider" and c.exported_attr is not False))


if __name__ == "__main__":
    unittest.main()
