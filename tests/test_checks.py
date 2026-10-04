"""Pure logic, no APK, no AXML parsing: each check gets a fake manifest it must fire on, and a fake clean one
it must stay quiet on. Same testing philosophy as this author's other tools: a check that cannot be proven both
ways with a plain unit test is not trustworthy enough to ship."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from manifesttrace import checks  # noqa: E402
from manifesttrace.manifest import Component, IntentFilter, Manifest  # noqa: E402


def clean_manifest(**over) -> Manifest:
    base = dict(path="x.apk", package="com.example.clean", min_sdk=21, target_sdk=34, debuggable=False,
                allow_backup=False, uses_cleartext_traffic=False, has_network_security_config=False, components=[])
    base.update(over)
    return Manifest(**base)


def launcher() -> Component:
    return Component(kind="activity", name=".Main", exported_attr=None, permission=None,
                     intent_filters=[IntentFilter(actions=["android.intent.action.MAIN"], categories=["android.intent.category.LAUNCHER"])])


class CleanTests(unittest.TestCase):
    def test_a_locked_down_manifest_has_no_findings(self):
        m = clean_manifest(components=[launcher()])
        self.assertEqual(checks.scan(m), [])
        self.assertEqual(checks.verdict([]), ("green", "No manifest-level exposure found by these checks."))

    def test_the_launcher_activity_is_not_flagged_even_though_it_is_exported(self):
        m = clean_manifest(components=[launcher()])
        self.assertEqual(checks.check_exported_components(m), [])

    def test_a_protected_exported_activity_is_not_flagged(self):
        c = Component(kind="activity", name=".Share", exported_attr=True, permission="com.example.clean.SHARE_PERM")
        self.assertEqual(checks.check_exported_components(clean_manifest(components=[c])), [])

    def test_a_provider_with_path_permissions_is_not_flagged_wide_open(self):
        c = Component(kind="provider", name=".Docs", exported_attr=True, permission=None, authorities="x", has_path_permissions=True)
        self.assertEqual(checks.check_exported_providers(clean_manifest(components=[c])), [])


class ExportedComponentTests(unittest.TestCase):
    def test_explicitly_exported_with_no_permission_is_flagged_high(self):
        c = Component(kind="activity", name=".Admin", exported_attr=True, permission=None)
        out = checks.check_exported_components(clean_manifest(components=[c]))
        self.assertEqual([(f.check, f.severity, f.component) for f in out], [("exported_without_protection", "high", ".Admin")])
        self.assertIn("exported=true", out[0].message)

    def test_implicitly_exported_via_intent_filter_is_also_flagged(self):
        c = Component(kind="receiver", name=".Hook", exported_attr=None, permission=None,
                     intent_filters=[IntentFilter(actions=["com.example.ACTION"])])
        out = checks.check_exported_components(clean_manifest(components=[c]))
        self.assertEqual(len(out), 1)
        self.assertIn("implicitly exported", out[0].message)

    def test_a_non_exported_component_is_not_flagged(self):
        c = Component(kind="service", name=".Internal", exported_attr=False, permission=None)
        self.assertEqual(checks.check_exported_components(clean_manifest(components=[c])), [])


class ExportedProviderTests(unittest.TestCase):
    def test_wide_open_provider_is_high(self):
        c = Component(kind="provider", name=".Users", exported_attr=True, permission=None, authorities="com.example.clean.users")
        out = checks.check_exported_providers(clean_manifest(components=[c]))
        self.assertEqual([(f.check, f.severity) for f in out], [("exported_provider_wide_open", "high")])
        self.assertIn("com.example.clean.users", out[0].message)

    def test_implicit_export_on_old_target_sdk_is_flagged_and_says_why(self):
        c = Component(kind="provider", name=".Legacy", exported_attr=None, permission=None, authorities="x")
        out = checks.check_exported_providers(clean_manifest(target_sdk=15, components=[c]))
        self.assertEqual(len(out), 1)
        self.assertIn("targetSdkVersion 15 < 17", out[0].message)

    def test_implicit_default_is_safe_on_modern_target_sdk(self):
        c = Component(kind="provider", name=".Modern", exported_attr=None, permission=None, authorities="x")
        self.assertEqual(checks.check_exported_providers(clean_manifest(target_sdk=34, components=[c])), [])

    def test_read_and_write_permission_together_counts_as_protected(self):
        c = Component(kind="provider", name=".P", exported_attr=True, permission=None, read_permission="R", write_permission="W", authorities="x")
        self.assertEqual(checks.check_exported_providers(clean_manifest(components=[c])), [])


class FlagChecksTests(unittest.TestCase):
    def test_allow_backup_true_is_flagged_medium(self):
        out = checks.check_allow_backup(clean_manifest(allow_backup=True))
        self.assertEqual([(f.check, f.severity) for f in out], [("allow_backup_enabled", "medium")])
        self.assertIn("allowBackup=true", out[0].message)

    def test_allow_backup_unset_defaults_true_and_is_flagged(self):
        out = checks.check_allow_backup(clean_manifest(allow_backup=None))
        self.assertEqual(len(out), 1)
        self.assertIn("not set (defaults to true)", out[0].message)

    def test_allow_backup_explicit_false_is_quiet(self):
        self.assertEqual(checks.check_allow_backup(clean_manifest(allow_backup=False)), [])

    def test_debuggable_is_flagged_high(self):
        out = checks.check_debuggable(clean_manifest(debuggable=True))
        self.assertEqual([(f.check, f.severity) for f in out], [("debuggable_true", "high")])

    def test_cleartext_explicit_true_is_flagged(self):
        out = checks.check_cleartext_traffic(clean_manifest(uses_cleartext_traffic=True))
        self.assertIn("usesCleartextTraffic=true", out[0].message)

    def test_cleartext_default_depends_on_target_sdk(self):
        old = checks.check_cleartext_traffic(clean_manifest(target_sdk=21, uses_cleartext_traffic=None))
        new = checks.check_cleartext_traffic(clean_manifest(target_sdk=34, uses_cleartext_traffic=None))
        self.assertEqual(len(old), 1)
        self.assertEqual(len(new), 0)

    def test_a_network_security_config_present_is_treated_as_the_apps_own_policy(self):
        out = checks.check_cleartext_traffic(clean_manifest(target_sdk=21, uses_cleartext_traffic=None, has_network_security_config=True))
        self.assertEqual(out, [])


class NextStepTests(unittest.TestCase):
    """next_step() has to produce a command that actually matches the component kind: `adb shell am start`
    only works for activities. A service needs startservice, a receiver needs broadcast. Getting this wrong
    means the tool's own advice doesn't work, caught here by checking a real adb am subcommand per kind."""

    def test_activity_suggests_am_start(self):
        c = Component(kind="activity", name=".Admin", exported_attr=True, permission=None)
        f = checks.check_exported_components(clean_manifest(components=[c]))[0]
        self.assertIn("adb shell am start -n com.example.clean/.Admin", checks.next_step(f))

    def test_service_suggests_am_startservice_not_start(self):
        c = Component(kind="service", name=".Sync", exported_attr=True, permission=None)
        f = checks.check_exported_components(clean_manifest(components=[c]))[0]
        nxt = checks.next_step(f)
        self.assertIn("am startservice -n com.example.clean/.Sync", nxt)
        self.assertNotIn("am start -n", nxt)

    def test_receiver_suggests_am_broadcast_not_start(self):
        c = Component(kind="receiver", name=".Hook", exported_attr=True, permission=None)
        f = checks.check_exported_components(clean_manifest(components=[c]))[0]
        nxt = checks.next_step(f)
        self.assertIn("am broadcast -n com.example.clean/.Hook", nxt)
        self.assertNotIn("am start -n", nxt)

    def test_provider_suggests_content_query_with_the_real_authority(self):
        c = Component(kind="provider", name=".Users", exported_attr=True, permission=None, authorities="com.example.clean.users")
        f = checks.check_exported_providers(clean_manifest(components=[c]))[0]
        self.assertIn("content://com.example.clean.users/", checks.next_step(f))

    def test_allow_backup_and_debuggable_suggest_the_right_adb_subcommand(self):
        self.assertIn("adb backup", checks.next_step(checks.check_allow_backup(clean_manifest(allow_backup=True))[0]))
        self.assertIn("run-as", checks.next_step(checks.check_debuggable(clean_manifest(debuggable=True))[0]))

    def test_exported_checks_mention_a_decompiler_the_backup_check_does_not(self):
        c = Component(kind="activity", name=".A", exported_attr=True, permission=None)
        exported_next = checks.next_step(checks.check_exported_components(clean_manifest(components=[c]))[0])
        backup_next = checks.next_step(checks.check_allow_backup(clean_manifest(allow_backup=True))[0])
        self.assertTrue(any(name in exported_next for name, _url in checks._DECOMPILERS))
        self.assertFalse(any(name in backup_next for name, _url in checks._DECOMPILERS))

    def test_as_dict_includes_a_working_next_field(self):
        c = Component(kind="activity", name=".A", exported_attr=True, permission=None)
        f = checks.check_exported_components(clean_manifest(components=[c]))[0]
        self.assertEqual(f.as_dict()["next"], checks.next_step(f))


class VerdictTests(unittest.TestCase):
    def test_severity_ordering_picks_the_worst(self):
        c = Component(kind="activity", name=".A", exported_attr=True, permission=None)
        m = clean_manifest(allow_backup=True, components=[c])
        color, msg = checks.verdict(checks.scan(m))
        self.assertEqual(color, "red")
        self.assertIn("high-severity", msg)


if __name__ == "__main__":
    unittest.main()
