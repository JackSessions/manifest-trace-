"""The checks: does what a component's manifest entry declares actually leave it safe to expose.

Every check here is the same class of bug twice: a component is reachable from outside the app (explicitly
marked exported, or implicitly exported because it has an intent-filter, or, for providers, because of an old
targetSdkVersion) without anything that stops an arbitrary app, or an attacker with ADB access, from reaching it.
This is deliberately the exact bug class behind this author's own CVE-2025-50861 (an exported activity reachable
without authentication) and CVE-2025-50862 (allowBackup=true permitting data extraction over ADB backup),
generalised into something that checks a batch of APKs instead of one app read by hand.

Static analysis only: nothing here runs the APK, decompiles its code, or touches a device. A finding means the
manifest leaves something reachable; it says nothing about what that component actually does once reached. Confirm
real impact (what data an exported provider returns, what an exported activity lets you skip past) by hand before
reporting it to anyone.
"""
from __future__ import annotations

from dataclasses import dataclass

from .manifest import Component, Manifest

SEVERITIES = ("high", "medium", "low")

WHY = {
    "exported_without_protection": (
        "This component is reachable by any other app on the device (and by anyone with ADB access), with no "
        "permission, signature check or other protection stopping them. This is the same bug class as "
        "CVE-2025-50861: an exported activity that skipped straight past the app's own login screen because "
        "nothing but the app's own UI enforced the authentication check. A component can be exported "
        "deliberately and safely (a share target, a deep link handler); the question this check cannot answer "
        "is whether what happens once reached is safe to expose. That needs a human read of the component's code."
    ),
    "exported_provider_wide_open": (
        "This content provider is reachable by any other app, with no read or write permission and no "
        "per-path restriction narrowing what is shared. Content providers usually sit in front of structured "
        "data (often a SQLite database), so an unprotected one is a common source of both data leakage and SQL "
        "injection, since the provider's query interface is now reachable from any installed app."
    ),
    "allow_backup_enabled": (
        "android:allowBackup is true (or left unset, which defaults to true), so `adb backup` can pull this "
        "app's private data without root, on any device where USB debugging is enabled. This is exactly "
        "CVE-2025-50862: the same flag, in a different app. A BackupAgent or a fullBackupContent rule can "
        "legitimately narrow what gets backed up; this check does not look that deep, only at the flag itself."
    ),
    "debuggable_true": (
        "android:debuggable is true. On a shipped build this means a debugger can attach to the app's process, "
        "and `adb shell run-as` can access its private data directory, without root, for anyone with physical "
        "or ADB access to the device. This flag belongs in development builds only."
    ),
    "cleartext_traffic_allowed": (
        "This app is allowed to send plaintext (unencrypted) HTTP traffic: either usesCleartextTraffic is "
        "explicitly true, or it was left unset on an app whose targetSdkVersion is old enough (below 28) that "
        "the platform default is still to allow it. Traffic sent this way can be read or modified by anyone on "
        "the same network path, the classic setup for a trivial man-in-the-middle."
    ),
}

LAUNCHER_NOTE = "the launcher activity (android.intent.action.MAIN / android.intent.category.LAUNCHER) is expected to be exported; this one is not flagged"

# A real, copy-pasteable next command per check: the shortest path from "flagged" to "confirmed", or dropped
# as a false lead. Only suggested, never run: this stays a read-only static scanner. Full context, including
# whether you're actually authorised to run any of these against a given app, is in docs/VALIDATING.md.
_AM_SUBCOMMAND = {"activity": "start", "activity-alias": "start", "service": "startservice", "receiver": "broadcast"}
_NEXT_STEP_TEMPLATES = {
    "exported_provider_wide_open": "adb shell content query --uri content://{detail}/",
    "allow_backup_enabled": "adb backup -f backup.ab {package}   (then extract it and look at what is actually inside)",
    "debuggable_true": "adb shell run-as {package} ls /data/data/{package}",
    "cleartext_traffic_allowed": "proxy the app's traffic (mitmproxy -p 8080, or Burp) and watch for a real http:// request going out",
}
_NEEDS_DECOMPILE = {"exported_without_protection", "exported_provider_wide_open"}   # confirming impact needs reading the component's own code
_DECOMPILERS = (("jadx", "https://github.com/skylot/jadx"), ("apktool", "https://apktool.org"))


def _tool_hint() -> str:
    """Which decompiler is actually on this machine, so the suggestion is something you can run right now."""
    import shutil
    found = [name for name, _url in _DECOMPILERS if shutil.which(name)]
    if found:
        return f"{found[0]} is on this machine: {found[0]} -d out/ <app.apk>, then read the component's code"
    name, url = _DECOMPILERS[0]
    return f"not on this machine: install {name} ({url}) to decompile and read the component's code"


def next_step(f: "Finding") -> str:
    if f.check == "exported_without_protection":
        # am's subcommand depends on what kind of component this is: starting an activity, starting a
        # service and broadcasting to a receiver are three different adb commands, not one.
        sub = _AM_SUBCOMMAND.get(f.kind, "start")
        cmd = f"adb shell am {sub} -n {f.package or '<package>'}/{f.component}"
    else:
        tmpl = _NEXT_STEP_TEMPLATES.get(f.check, "")
        if not tmpl:
            return ""
        cmd = tmpl.format(package=f.package or "<package>", component=f.component, detail=f.detail or f.component)
    if f.check in _NEEDS_DECOMPILE:
        return f"{cmd}   |   {_tool_hint()}"
    return cmd


@dataclass
class Finding:
    check: str
    severity: str
    component: str
    package: str
    message: str
    detail: str = ""                                      # check-specific extra (a provider's authority, so far)
    kind: str = ""                                         # the manifest.Component kind, where relevant (activity/service/receiver/...)

    def as_dict(self) -> dict:
        return {"check": self.check, "severity": self.severity, "component": self.component,
                "package": self.package, "message": self.message, "why": WHY[self.check], "next": next_step(self)}


def _is_launcher(c: Component) -> bool:
    return c.kind in ("activity", "activity-alias") and any(f.is_launcher for f in c.intent_filters)


def check_exported_components(m: Manifest) -> list[Finding]:
    out = []
    for c in m.components:
        if c.kind == "provider" or not c.effective_exported(m.target_sdk) or c.is_protected():
            continue
        if _is_launcher(c):
            continue
        how = "exported=true" if c.exported_attr else "implicitly exported (it has an intent-filter and exported was not set)"
        out.append(Finding("exported_without_protection", "high", c.name, m.package,
                            f"{c.kind} {c.name} is {how}, with no permission requirement", kind=c.kind))
    return out


def check_exported_providers(m: Manifest) -> list[Finding]:
    out = []
    for c in m.components:
        if c.kind != "provider" or not c.effective_exported(m.target_sdk) or c.is_protected():
            continue
        if c.has_path_permissions:
            continue                                      # narrower per-path grants exist; a human should read them, but it is not wide open
        how = "exported=true" if c.exported_attr is not None else f"implicitly exported (targetSdkVersion {m.target_sdk} < 17)"
        out.append(Finding("exported_provider_wide_open", "high", c.name, m.package,
                            f"provider {c.name} (authorities: {c.authorities or '?'}) is {how}, with no read/write permission",
                            detail=c.authorities))
    return out


def check_allow_backup(m: Manifest) -> list[Finding]:
    if m.allow_backup is False:
        return []
    how = "allowBackup=true" if m.allow_backup else "allowBackup is not set (defaults to true)"
    return [Finding("allow_backup_enabled", "medium", "application", m.package, f"{how} for {m.package or 'this app'}")]


def check_debuggable(m: Manifest) -> list[Finding]:
    if not m.debuggable:
        return []
    return [Finding("debuggable_true", "high", "application", m.package, f"android:debuggable=true for {m.package or 'this app'}")]


def check_cleartext_traffic(m: Manifest) -> list[Finding]:
    if not m.effective_cleartext():
        return []
    how = "usesCleartextTraffic=true" if m.uses_cleartext_traffic else f"unset, defaulting to allowed (targetSdkVersion {m.target_sdk} < 28)"
    return [Finding("cleartext_traffic_allowed", "medium", "application", m.package, f"cleartext HTTP traffic is allowed: {how}")]


def scan(m: Manifest) -> list[Finding]:
    out: list[Finding] = []
    out += check_exported_components(m)
    out += check_exported_providers(m)
    out += check_allow_backup(m)
    out += check_debuggable(m)
    out += check_cleartext_traffic(m)
    return out


def verdict(findings: list[Finding]) -> tuple[str, str]:
    n = {s: sum(f.severity == s for f in findings) for s in SEVERITIES}
    if n["high"]:
        return "red", f"{n['high']} high-severity finding{'s' if n['high'] != 1 else ''}. Confirm manually before reporting; a finding here is a lead, not proof."
    if n["medium"]:
        return "yellow", f"{n['medium']} medium-severity finding(s)."
    if findings:
        return "cyan", "Only low-confidence notes."
    return "green", "No manifest-level exposure found by these checks."
