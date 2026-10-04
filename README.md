# ManifestTrace

![tests](https://github.com/JackSessions/manifest-trace/actions/workflows/test.yml/badge.svg)
![python](https://img.shields.io/badge/python-3.9%2B-blue)
![licence](https://img.shields.io/badge/licence-MIT-blue)

Does an Android app's manifest leave something reachable that should not be.

This generalises two of this author's own disclosed CVEs into a scanner. CVE-2025-50861 was a single exported Android activity that could be reached without authentication. CVE-2025-50862 was `android:allowBackup=true` permitting the app's private data to be pulled over ADB backup. Both were found by hand, in one app, by reading its manifest. ManifestTrace reads the same signal, straight out of the compiled AndroidManifest.xml, across as many APKs as you point it at.

```bash
pip install manifest-trace
manifest-trace app.apk
manifest-trace ./apks/              # every .apk found under a folder
```

## Why would anyone use this?

- Mobile security researchers get a fast first pass across a batch of APKs for the exact bug class this author has already had assigned two CVEs for: unprotected exported components, open backups, debuggable builds, and plaintext network traffic by default.
- Anyone auditing their own app's manifest gets the same check without installing the Android SDK or androguard.
- People learning Android security get a small, readable reference for what a manifest actually controls, and a from-scratch reader for the binary XML format the manifest is compiled into, which most tools treat as a black box behind a heavier dependency.

What it is not: a decompiler, a dynamic analysis tool, or proof that a finding is exploitable. It reads what the manifest declares a component's exposure to be. Whether what happens once that component is reached is actually a problem needs a human to read the component's code. A finding here is a lead, not a report. Before acting on one, including against an app you did not expect to scan or one that turns out to belong to your own employer, read [docs/VALIDATING.md](docs/VALIDATING.md): it covers whether you're authorised to go further, how to confirm each check by hand, and coordinated disclosure (ISO/IEC 29147) for anything found in someone else's app.

## What it checks

| Check | What it looks for | Generalises |
|---|---|---|
| `exported_without_protection` | An activity, activity-alias, service or receiver reachable by any other app, with no permission and no signature check | CVE-2025-50861 |
| `exported_provider_wide_open` | A content provider reachable by any other app, with no read or write permission and no per-path restriction | the same bug class, for data providers |
| `allow_backup_enabled` | android:allowBackup true, or left unset (which defaults to true) | CVE-2025-50862 |
| `debuggable_true` | android:debuggable true in a shipped build | a classic, unambiguous misconfiguration |
| `cleartext_traffic_allowed` | Plaintext HTTP permitted, explicitly or by an old targetSdkVersion default | a man-in-the-middle enabler |

A component counts as exported if it is marked exported=true, or if exported is left unset and it has an intent-filter (the platform's own default), or, for providers only, if exported is unset and targetSdkVersion is below 17 (the old, implicit-export default that catches people who never even wrote exported=true). The one deliberate exception: the launcher activity (android.intent.action.MAIN / android.intent.category.LAUNCHER) is expected to be exported and is never flagged for that alone.

## Install

```bash
pip install manifest-trace
# or: pipx install manifest-trace
```

Standard library only. No androguard, no Android SDK, no aapt.

## Use

```
manifest-trace app.apk                   scan one APK
manifest-trace ./apks/                   scan every .apk found under a folder
manifest-trace app.apk --json            machine-readable output
manifest-trace ./apks/ --html report.html  a shareable report for a whole batch
manifest-trace app.apk --list-checks     every check, its severity and what it means
manifest-trace app.apk -q                just the verdict per APK
```

Exit codes: 0 clean, 1 at least one high or medium finding, 2 error (including a folder with no .apk files, or a file that is not a valid APK).

## How it is tested

Two layers, the same split this author's other tools use. The binary XML reader (axml.py) is proven against hand-built compiled documents, byte for byte, so the format parsing itself is correct independent of any one real manifest. The checks (checks.py) are proven against fake manifests, one scenario per check that must fire, one clean scenario that must stay quiet. Neither of those needs a real APK and both run in CI on every commit.

Separately, the whole pipeline is run against two real, independently-built APKs: [InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2), a well-known, deliberately vulnerable training app, and a real, modern open-source app from F-Droid as a clean baseline. The tool correctly finds InsecureBankv2's documented exported-activity, exported-provider, allowBackup and debuggable issues without being tuned to that specific app, and does not invent findings on the clean sample that are not actually in its manifest. Not committed to the repository (APKs are large binaries); `tests/fixtures/download.py` fetches both on demand, and the tests that need them are skipped otherwise.

Run everything: `python3 -m unittest discover -s tests -v`. Real-APK tests first need `python3 tests/fixtures/download.py` (needs network, about 9 MB).

## Known limitations

- Manifest-level static analysis only. It does not decompile code, so it cannot tell you what an exported component actually does once reached, only that it is reachable.
- It does not check code-level protections that never show up in the manifest: a component can declare no permission and still check the calling package or signature in its own code before doing anything sensitive. A finding here is a starting point for a manual read, not a conclusion.
- allowBackup is checked as a flag only. A BackupAgent or fullBackupContent rule can legitimately narrow what actually gets backed up; this tool does not look that deep yet.
- No deep link validation, no WebView-specific checks (addJavascriptInterface, loadUrl with untrusted input), no native library analysis. These are real, common Android bug classes this tool does not cover yet.
- Tested against two real APKs so far, one old (targetSdkVersion 22) and one modern (targetSdkVersion 32+). If the binary XML reader behaves differently on an APK built by a toolchain neither of those represents, please open an issue with the APK's build tool version if you can share it: that is the most useful kind of report this project can get.

## Credit and licence

Created and maintained by Jack Sessions. Parts of the code were written with AI assistance; every check is covered by the tests described above, and a finding is a lead to confirm, not proof.

MIT licence (see [LICENSE](LICENSE)). If you use ManifestTrace in a report, talk, course or another tool, please credit Jack Sessions and link https://github.com/JackSessions/manifest-trace ([CITATION.cff](CITATION.cff) has the details).
