# Changelog

## 0.1.0
First release. Generalises CVE-2025-50861 (an exported activity reachable without authentication) and
CVE-2025-50862 (allowBackup=true) into a scanner with five checks: exported components, exported content
providers, allowBackup, debuggable, and cleartext traffic. A from-scratch, standard-library-only reader for
Android's compiled binary XML manifest format, no androguard, no Android SDK. Batch-scans a folder of APKs.
Validated against a well-known deliberately vulnerable training app and a real, modern open-source app.

`--pretty` (a boxed wordmark and severity bars, matching RuntimeTrace's visual family) and a coloured wordmark
on `--help` too. Added `docs/VALIDATING.md`: whether you're authorised to go past the static scan for a given
app, how to confirm each check by hand, and coordinated disclosure for anything found in someone else's app.
