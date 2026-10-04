# Testing ManifestTrace

## 1. Automated tests, no network (a few seconds)

```bash
cd ~/Projects/manifest-trace
python3 -m unittest discover -s tests -v
```

Expect most tests to pass with a handful skipped (the real-APK tests, which need the fixtures downloaded first). This covers the binary XML reader against hand-built documents and every check against fake manifests.

## 2. Automated tests, with the real APK fixtures

```bash
python3 tests/fixtures/download.py     # fetches two real APKs, about 9 MB, needs network
python3 -m unittest discover -s tests -v
```

Now the real-APK tests run too: the parser against InsecureBankv2 (a well-known deliberately vulnerable training app) and a real, modern F-Droid app as a clean baseline. Expect all tests to pass.

## 3. A five-minute manual run-through

```bash
manifest-trace --help                              banner, every check, examples
manifest-trace --list-checks                        every check explained
manifest-trace tests/fixtures/insecurebankv2.apk    should find 7+ high/medium findings
manifest-trace tests/fixtures/                      batch scan both fixtures
manifest-trace tests/fixtures/ --json | python3 -m json.tool | head -30
manifest-trace tests/fixtures/ --html /tmp/mt.html -q && xdg-open /tmp/mt.html
```

| Step | Expected |
|---|---|
| `--help` | Banner, every check described, exit codes explained |
| InsecureBankv2 scan | PostLogin, DoTransfer, ViewStatement, ChangePassword flagged exported, TrackUserContentProvider flagged, allowBackup and debuggable both flagged |
| batch scan | Both APKs listed, package name shown for each |
| `--json` | Valid JSON, one entry per scanned APK |
| a non-APK file | A clean `[ERROR]` line, not a traceback; exit code 2 |
| an empty folder | A clean error, exit code 2 |

## 4. Report a bug or a false positive

False positive reports, a finding on a manifest entry that is actually safe, are the most valuable kind of issue here. Open one with `manifest-trace app.apk --json` output and, if you can share it, the APK's build tool version.
