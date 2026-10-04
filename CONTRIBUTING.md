# Contributing

Thanks for looking. This is a small project by one person, so the process is light.

1. Open an issue first for anything bigger than a bug fix.
2. `python3 -m unittest discover -s tests -v` must pass. Real-APK tests need `python3 tests/fixtures/download.py` first (needs network); without it they are skipped, not required.
3. A new check needs a test that proves it fires on a fake manifest and a test that proves a clean manifest stays quiet, the same bar every other check here is held to.
4. False positive reports, a check firing on a manifest entry that is actually safe, are the most valuable kind of issue this project can get.
5. Nothing added to this project may help exploit a finding rather than report it. ManifestTrace finds exposure; it does not weaponise it.

ManifestTrace is MIT licensed.
