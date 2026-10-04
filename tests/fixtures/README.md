# Test fixture APKs

Not committed to git (see `.gitignore`): two real, independently-built APKs are fetched on demand.

- `insecurebankv2.apk`: [Android-InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2), a well-known,
  deliberately vulnerable training app (Apache-2.0 / MIT style open project, built for security training). Used
  here as a real compiled binary manifest with documented, well-known exported-component, backup and debuggable
  vulnerabilities, to prove the checks fire on something real, not just on hand-built fixtures.
- `clean-sample.apk`: a real, modern, open-source app from F-Droid, used as a baseline to prove the tool does not
  invent findings that are not actually in the manifest.

Run `python3 tests/fixtures/download.py` once to fetch both (needs network, about 9 MB total). Tests that need
them are skipped automatically if they are not present.
