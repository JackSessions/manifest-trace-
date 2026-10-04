# Releasing to PyPI

One-time setup (about 5 minutes):

1. Push `main` to `github.com/JackSessions/manifest-trace-`.
2. On https://pypi.org, log in, then Your account > Publishing > Add a new pending publisher. Type these by hand rather than pasting, so no hidden character sneaks in:
   - PyPI project name: `manifest-trace`
   - Owner: `JackSessions`
   - Repository name: `manifest-trace-`
   - Workflow name: `publish.yml`
   - Environment name: `pypi`
3. On GitHub: Settings > Environments > New environment, name it `pypi` (optionally require your approval before each publish).

Each release:

1. Update the version in `pyproject.toml`, `manifesttrace/__init__.py` and `CITATION.cff`, and add a section to `CHANGELOG.md`.
2. `python3 tests/fixtures/download.py && python -m unittest discover -s tests` and `python -m build && python -m twine check dist/*`.
3. Commit, push, then create a GitHub Release with the tag `vX.Y.Z` (the tag must match the version, and must be on `main` after `publish.yml` exists there). Publishing the release runs `.github/workflows/publish.yml`.
4. Check https://pypi.org/project/manifest-trace/ and try `pipx install manifest-trace` on a clean machine.

A version number can only be uploaded once, even if you delete the release, so run the checks above first.
