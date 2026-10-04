from __future__ import annotations

import argparse
import json as json_mod
import os
import sys

from . import __author__, __url__, __version__
from . import axml
from . import checks
from . import manifest as M

GOOGLE = {"blue": "38;2;66;133;244", "red": "38;2;234;67;53", "yellow": "38;2;251;188;4", "green": "38;2;52;168;83"}
CODES = {**GOOGLE, "cyan": GOOGLE["blue"], "dim": "2", "bold": "1"}
SEV_COLOR = {"high": "red", "medium": "yellow", "low": "cyan"}
_CYCLE_COLORS = ["blue", "red", "yellow", "green"]
WORDMARK = [
    r" __  __             _  __          _  _____                 ",
    r"|  \/  |__ _ _ _  __| |/ _|___ _ _| |_|_   _| __ __ _ __ ___ ",
    r"| |\/| / _` | ' \/ _| |  _/ -_|_-<  _||| || '_/ _` / _/ -_)",
    r"|_|  |_\__,_|_||_\__|_|_| \___/__/\__||_||_| \__,_\__\___|",
]
BANNER = "\n".join(f"  {ln}" for ln in WORDMARK)


def _box(*lines: str, pad: str = "  ") -> str:
    """Builds a box-drawing frame sized to its own longest line, so it can never go out of alignment."""
    width = max(len(ln) for ln in lines) + 2
    top, bottom = f"{pad}┌{'─' * width}┐", f"{pad}└{'─' * width}┘"
    middle = "\n".join(f"{pad}│ {ln.ljust(width - 1)}│" for ln in lines)
    return f"{top}\n{middle}\n{bottom}"


BANNER_PRETTY = _box(*WORDMARK, "", "Android manifest exposure scanner")


def bar(n: int, cap: int = 20) -> str:
    filled = min(cap, n)
    return "█" * filled + "░" * (cap - filled)


class Style:
    def __init__(self, on: bool) -> None:
        self.on = on

    def __call__(self, name: str, text: str) -> str:
        if not self.on:
            return text
        code = CODES.get(name)
        return f"\x1b[{code}m{text}\x1b[0m" if code else text

    def google(self, text: str) -> str:
        if not self.on:
            return text
        out = []
        for i, line in enumerate(text.split("\n")):
            out.append(self(_CYCLE_COLORS[i % len(_CYCLE_COLORS)], line) if line.strip() else line)
        return "\n".join(out)

    def wordmark(self, text: str) -> str:
        """A diagonal, four-colour cycle across every non-space character, the same family identity as
        PhantomTrace's rainbow and RuntimeTrace's own wordmark, in this author's Google-colour palette."""
        if not self.on:
            return text
        out = []
        for row, line in enumerate(text.split("\n")):
            chars = []
            for col, ch in enumerate(line):
                if ch == " ":
                    chars.append(ch)
                    continue
                chars.append(self(_CYCLE_COLORS[(col // 3 + row) % len(_CYCLE_COLORS)], ch))
            out.append("".join(chars))
        return "\n".join(out)


def color_ok(no_color: bool) -> bool:
    return sys.stdout.isatty() and not no_color and "NO_COLOR" not in os.environ


class _Help(argparse.Action):
    """-h / --help: shows the coloured wordmark first when talking to a terminal, same as this author's other tools."""
    def __init__(self, option_strings, dest=argparse.SUPPRESS, default=argparse.SUPPRESS, help=None):
        super().__init__(option_strings, dest=dest, default=default, nargs=0, help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        if sys.stdout.isatty():
            st = Style("NO_COLOR" not in os.environ)
            print(st.wordmark(BANNER) + "\n" + st("dim", f"  v{__version__}  |  Android manifest exposure scanner") + "\n")
        parser.print_help()
        parser.exit()


def find_apks(path: str) -> list[str]:
    if os.path.isfile(path):
        return [path]
    out = []
    for dirpath, _dirs, files in os.walk(path):
        for f in files:
            if f.lower().endswith(".apk"):
                out.append(os.path.join(dirpath, f))
    return sorted(out)


def scan_one(path: str) -> tuple[M.Manifest | None, list[checks.Finding], str]:
    try:
        m = M.load(path)
    except (axml.AxmlError, OSError, ValueError) as e:
        return None, [], str(e)
    return m, checks.scan(m), ""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="manifest-trace", add_help=False, formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "ManifestTrace: does an Android app's manifest leave something reachable that should not be.\n\n"
            "Reads the compiled AndroidManifest.xml directly out of one or more .apk files (no Android SDK, no\n"
            "androguard) and checks for the exact bug class behind CVE-2025-50861 and CVE-2025-50862:\n\n"
            "  exported_without_protection   an activity/service/receiver reachable by any app, no permission\n"
            "  exported_provider_wide_open   a content provider reachable by any app, no read/write permission\n"
            "  allow_backup_enabled          adb backup can pull this app's private data, no root needed\n"
            "  debuggable_true               a debugger or `adb shell run-as` can attach to this app\n"
            "  cleartext_traffic_allowed     this app may send unencrypted HTTP traffic"),
        epilog=(
            "examples:\n"
            "  manifest-trace app.apk                   scan one APK\n"
            "  manifest-trace ./apks/                    scan every .apk found under a folder\n"
            "  manifest-trace app.apk --json              machine-readable output\n"
            "  manifest-trace ./apks/ --html report.html  a shareable report for a whole batch\n"
            "  manifest-trace app.apk --list-checks       every check, its severity and what it means\n"
            "  manifest-trace ./apks/ --pretty             an extra-visual report: a boxed banner and severity bars\n\n"
            "exit codes:  0 clean   1 a finding   2 error\n\n"
            "Static analysis only: this never runs the APK or touches a device. A finding is a lead for a human\n"
            "to confirm, not proof, and confirming real impact needs reading the component's actual code.\n"
            "If you use this to find a real issue in someone else's app, disclose it responsibly (ISO/IEC 29147)\n"
            "to the vendor before anything public; do not mass-scan the Play Store and publish results.\n\n"
            f"Created by {__author__} | MIT licence | {__url__}"))
    ap.add_argument("-h", "--help", action=_Help, help="show this help message and exit")
    ap.add_argument("target", nargs="?", help="an .apk file, or a folder to scan every .apk under")
    ap.add_argument("--json", action="store_true", help="print machine-readable JSON instead of the report")
    ap.add_argument("--html", metavar="FILE", help="also write a self-contained HTML report")
    ap.add_argument("-q", "--quiet", action="store_true", help="print only the verdict per APK")
    ap.add_argument("--no-color", action="store_true", help="disable colour (NO_COLOR is also honoured)")
    ap.add_argument("--list-checks", action="store_true", help="list every check with its severity and meaning, then exit")
    ap.add_argument("--pretty", action="store_true", help="an extra-visual report: a boxed banner and severity bars")
    ap.add_argument("--version", action="version", version=f"manifest-trace {__version__}")
    a = ap.parse_args(argv)

    if a.list_checks:
        for name, why in checks.WHY.items():
            print(f"{name}\n  {why}\n")
        return 0
    if not a.target:
        ap.error("give an .apk file or a folder to scan. Try --help for examples.")

    apks = find_apks(a.target)
    if not apks:
        print(f"Error: no .apk files found at {a.target}", file=sys.stderr)
        return 2

    st = Style(color_ok(a.no_color))
    results = []
    worst_exit = 0
    for path in apks:
        m, fs, err = scan_one(path)
        results.append((path, m, fs, err))
        if err:
            worst_exit = 2
        elif any(f.severity in ("high", "medium") for f in fs):
            worst_exit = max(worst_exit, 1)

    if a.json:
        out = []
        for path, m, fs, err in results:
            if err:
                out.append({"path": path, "error": err})
                continue
            color, msg = checks.verdict(fs)
            out.append({"path": path, "package": m.package, "verdict": msg, "findings": [f.as_dict() for f in fs]})
        print(json_mod.dumps({"version": __version__, "results": out}, indent=2))
    else:
        if not a.quiet:
            if a.pretty:
                print(st.google(BANNER_PRETTY))
            else:
                print(st.wordmark(BANNER))
            print(st("dim", f"  v{__version__}  |  Android manifest exposure scanner"))
            print()
        for path, m, fs, err in results:
            _print_one(path, m, fs, err, st, quiet=a.quiet, many=len(apks) > 1, pretty=a.pretty)
        if a.pretty and not a.quiet and len(apks) > 1:
            _print_batch_bars([f for _p, _m, fs, _e in results for f in fs], st)

    if a.html:
        from .report import html_report
        with open(a.html, "w", encoding="utf-8") as f:
            f.write(html_report(results))
        if not a.quiet and not a.json:
            print(f"\nWrote {a.html}")
    return worst_exit


def _print_one(path: str, m, fs, err: str, st: Style, quiet: bool, many: bool, pretty: bool = False) -> None:
    label = f"{path}" if not m else f"{path}  ({m.package})" if many else path
    if err:
        print(f"  {st('red', '[ERROR]')} {label}: {err}")
        return
    color, msg = checks.verdict(fs)
    if quiet:
        print(f"  {label}: {msg}")
        return
    print(f"  {label}")
    order = {"high": 0, "medium": 1, "low": 2}
    for f in sorted(fs, key=lambda x: order[x.severity]):
        print(f"    {st(SEV_COLOR[f.severity], f'[{f.severity.upper()}]')} {st('bold', f.check)}  {f.message}")
        nxt = checks.next_step(f)
        if nxt:
            print(f"      {st('dim', 'Next:')} {st('dim', nxt)}")
    if pretty:
        counts = {s: sum(x.severity == s for x in fs) for s in ("high", "medium", "low")}
        for s in ("high", "medium", "low"):
            print(f"    {st(SEV_COLOR[s], f'{s:7}')} {st(SEV_COLOR[s], bar(counts[s]))}  {counts[s]}")
    print(f"    {st(color, 'Verdict')}  {msg}\n")


def _print_batch_bars(all_findings: list[checks.Finding], st: Style) -> None:
    counts = {s: sum(f.severity == s for f in all_findings) for s in ("high", "medium", "low")}
    print(f"  {st('bold', 'Across the whole batch')}")
    for s in ("high", "medium", "low"):
        print(f"  {st(SEV_COLOR[s], f'{s:7}')} {st(SEV_COLOR[s], bar(counts[s], 30))}  {counts[s]}")
    print()


if __name__ == "__main__":
    raise SystemExit(main())
