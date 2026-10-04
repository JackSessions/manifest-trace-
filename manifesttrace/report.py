"""A self-contained HTML report, in the same visual family as this author's other DFIR tools: frosted glass
over a night-security backdrop, Google colours, no external assets, no network calls."""
from __future__ import annotations

import html
import time

from . import __url__, __version__
from .checks import verdict

SHIELD_SVG = ('<svg class="shield" viewBox="0 0 48 56" aria-hidden="true"><path d="M24 4 7 10v16c0 12 7 20 17 26" fill="none" stroke="#4285f4" stroke-width="4.6" stroke-linecap="round" stroke-linejoin="round"/>'
              '<path d="M24 4l17 6v16c0 12-7 20-17 26" fill="none" stroke="#34a853" stroke-width="4.6" stroke-linecap="round" stroke-linejoin="round"/>'
              '<path d="M24 42c-5-3-9-7-9-13V21" fill="none" stroke="#fbbc04" stroke-width="4.2" stroke-linecap="round" stroke-linejoin="round"/>'
              '<path d="M15 21l9-3 9 3v8c0 6-4 10-9 13" fill="none" stroke="#ea4335" stroke-width="4.2" stroke-linecap="round" stroke-linejoin="round"/></svg>')

CSS = r"""
:root{color-scheme:dark;--bg:#0f1316;--panel:#171c20;--text:#e8eaed;--mut:#9aa0a6;--cy:#8ab4f8;--am:#fdd663;--red:#f28b82;--grn:#81c995;
--sans:"Google Sans","Space Grotesk",Inter,"Segoe UI",Roboto,system-ui,sans-serif;--mono:"JetBrains Mono","Roboto Mono",ui-monospace,Menlo,monospace}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 var(--sans);position:relative;min-height:100vh}
body::before{content:"";position:fixed;inset:-18%;z-index:-1;filter:blur(24px);background:radial-gradient(34% 34% at 12% 16%,rgba(66,133,244,.28),transparent 70%),radial-gradient(28% 28% at 90% 10%,rgba(234,67,53,.18),transparent 70%),radial-gradient(32% 32% at 82% 90%,rgba(52,168,83,.18),transparent 70%)}
main{max-width:66rem;margin:0 auto;padding:1.8rem 1rem 3rem}
.panel,.head,.stat{background:rgba(23,28,32,.58);backdrop-filter:blur(16px) saturate(1.5);border:1px solid rgba(255,255,255,.09);border-radius:16px}
.head{display:flex;gap:1rem;align-items:center;padding:1.1rem 1.4rem;margin-bottom:1rem}
.shield{width:2.6rem;height:3rem;flex:none}
h1{margin:0;font:700 clamp(1.5rem,4vw,2.1rem) var(--sans);letter-spacing:-.02em;background:linear-gradient(90deg,#4285f4,#ea4335 40%,#fbbc04 70%,#34a853);-webkit-background-clip:text;background-clip:text;color:transparent}
.sub,.meta{color:var(--mut);font-size:13px;margin:.1rem 0 0}.meta{font-family:var(--mono);margin:.4rem 0 1.2rem}
.app{padding:1rem 1.2rem;margin:1rem 0;border-radius:16px}.app h2{font-size:1.05rem;margin:0 0 .2rem}
.verdict{border-left:4px solid var(--grn);border-radius:0 12px 12px 0;padding:.6rem 1rem;margin:.6rem 0;background:rgba(23,28,32,.58)}.verdict.red{border-left-color:var(--red)}.verdict.yellow{border-left-color:var(--am)}.verdict.cyan{border-left-color:var(--cy)}
table{width:100%;border-collapse:collapse;margin-top:.5rem}th,td{text-align:left;padding:.5rem .5rem;border-bottom:1px solid rgba(255,255,255,.08);vertical-align:top}
th{font:600 11px var(--sans);letter-spacing:.06em;color:var(--mut);text-transform:uppercase}
.chip{display:inline-block;border:1px solid var(--c);color:var(--c);border-radius:999px;padding:0 .6rem;font:600 11px var(--sans);text-transform:uppercase}
code{color:var(--am);font-family:var(--mono)}.why{color:var(--mut);font-size:.85rem;margin-top:.25rem}
.next{color:var(--cy);font-size:.85rem;margin-top:.4rem}.next b{color:var(--text)}
footer{margin-top:2rem;color:var(--mut);font-size:.85rem}a{color:var(--cy)}
"""


def html_report(results: list) -> str:
    e = html.escape
    chip = {"high": "#f28b82", "medium": "#fdd663", "low": "#8ab4f8"}
    apps = []
    for path, m, fs, err in results:
        if err:
            apps.append(f'<div class="app panel"><h2>{e(path)}</h2><p>Error: {e(err)}</p></div>')
            continue
        color, msg = verdict(fs)
        rows = "".join(
            f'<tr><td><span class="chip" style="--c:{chip[f.severity]}">{f.severity}</span></td><td><code>{e(f.check)}</code></td>'
            f'<td>{e(f.component)}</td><td>{e(f.message)}<div class="why">{e(f.as_dict()["why"])}</div>'
            + (f'<div class="next"><b>Next:</b> <code>{e(f.as_dict()["next"])}</code></div>' if f.as_dict()["next"] else '')
            + '</td></tr>'
            for f in sorted(fs, key=lambda x: ("high", "medium", "low").index(x.severity)))
        apps.append(f"""<div class="app panel"><h2>{e(path)}</h2><div class="meta">{e(m.package)} | minSdk {m.min_sdk} | targetSdk {m.target_sdk} | {len(m.components)} components</div>
<div class="verdict {color}"><b>Verdict.</b> {e(msg)}</div>
<table><tr><th>Severity</th><th>Check</th><th>Component</th><th>Finding</th></tr>{rows or '<tr><td colspan="4">No findings.</td></tr>'}</table></div>""")
    return f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ManifestTrace report</title><style>{CSS}</style>
<main><div class="head">{SHIELD_SVG}<div><h1>ManifestTrace</h1><div class="sub">Android manifest exposure scan</div></div></div>
<div class="meta">v{__version__} | {len(results)} app(s) scanned | generated {time.strftime('%Y-%m-%d %H:%M:%S')}</div>
{''.join(apps)}
<footer>Created by <a href="{__url__}">Jack Sessions</a> (ManifestTrace v{__version__}, MIT licence). Static analysis only: findings are leads to confirm by hand, not proof. Disclose anything real responsibly (ISO/IEC 29147) before it goes public.</footer></main></html>"""
