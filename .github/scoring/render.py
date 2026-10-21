#!/usr/bin/env python3
"""Render the leaderboard page from results/*.json.

Usage: python render.py <results-dir> <output.html>
"""

import html
import json
import sys
from pathlib import Path

AREAS = ["Identity", "Data exposure", "Secrets", "Supply chain",
         "Release gate", "Network", "Detection", "Recovery"]


def main() -> int:
    results_dir, out = Path(sys.argv[1]), Path(sys.argv[2])
    rows = []
    for path in sorted(results_dir.glob("*.json")):
        try:
            rows.append(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            continue
    # Highest score first; on a tie, whoever got there first wins.
    rows.sort(key=lambda r: (-int(r.get("score", 0)), r.get("scored_at", "")))

    body = []
    for rank, row in enumerate(rows, start=1):
        dots = "".join(
            f'<span class="dot {"on" if row.get("checks", {}).get(str(i)) else ""}" '
            f'title="{html.escape(AREAS[i - 1]) if row.get("checks", {}).get(str(i)) else "Not yet"}"></span>'
            for i in range(1, 9)
        )
        flag = "" if row.get("build_ok", True) else '<span class="warn">build broken</span>'
        body.append(
            f"<tr><td class='rank'>{rank}</td>"
            f"<td class='team'>{html.escape(str(row.get('team', '?')))} {flag}</td>"
            f"<td class='dots'>{dots}</td>"
            f"<td class='num'>{int(row.get('fixed', 0))}/8</td>"
            f"<td class='num'>{int(row.get('classified', 0))}/8</td>"
            f"<td class='num'>{int(row.get('verdict_points', 0))}/10</td>"
            f"<td class='score'>{int(row.get('score', 0))}</td>"
            f"<td class='when'>{html.escape(str(row.get('scored_at', ''))[11:16])} UTC</td></tr>"
        )
    table = "\n".join(body) or "<tr><td colspan='8' class='empty'>No submissions yet. Push to a team/ branch to get on the board.</td></tr>"

    out.write_text(f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="30">
<title>Insecure Architecture · Leaderboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{{--bg:#E7EDF4;--card:#F7F5F0;--ink:#1E2A3A;--soft:#4A5568;--accent:#3B5BA9;--mint:#A9D6C2;--line:#DEDBD2;--warn:#A8432A}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);font-family:'IBM Plex Sans',Arial,sans-serif}}
main{{max-width:1100px;margin:0 auto;padding:48px 16px}}
.eyebrow{{font-size:13px;font-weight:600;letter-spacing:3px;text-transform:uppercase;color:var(--accent);margin:0 0 8px}}
h1{{font-family:'Space Grotesk',Arial,sans-serif;font-size:clamp(30px,5vw,48px);margin:0 0 8px;letter-spacing:-1px}}
p.sub{{color:var(--soft);margin:0 0 32px}}
.card{{background:var(--card);border-radius:20px;padding:8px 8px;overflow-x:auto}}
table{{width:100%;border-collapse:collapse;min-width:720px}}
th{{text-align:left;font-size:12px;letter-spacing:2px;text-transform:uppercase;color:var(--soft);padding:14px 12px;border-bottom:2px solid var(--line)}}
td{{padding:14px 12px;border-bottom:1px solid var(--line);font-size:16px}}
tr:last-child td{{border-bottom:none}}
.rank{{font-family:'Space Grotesk',Arial,sans-serif;font-weight:600;font-size:20px;width:48px}}
tr:nth-child(1) .rank{{color:var(--accent)}}
.team{{font-weight:600}}
.num,.when{{color:var(--soft);font-variant-numeric:tabular-nums}}
.score{{font-family:'Space Grotesk',Arial,sans-serif;font-weight:600;font-size:22px;text-align:right}}
.dot{{display:inline-block;width:14px;height:14px;border-radius:50%;margin-right:4px;background:#E2E0D8}}
.dot.on{{background:#3E8A6E}}
.warn{{font-size:12px;font-weight:600;color:var(--warn);margin-left:8px}}
.empty{{text-align:center;color:var(--soft);padding:40px}}
footer{{color:var(--soft);font-size:13px;margin-top:20px}}
</style></head>
<body><main>
<p class="eyebrow">Team Challenge · Live</p>
<h1>The Insecure Architecture</h1>
<p class="sub">Eight planted flaws. Green dots are fixes the scorer has confirmed. Refreshes every 30 seconds.</p>
<div class="card"><table>
<thead><tr><th>#</th><th>Team</th><th>Checks</th><th>Fixed</th><th>Classified</th><th>Verdict</th><th style="text-align:right">Score</th><th>Last push</th></tr></thead>
<tbody>
{table}
</tbody></table></div>
<footer>Maximum 130 points: 80 for fixes, 40 for classifications, 10 for the verdict.</footer>
</main></body></html>
""", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
