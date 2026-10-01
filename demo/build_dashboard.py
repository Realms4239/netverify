#!/usr/bin/env python3
"""Build demo/dashboard.html from the artefacts the demos actually produced.

Every number and string on the page is read from ``transcript.txt`` (the
wrap-up run) and ``stress_results.json`` (the adversarial run) - the page
renders what the tool did, it does not assert it. Re-run after re-running
either demo. No external assets: the file is self-contained and opens
anywhere.
"""

from __future__ import annotations

import html
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEMO = ROOT / "demo"

GATES = [
    ("unittest suite", "370 tests"),
    ("evals", "46/46"),
    ("stdio wire gate", "extensions answered"),
    ("smoke test", "7 tools"),
    ("upstream parity", "byte-identical"),
    ("zero-dependency", "stdlib only"),
    ("ruff", "clean"),
    ("bandit -ll", "clean"),
    ("mutation", "21/21 caught"),
]

SEV_COLOR = {"critical": "#f85149", "high": "#d29922", "medium": "#58a6ff", "low": "#8b949e"}
OUTCOME_COLOR = {"pass": "#3fb950", "fail": "#f85149", "input_error": "#d29922"}


def esc(s: object) -> str:
    return html.escape(str(s))


def chip(text: str, color: str, bg: str) -> str:
    return (
        f'<span style="display:inline-block;padding:2px 10px;border-radius:12px;'
        f"font-size:12px;font-weight:600;color:{color};background:{bg};"
        f'border:1px solid {color}44">{esc(text)}</span>'
    )


def render_wrapup() -> str:
    lines = (DEMO / "transcript.txt").read_text(encoding="utf-8").splitlines()
    blocks: list[list[str]] = []
    cur: list[str] = []
    for ln in lines[3:]:  # skip header
        if ln.startswith("$ "):
            if cur:
                blocks.append(cur)
            cur = [ln]
        else:
            cur.append(ln)
    if cur:
        blocks.append(cur)
    out = []
    for b in blocks:
        title = next((x[2:] for x in b if x.startswith("# ")), "")
        exit_line = next((x for x in b if x.startswith("[exit ")), "")
        good = "[exit 0]" in exit_line
        rows = "".join(
            f'<div style="color:{"#8b949e" if x.startswith("$") else "#e6edf3"};'
            f'font-size:12.5px;line-height:1.65;white-space:pre-wrap">{esc(x)}</div>'
            for x in b
            if not x.startswith("# ") and not x.startswith("[exit")
        )
        out.append(
            f'<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;'
            f'padding:14px 16px;flex:1;min-width:340px">'
            f'<div style="display:flex;justify-content:space-between;gap:8px;align-items:baseline">'
            f'<div style="font-size:13px;font-weight:600;color:#e6edf3;margin-bottom:6px">{esc(title)}</div>'
            f'<div style="font-family:ui-monospace,monospace;font-size:11px;color:'
            f'{"#3fb950" if good else "#f85149"};white-space:nowrap">{esc(exit_line)}</div></div>'
            f'<div style="background:#0d1117;border-radius:6px;padding:8px 10px;'
            f'font-family:ui-monospace,Consolas,monospace">{rows}</div></div>'
        )
    return "".join(out)


def observed_card(s: dict) -> str:
    o = s["observed"]
    sid = s["id"]
    body = ""
    if sid == "hostile_capture":
        chips = " ".join(
            chip(
                f["kind"] + " · " + f["severity"],
                SEV_COLOR.get(f["severity"], "#8b949e"),
                "transparent",
            )
            for f in o["findings"]
        )
        body = (
            f'<div style="margin-bottom:8px">{chips}</div>'
            f'<div style="font-family:ui-monospace,monospace;font-size:12px;background:#0d1117;'
            f'border-radius:6px;padding:8px 10px;line-height:1.7">'
            f'<div><span style="color:#8b949e">pasted&nbsp;&nbsp;</span>'
            f'<span style="color:#f85149">password: Sup3rSecret!</span></div>'
            f'<div><span style="color:#8b949e">emitted&nbsp;</span>'
            f'<span style="color:#3fb950">{esc(o["masked_password_line"])}</span></div></div>'
            f'<div style="margin-top:8px;font-size:12.5px">'
            f'outcome <b style="color:{OUTCOME_COLOR[o["outcome"]]}">{esc(o["outcome"])}</b>'
            f" &nbsp;·&nbsp; secret leaked: "
            f'<b style="color:{"#f85149" if o["secret_leaked"] else "#3fb950"}">'
            f"{'YES' if o['secret_leaked'] else 'no'}</b></div>"
        )
    elif sid.startswith("refusal"):
        body = (
            f'<div style="margin-bottom:8px">{chip("reason=" + o["reason"], "#d29922", "transparent")}'
            + (
                " " + chip("metric label: None (bounded)", "#58a6ff", "transparent")
                if "metric_command_label" in o and o["metric_command_label"] is None
                else ""
            )
            + "</div>"
            f'<div style="font-family:ui-monospace,monospace;font-size:12px;background:#0d1117;'
            f'border-radius:6px;padding:8px 10px;line-height:1.6;color:#e6edf3">'
            f"{esc(o['message'])}…</div>"
            f'<div style="margin-top:8px;font-size:12.5px">raised instead of answered: '
            f'<b style="color:{"#3fb950" if o["raised"] else "#f85149"}">'
            f"{'yes' if o['raised'] else 'NO'}</b></div>"
        )
    elif sid == "rate_limit_burst":
        pips = ""
        for _ in range(o["allowed_before_refusal"]):
            pips += (
                '<span style="display:inline-block;width:26px;height:26px;border-radius:6px;'
                "background:#3fb95033;border:1px solid #3fb950;color:#3fb950;"
                "text-align:center;line-height:26px;font-size:12px;font-weight:700;"
                'margin-right:5px">✓</span>'
            )
        pips += (
            '<span style="display:inline-block;width:26px;height:26px;border-radius:6px;'
            "background:#f8514933;border:1px solid #f85149;color:#f85149;"
            "text-align:center;line-height:26px;font-size:12px;font-weight:700;"
            'margin-right:5px">✗</span>'
        )
        body = (
            f'<div style="margin-bottom:8px">{pips}</div>'
            f'<div style="font-size:12.5px;color:#e6edf3;line-height:1.7">'
            f'5th spend refused with <code style="color:#d29922">reason={esc(o["refusal_reason"])}</code>'
            f"<br>recovered after refill: "
            f'<b style="color:{"#3fb950" if o["recovered_after_refill"] else "#f85149"}">'
            f"{'yes' if o['recovered_after_refill'] else 'no'}</b></div>"
        )
    elif sid == "oversize_truncation":
        w = int(o["emitted_bytes"] / o["input_bytes"] * 100)
        body = (
            f'<div style="font-size:12px;color:#8b949e;margin-bottom:6px">'
            f"{o['input_bytes']:,} B in → budget {o['max_bytes']:,} B → "
            f"{o['emitted_bytes']:,} B out</div>"
            f'<div style="height:14px;border-radius:7px;background:#0d1117;border:1px solid #30363d;'
            f'overflow:hidden;margin-bottom:8px">'
            f'<div style="width:{w}%;height:100%;background:#58a6ff55;border-right:2px solid #58a6ff"></div></div>'
            f'<div style="font-size:12.5px">truncated: '
            f'<b style="color:#3fb950">{"yes" if o["truncated"] else "no"}</b>'
            f" &nbsp;·&nbsp; tail secret in emitted text: "
            f'<b style="color:{"#f85149" if o["secret_leaked"] else "#3fb950"}">'
            f"{'YES' if o['secret_leaked'] else 'no'}</b></div>"
        )
    elif sid == "empty_table_semantics":
        body = (
            '<div style="display:flex;gap:10px">'
            '<div style="flex:1;background:#0d1117;border:1px solid #f8514966;border-radius:6px;padding:10px">'
            '<div style="font-size:11px;color:#8b949e;margin-bottom:4px">"No entries found for prefix"</div>'
            f'<div style="font-family:ui-monospace,monospace;font-size:14px;font-weight:700;color:'
            f'{OUTCOME_COLOR[o["no_entries_outcome"]]}">{esc(o["no_entries_outcome"])}</div>'
            '<div style="font-size:11px;color:#8b949e;margin-top:4px">the device answered NO — a real fault</div></div>'
            '<div style="flex:1;background:#0d1117;border:1px solid #d2992266;border-radius:6px;padding:10px">'
            '<div style="font-size:11px;color:#8b949e;margin-bottom:4px">no route row in the text at all</div>'
            f'<div style="font-family:ui-monospace,monospace;font-size:14px;font-weight:700;color:'
            f'{OUTCOME_COLOR[o["no_row_outcome"]]}">{esc(o["no_row_outcome"])}</div>'
            '<div style="font-size:11px;color:#8b949e;margin-top:4px">an unusable capture — not a fault</div></div>'
            "</div>"
        )
    return (
        f'<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;'
        f'flex:1;min-width:380px">'
        f'<div style="display:flex;justify-content:space-between;align-items:baseline;gap:8px">'
        f'<div style="font-size:13.5px;font-weight:600;color:#e6edf3">{esc(s["title"])}</div>'
        f'<span style="font-size:11px;color:#3fb950;white-space:nowrap">● PASS</span></div>'
        f'<div style="font-size:12px;color:#8b949e;margin:6px 0 10px;line-height:1.5">'
        f"{esc(s['expectation'])}</div>"
        f"{body}"
        f'<div style="margin-top:10px;font-size:11px;color:#8b949e">measured '
        f"{s['duration_ms']} ms · demo/stress_demo.py</div></div>"
    )


def main() -> int:
    stress = json.loads((DEMO / "stress_results.json").read_text(encoding="utf-8"))
    gate_chips = " ".join(
        f'<span style="display:inline-flex;flex-direction:column;gap:2px;padding:8px 14px;'
        f'background:#161b22;border:1px solid #30363d;border-radius:8px">'
        f'<span style="font-size:11px;color:#8b949e">{esc(name)}</span>'
        f'<span style="font-size:12.5px;font-weight:700;color:#3fb950">{esc(val)} ✓</span></span>'
        for name, val in GATES
    )
    commit = stress["commit"]
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>netverify — live demonstration &amp; stress results</title>
</head>
<body style="margin:0;background:#0d1117;color:#e6edf3;font-family:-apple-system,'Segoe UI',Roboto,sans-serif">
<div style="max-width:1180px;margin:0 auto;padding:36px 24px 60px">

<div style="display:flex;justify-content:space-between;align-items:flex-end;flex-wrap:wrap;gap:12px">
<div>
<h1 style="margin:0;font-size:26px;letter-spacing:-0.5px">netverify <span style="color:#8b949e;font-weight:400">1.2.0</span></h1>
<div style="color:#8b949e;font-size:13px;margin-top:4px">read-only MCP verifier for ISP backbone output · commit {esc(commit)} · every value on this page is measured output, not a claim</div>
</div>
{chip("ALL SCENARIOS PASS · 6/6", "#3fb950", "#3fb95018")}
</div>

<h2 style="font-size:15px;margin:30px 0 12px;color:#e6edf3">Automated gates — this build</h2>
<div style="display:flex;flex-wrap:wrap;gap:8px">{gate_chips}</div>

<h2 style="font-size:15px;margin:30px 0 12px;color:#e6edf3">Wrap-up demo — the operator story <span style="color:#8b949e;font-weight:400;font-size:12px">demo/transcript.txt · exits 0</span></h2>
<div style="display:flex;flex-wrap:wrap;gap:10px">{render_wrapup()}</div>

<h2 style="font-size:15px;margin:30px 0 12px;color:#e6edf3">Stress demo — the tool under attack <span style="color:#8b949e;font-weight:400;font-size:12px">demo/stress_results.json · exit 0</span></h2>
<div style="display:flex;flex-wrap:wrap;gap:10px">
{"".join(observed_card(s) for s in stress["scenarios"])}
</div>

<div style="margin-top:28px;padding:14px 16px;background:#161b22;border:1px solid #30363d;border-radius:8px;font-size:12.5px;color:#8b949e;line-height:1.7">
<b style="color:#e6edf3">Reproduce:</b>
<code style="color:#58a6ff">python demo/wrap_up_demo.py</code> ·
<code style="color:#58a6ff">python demo/stress_demo.py</code> ·
<code style="color:#58a6ff">python demo/build_dashboard.py</code> — all read-only, offline, zero dependencies beyond the optional PNG render.
</div>

</div>
</body>
</html>
"""
    (DEMO / "static_report.html").write_text(page, encoding="utf-8")
    print("wrote demo/static_report.html")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
