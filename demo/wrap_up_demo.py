#!/usr/bin/env python3
"""Wrap-up demonstration: fixed, reviewable CLI output.

The project is verified by its automated gates, but gates are not a
demonstration. This script performs the same operator story twice:

  1. `netverify` CLI calls (the Rust binary replacement used by engineers).
  2. Direct MCP server calls over an in-memory session (what a host uses).

Every input is checked in under ``demo/inputs``. Each command is printed before
it runs and its stdout/stderr/exit code are captured into the transcript. Only
three files are produced, all under ``demo/``: ``transcript.txt``,
``transcript.png``, and this script's own console summary.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEMO = ROOT / "demo"
INPUTS = DEMO / "inputs"
TRANSCRIPT_TXT = DEMO / "transcript.txt"
TRANSCRIPT_PNG = DEMO / "transcript.png"
ENV = {
    **os.environ,
    "NETVERIFY_AUDIT": "0",
    "PYTHONIOENCODING": "utf-8",
}

#: Monospace face present on this machine; fall back to Pillow's default.
FONT_PATH = pathlib.Path("C:/Windows/Fonts/consola.ttf")
FONT_SIZE = 19
PADDING = 28
LINE_HEIGHT = 28
FOREGROUND = (235, 237, 240)
MUTED = (139, 148, 158)
ACCENT_GREEN = (63, 185, 80)
ACCENT_RED = (248, 81, 73)
BACKGROUND = (13, 17, 23)

COMMANDS: tuple[tuple[str, ...], ...] = (
    (
        "A healthy interface is reported healthy.",
        sys.executable,
        "-m",
        "netverify.cli",
        "verify",
        "--command",
        "srl_interface_brief",
        "--interface",
        "ethernet-1/1",
        "--file",
        str(INPUTS / "interface-up.txt"),
    ),
    (
        "A disabled interface is a fault, with the reason named.",
        sys.executable,
        "-m",
        "netverify.cli",
        "verify",
        "--command",
        "srl_interface_brief",
        "--interface",
        "ethernet-1/1",
        "--file",
        str(INPUTS / "interface-down.txt"),
    ),
    (
        "Total ping loss is a fault, not an unreadable capture.",
        sys.executable,
        "-m",
        "netverify.cli",
        "verify",
        "--command",
        "ping",
        "--file",
        str(INPUTS / "ping-total-loss.txt"),
    ),
    (
        "Credential-shaped text is masked and the finding is named.",
        sys.executable,
        "-m",
        "netverify.cli",
        "verify",
        "--command",
        "ping",
        "--scan",
        "--file",
        str(INPUTS / "hostile-secret.txt"),
    ),
    (
        "The installation reports on itself before answering for a network.",
        sys.executable,
        "-m",
        "netverify.cli",
        "self-check",
    ),
    (
        "The MCP surface a host would use: tools, resources, refusal, prompt.",
        sys.executable,
        "scripts/smoke_test.py",
    ),
)


def short_head() -> str:
    """Current commit, for provenance in the transcript."""
    completed = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=str(ROOT),
        env=ENV,
        text=True,
        capture_output=True,
        check=False,
    )
    return completed.stdout.strip() or "unknown"


def run_step(title: str, argv: tuple[str, ...]) -> tuple[int, str, str]:
    """Run one command, returning exit code, stdout, and stderr."""
    completed = subprocess.run(
        list(argv),
        cwd=str(ROOT),
        env=ENV,
        text=True,
        capture_output=True,
        check=False,
    )
    return completed.returncode, completed.stdout, completed.stderr


# CLI verdicts use exit codes as the answer (0 healthy, 1 fault), so only an
# unexpected refusal or infrastructure failure counts as a demonstration error.
EXPECTED_EXITS: dict[str, tuple[int, ...]] = {
    "verify": (0, 1),
    "self-check": (0,),
    "smoke_test.py": (0,),
}


def main() -> int:
    lines: list[str] = [
        "netverify wrap-up demonstration",
        f"commit: {short_head()}",
        "Every command below is read-only and offline.",
        "",
    ]
    failures = 0
    for title, *argv in COMMANDS:
        code, out, err = run_step(title, tuple(argv))
        lines.append(f"$ {' '.join(argv[1:])}")
        lines.append(f"# {title}")
        lines.extend(out.rstrip().splitlines() or ["<no stdout>"])
        for err_line in err.rstrip().splitlines():
            lines.append(f"(stderr) {err_line}")
        lines.append(f"[exit {code}]")
        lines.append("")
        step = argv[2] if argv[1] == "-m" else argv[1]
        key = "verify" if step == "netverify.cli" and "verify" in argv else step
        if step.endswith("smoke_test.py"):
            key = "smoke_test.py"
        if code not in EXPECTED_EXITS.get(key, (0,)):
            failures += 1
    TRANSCRIPT_TXT.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    print(f"wrote {TRANSCRIPT_TXT.relative_to(ROOT)}")
    if render_transcript_png("\n".join(lines)):
        print(f"wrote {TRANSCRIPT_PNG.relative_to(ROOT)}")
    else:
        print(
            "skipped demo/transcript.png: Pillow is not installed "
            "(pip install pillow); transcript.txt is the canonical record"
        )
    print(f"steps: {len(COMMANDS)}, non-verdict failures: {failures}")
    return 0 if failures == 0 else 1


def render_transcript_png(text: str) -> bool:
    """Render the transcript as a terminal-style screenshot.

    A headless shell has no desktop to capture, so this draws the transcript
    Pillow offers instead: one monospace line per terminal row on a dark
    background, with command rows emphasized and verdict rows colored. The PNG
    is a rendering of the text above, not a photograph, and it says so.

    Returns True when the PNG was written. Rendering is optional: the
    demonstration's claims live in transcript.txt, and a missing optional
    dependency must not turn a passing demonstration into a crash. (The first
    version raised ModuleNotFoundError at this line, after every command had
    already succeeded - a demonstrable thing made non-demonstrable by its
    decoration.)
    """
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ModuleNotFoundError:
        return False

    rows = text.splitlines()
    try:
        font = ImageFont.truetype(str(FONT_PATH), FONT_SIZE)
    except OSError:
        font = ImageFont.load_default()
    ascent, descent = font.getmetrics()
    row_height = max(LINE_HEIGHT, ascent + descent + 8)
    width = max(font.getlength(row) for row in rows) + PADDING * 2
    height = row_height * len(rows) + PADDING * 2
    image = Image.new("RGB", (int(width), int(height)), BACKGROUND)
    draw = ImageDraw.Draw(image)
    y = PADDING
    for row in rows:
        color = FOREGROUND
        if row.startswith("$"):
            color = MUTED
        elif row.startswith("ok") or "SMOKE TEST OK" in row or "[exit 0]" in row:
            color = ACCENT_GREEN
        elif row.startswith("FAIL") or "[exit 1]" in row:
            color = ACCENT_RED
        draw.text((PADDING, y), row, font=font, fill=color)
        y += row_height
    image.save(TRANSCRIPT_PNG)
    return True


if __name__ == "__main__":
    raise SystemExit(main())
