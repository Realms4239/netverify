#!/usr/bin/env python3
"""Command line interface: verify a pasted command's output, offline.

The MCP server is the interesting surface, but it is not the *only* audience.
A network engineer with a `show` output in a text file and no AI tooling
installed still needs to know whether a link is healthy - and that person cannot
use a protocol they have never heard of. The library is the product; this is the
door into it.

Deliberately small and dependency-free. It reads stdin or a file and prints
either human-readable text or JSON. Exit codes are meaningful, because this is
meant to be usable from a shell script, and distinguishing them is the point:

    0  every check passed
    1  a check failed - the network has a fault
    2  the request was refused, or the input could not be read
    3  the output could not be parsed, so the network state is unknown

`set -e` around this must not treat "this link is down" (1) and "I typed the
command wrong" (2) as the same event, and must not treat "I pasted the wrong
slice of output" (3) as a fault either.

Examples:
    netverify verify --command srl_interface_brief --interface ethernet-1/1 \\
        --file interface.txt
    cat out.txt | netverify verify --command ping --scan
    netverify health --compare before.json after.json
    netverify commands
    netverify self-check
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from netverify import (  # noqa: E402
    ScopeError,
    compare_states,
    describe_all,
    sanitize,
    self_check,
    synthesize_health,
    verify,
    verify_many,
)

EXIT_OK = 0
EXIT_FAILED_CHECK = 1
EXIT_REFUSED = 2
#: A verdict that could not be formed at all - an unparseable capture, not a
#: network fault. Distinct so a script does not page someone for a paste error.
EXIT_INDETERMINATE = 3


def _read(path: str | None) -> str:
    """Read the output to check, from a file or stdin.

    Refuses stdin when it is a TTY: an engineer who forgot the filename would
    otherwise sit watching a hang with no explanation.
    """
    if path:
        return pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    if sys.stdin.isatty():
        raise ScopeError(
            "no input. Pass --file PATH, or pipe the output in: "
            "cat out.txt | netverify verify --command ..."
        )
    return sys.stdin.read()


def _emit(payload: Any, as_json: bool, lines: list[str]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True) if as_json else "\n".join(lines))


def _verdict_lines(verdict: Any) -> list[str]:
    mark = "ok  " if verdict.ok else "FAIL"
    lines = [f"{mark}  {verdict.check}  [{verdict.outcome.value}]"]
    lines.extend(f"        {reason}" for reason in verdict.reasons)
    return lines


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        output = _read(args.file)
    except (OSError, ScopeError) as exc:
        print(f"netverify: {exc}", file=sys.stderr)
        return EXIT_REFUSED

    extra: dict[str, Any] = {
        name: getattr(args, name)
        for name in ("interface", "neighbor_router_id", "peer_ip", "remote_as", "prefix")
        if getattr(args, name, None) is not None
    }

    try:
        verdict = verify(args.command, output, audit=None, **extra)
    except ValueError as exc:
        print(f"netverify: refused: {exc}", file=sys.stderr)
        return EXIT_REFUSED

    lines = _verdict_lines(verdict)
    if args.scan:
        # Report untrusted content in the same pass. Cheap, and it means an
        # operator reading a verdict also learns the output was trying something.
        findings = sanitize(output).findings
        if findings:
            lines.append("")
            lines.append("untrusted content found in the supplied output:")
            lines.extend(f"  {f.severity:8s} {f.kind} - {f.detail}" for f in findings)
    _emit(verdict.to_dict(), args.json, lines)

    if verdict.outcome.value == "input_error":
        return EXIT_INDETERMINATE
    return EXIT_OK if verdict.ok else EXIT_FAILED_CHECK


def cmd_health(args: argparse.Namespace) -> int:
    try:
        before = json.loads(pathlib.Path(args.before).read_text(encoding="utf-8"))
        after = json.loads(pathlib.Path(args.after).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"netverify: {exc}", file=sys.stderr)
        return EXIT_REFUSED

    if args.compare:
        results = compare_states(verify_many(before, audit=None), verify_many(after, audit=None))
        lines = [f"REGRESSED  {r['check']}  ({r['change']})" for r in results["regressions"]]
        lines += [f"recovered  {r['check']}" for r in results["recoveries"]]
        lines += [f"removed    {r['check']}" for r in results["removed"]]
        if not results["regressions"]:
            lines.append(f"no regressions; {results['unchanged']} unchanged")
        _emit(results, args.json, lines)
        return EXIT_OK if not results["regressions"] else EXIT_FAILED_CHECK

    health = synthesize_health(verify_many(after, audit=None))
    lines = [
        f"status: {health['status']}",
        f"  checked {health['checked']}  passed {health['passed']}  "
        f"failed {health['failed']}  unreadable {health['input_errors']}",
    ]
    if health["worst"]:
        lines.append(f"  worst: {health['worst']['check']}")
    _emit(health, args.json, lines)
    return {
        "healthy": EXIT_OK,
        "unhealthy": EXIT_FAILED_CHECK,
        "indeterminate": EXIT_INDETERMINATE,
        "partially_checked": EXIT_INDETERMINATE,
    }[health["status"]]


def cmd_selfcheck(args: argparse.Namespace) -> int:
    report = self_check()
    lines = [
        f"netverify {report['server']['version']}  (MCP {report['server']['protocol_revision']})",
        f"  commands            {report['commands']['count']}",
        f"  secret patterns     {len(report['detection']['secret_patterns'])}",
        f"  injection patterns  {len(report['detection']['injection_patterns'])}",
        f"  max output          {report['limits']['max_output_bytes']} bytes",
        f"  vendored parser     {report['vendored_parser']['pinned_commit'][:7]} "
        f"({report['vendored_parser']['bytes']} bytes)",
        f"  tracing             {report['telemetry']['exporter'] or 'off'}",
        "  guards:",
    ]
    lines += [
        f"    {'ok  ' if held else 'FAIL'} {name}"
        for name, held in sorted(report["guards_verified"].items())
    ]
    _emit(report, args.json, lines)
    # A server whose own guards do not hold is not fit to answer with, so the
    # exit code reports that rather than always being zero.
    return EXIT_OK if all(report["guards_verified"].values()) else EXIT_FAILED_CHECK


def cmd_commands(args: argparse.Namespace) -> int:
    entries = describe_all()
    lines: list[str] = []
    for entry in entries:
        lines += [
            entry["id"],
            f"    cli      {entry['command']}",
            f"    platform {entry['platform']}",
            f"    requires {', '.join(entry['required_arguments']) or '-'}",
            f"    checks   {entry['summary']}",
        ]
    _emit(entries, args.json, lines)
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netverify",
        description=(
            "Verify ISP backbone device output. Read-only, offline, no "
            "credentials. The same library the MCP server uses."
        ),
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    sub = parser.add_subparsers(dest="command", required=True)

    one = sub.add_parser("verify", help="verify one command's output")
    one.add_argument("--command", required=True, help="command id; see `commands`")
    one.add_argument("--file", help="read from PATH instead of stdin")
    one.add_argument("--interface")
    one.add_argument("--neighbor-router-id", dest="neighbor_router_id")
    one.add_argument("--peer-ip", dest="peer_ip")
    one.add_argument("--remote-as", dest="remote_as")
    one.add_argument("--prefix")
    one.add_argument(
        "--scan",
        action="store_true",
        help="also report secrets and prompt injection found in the output",
    )
    one.set_defaults(func=cmd_verify)

    health = sub.add_parser("health", help="summarise a capture, or diff two")
    health.add_argument("before", help="earlier capture: JSON list of entries")
    health.add_argument("after", help="later capture: JSON list of entries")
    health.add_argument(
        "--compare",
        action="store_true",
        help="report what changed instead of summarising the later capture",
    )
    health.set_defaults(func=cmd_health)

    commands = sub.add_parser("commands", help="list the allowlisted commands")
    commands.set_defaults(func=cmd_commands)

    check = sub.add_parser("self-check", help="verify this installation's guards")
    check.set_defaults(func=cmd_selfcheck)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
