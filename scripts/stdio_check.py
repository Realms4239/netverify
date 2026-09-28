#!/usr/bin/env python3
"""Spawn the real stdio server and speak MCP to it over a pipe.

The in-memory smoke test cannot catch the most common way an MCP server breaks:
printing something to stdout. On the stdio transport stdout *is* the protocol
channel, so one stray print - a debug line, a library banner, a warning that
somebody forgot to redirect - corrupts the message stream and the client drops
the connection with an unhelpful JSON parse error. Nothing about an in-process
test would notice.

So this launches the actual process, sends real JSON-RPC, and asserts three
things:

1. the server answers `server/discover` and advertises 2026-07-28
2. `tools/list` returns the four tools, each annotated read-only
3. every byte the server wrote to stdout parses as JSON-RPC. This is the real
   assertion; the rest is context.

The 2026-07-28 revision removed the `initialize` handshake, so there is no
handshake to perform - the protocol version travels in `_meta` on every request,
which is exactly what this script does.

Exit codes: 0 pass, 1 fail.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

PROTOCOL_VERSION = "2026-07-28"
ROOT = pathlib.Path(__file__).resolve().parents[1]

#: The client identity the 2026-07-28 revision expects on every request, in
#: `_meta`. Version negotiation moved out of the `initialize` handshake and into
#: per-request metadata, so a server that only understands the old handshake
#: will not answer at all.
CLIENT_META = {
    "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
    "io.modelcontextprotocol/clientInfo": {
        "name": "netverify-stdio-check",
        "version": "0.0.0",
    },
    "io.modelcontextprotocol/clientCapabilities": {},
}


def _frame(message: dict) -> bytes:
    """One JSON-RPC message, newline-delimited, as the stdio transport expects."""
    return (json.dumps(message) + "\n").encode()


def _request(message_id: int, method: str) -> bytes:
    return _frame(
        {
            "jsonrpc": "2.0",
            "id": message_id,
            "method": method,
            "params": {"_meta": dict(CLIENT_META)},
        }
    )


def main() -> int:
    failures: list[str] = []

    # Binary pipes, deliberately. On the stdio transport stdout *is* the
    # protocol channel, so any text-mode newline translation or stray print
    # corrupts the stream - and on Windows, text-mode pipes mangle the framing
    # in ways a developer machine would show and a Linux CI runner would not.
    process = subprocess.Popen(  # noqa: S603
        [sys.executable, "-m", "server"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        # stderr is piped, not discarded, so this script can assert that audit
        # records really are written - and, more usefully, that they carry the
        # id of the request that caused them. A control nobody checks is a
        # control that quietly stopped working.
        stderr=subprocess.PIPE,
        # Pinned rather than inherited: this script asserts audit lines are
        # written, so it must not silently pass on a machine where auditing was
        # turned off, nor fail confusingly on one where it was turned on.
        env={**os.environ, "NETVERIFY_AUDIT": "1"},
        cwd=str(ROOT),
    )

    try:
        assert process.stdin and process.stdout

        process.stdin.write(_request(1, "server/discover"))
        process.stdin.flush()
        first = process.stdout.readline()

        if not first:
            failures.append("server produced no response to server/discover")
        else:
            try:
                discover = json.loads(first.decode("utf-8"))
            except json.JSONDecodeError:
                # The stdout-pollution failure mode, caught by name.
                failures.append(
                    f"stdout carried non-JSON, so the protocol is corrupted: {first[:200]!r}"
                )
            else:
                versions = discover.get("result", {}).get("supportedVersions", [])
                if PROTOCOL_VERSION not in versions:
                    failures.append(f"server does not advertise {PROTOCOL_VERSION}: {versions}")

        process.stdin.write(_request(2, "tools/list"))
        process.stdin.flush()
        second = process.stdout.readline()

        try:
            tools = json.loads(second.decode("utf-8"))["result"]["tools"]
        except (json.JSONDecodeError, KeyError, IndexError, UnicodeDecodeError) as exc:
            failures.append(f"tools/list did not return a tool list: {exc}")
        else:
            names = {t["name"] for t in tools}
            expected = {
                # Single-command verification, and the two that harden its input.
                "verify_network_output",
                "sanitize_device_output",
                "audit_device_output",
                # Batch and aggregate reasoning: the operator workflows.
                "verify_capture",
                "synthesize_health",
                "compare_captures",
                # Self-description, so a caller can check its claims.
                "self_check",
            }
            if names != expected:
                failures.append(f"expected {sorted(expected)}, got {sorted(names)}")
            for tool in tools:
                annotations = tool.get("annotations") or {}
                if not annotations.get("readOnlyHint"):
                    failures.append(f"{tool['name']} is not annotated read-only")
        # The prompt has to survive the real wire too. A prompt that renders
        # in-process but 404s over a pipe is invisible in every client, and
        # prompts/list is the only way a user discovers it. Asked before the
        # tools/call below, which closes stdin and lets the server exit.
        process.stdin.write(_request(3, "prompts/list"))
        process.stdin.flush()
        prompts_line = process.stdout.readline()
        try:
            prompt_names = {
                p["name"] for p in json.loads(prompts_line.decode("utf-8"))["result"]["prompts"]
            }
        except (json.JSONDecodeError, KeyError, IndexError, UnicodeDecodeError) as exc:
            failures.append(f"prompts/list did not return prompts: {exc}")
        else:
            if prompt_names != {"triage_capture"}:
                failures.append(f"expected prompts ['triage_capture'], got {sorted(prompt_names)}")

        # The real proof that audit correlation works end to end, and it has to
        # live here rather than in a unit test. `MCPServer.call_tool()` is the
        # in-process entry point and does NOT run the middleware chain; only the
        # request dispatcher does. A test using it would pass happily while the
        # real path stayed uncorrelated, which is the exact bug worth catching.
        process.stdin.write(
            _frame(
                {
                    "jsonrpc": "2.0",
                    "id": 77,
                    "method": "tools/call",
                    "params": {
                        "_meta": dict(CLIENT_META),
                        "name": "verify_network_output",
                        "arguments": {
                            "command": "srl_interface_brief",
                            "output": "| ethernet-1/1 | enable | up |",
                            "interface": "ethernet-1/1",
                        },
                    },
                }
            )
        )
        process.stdin.flush()
        third = process.stdout.readline()
        if not third:
            failures.append("tools/call produced no response")
        else:
            # Close stdin so the server exits on its own; terminating it here
            # would truncate the audit stream this assertion reads.
            process.stdin.close()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:  # pragma: no cover
                process.terminate()
            audit = (process.stderr.read() or b"").decode("utf-8", "replace")
            entries = [
                json.loads(line) for line in audit.splitlines() if line.strip().startswith("{")
            ]
            if not entries:
                failures.append(
                    "the tool call wrote no audit lines to stderr; audit logging "
                    "is a control, and a silently broken one is worse than none"
                )
            elif not all(e.get("request_id") == "77" for e in entries):
                failures.append(f"audit lines are not correlated to request 77: {entries}")

    except BrokenPipeError:
        failures.append("the server closed stdout before answering; it likely crashed")
    finally:
        process.stdin and process.stdin.close()
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover
            process.kill()

    if failures:
        print("STDIO CHECK FAILED", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print("STDIO CHECK OK")
    print(f"  server/discover advertised {PROTOCOL_VERSION} over a real pipe")
    print(f"  tools/list returned {len(expected)} read-only tools, stdout stayed pure JSON-RPC")
    print("  a real tools/call was correlated to its request id in the audit log")
    print("  prompts/list returned the triage workflow over the wire")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
