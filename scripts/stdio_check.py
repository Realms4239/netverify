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
2. `tools/list` returns the seven tools, each annotated read-only
3. every byte the server wrote to stdout parses as JSON-RPC. This is the real
   assertion; the rest is context.

That list has since grown, and every addition is one that could not have been
written from an in-process test: the prompt, the skill resource, the progress
notifications, the audit correlation, and the two SEP-2640 extension methods. The
skills methods earned their place immediately - the block that asks `skills/get`
for a URI naming no skill found that the server answered with *silence*. An
extension handler that raises anything but `MCPError` produces no response at all
on this transport, so a mistyped skill URI looks to a client exactly like a wedged
server. In-process, the same call raised a clean exception and everything looked
fine, which is the strongest argument yet for having this script.

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
import threading

#: The spec's invalid-params code, imported rather than written out as a literal so
#: this script cannot drift from the SDK's own mapping. Used to assert that a
#: refusal is a *client* error: a host has to be able to tell a mistyped URI from
#: a server fault, and the code is how it does that.
from mcp_types import INVALID_PARAMS

PROTOCOL_VERSION = "2026-07-28"
ROOT = pathlib.Path(__file__).resolve().parents[1]

#: How long to wait for a refusal before deciding the server will never send one.
#: Generous, because the server may be mid-startup on a cold interpreter, but
#: bounded, because "no response at all" is a real failure mode of this extension
#: and a gate that waits forever reports it as a mystery timeout instead.
REFUSAL_TIMEOUT = 15.0

#: Real output from the `ping` checker, inlined rather than imported: this script
#: runs against a *subprocess* server and must not depend on the test tree.
PING_OK = "3 packets transmitted, 3 received, 0% packet loss"

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

        # The skill has to resolve over the real wire too, and specifically as
        # *text*. A resource that returns bytes reaches the host base64-encoded,
        # which is unreadable markdown - and that is invisible to every in-process
        # test, because the SDK coerces based on how the handler returns it.
        process.stdin.write(
            _frame(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "resources/read",
                    "params": {
                        "_meta": dict(CLIENT_META),
                        "uri": "skill://triage-backbone/SKILL.md",
                    },
                }
            )
        )
        process.stdin.flush()
        skill_line = process.stdout.readline()
        try:
            contents = json.loads(skill_line.decode("utf-8"))["result"]["contents"]
            text = contents[0].get("text", "")
        except (json.JSONDecodeError, KeyError, IndexError, UnicodeDecodeError) as exc:
            failures.append(f"resources/read did not return the skill: {exc}")
        else:
            if not text:
                failures.append(
                    "the skill came back with no `text` field, so a host would "
                    "receive base64 for a markdown document"
                )
            elif "sanitize_device_output" not in text:
                failures.append("the served skill lost its sanitise-first instruction")

        # The two SEP-2640 extension methods, over the real pipe. This block
        # exists because the in-process tests were blind to a defect that only
        # appears on the wire: `skills/get` for a URI naming no skill raised a
        # bare `ValueError`, the SDK maps only `MCPError` onto the wire, and the
        # stdio runner's answer to anything else is to log a traceback and write
        # *no response at all*. Over a pipe that is a client hanging until its own
        # timeout, unable to tell a refusal from a wedged server - and it is the
        # one call an agent is most likely to get wrong, because the URI arrives
        # from wherever the user pasted it rather than from our own listing.
        process.stdin.write(_request(5, "skills/list"))
        process.stdin.flush()
        entries: list = []
        try:
            listing = json.loads(process.stdout.readline().decode("utf-8"))["result"]
            entries = listing["skills"]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError, UnicodeDecodeError) as exc:
            failures.append(f"skills/list did not return a catalogue: {exc}")
        else:
            if listing.get("resultType") != "complete":
                failures.append(f"skills/list resultType is {listing.get('resultType')!r}")
            advertised = {e["frontmatter"]["name"] for e in entries}
            if advertised != {"triage-backbone"}:
                failures.append(f"skills/list advertised {sorted(advertised)}")
            for entry in entries:
                # Progressive disclosure: the entry is metadata and digests, not
                # the document. A host handed the body here has loaded the whole
                # skill to decide whether it wants it, which is what the split is
                # meant to avoid.
                if "body" in entry:
                    failures.append(
                        f"the {entry['uri']} entry carries the skill body, so a host "
                        f"loads the document to decide whether it wants it"
                    )
                if not entry.get("resources"):
                    failures.append(f"{entry['uri']} lists no resources, so it is unusable")
                for resource in entry.get("resources", []):
                    digest = str(resource.get("digest", ""))
                    if not digest.startswith("sha256:"):
                        failures.append(f"{resource.get('uri')} has no sha256 digest: {digest!r}")

        # SEP-2640 requires `skills/get` to resolve a URI the caller never listed,
        # because a host may hand a model a URI from anywhere. Asked for the bare
        # name rather than the full path, which is the harder case: the extension
        # has to derive the name from the URI itself.
        process.stdin.write(
            _frame(
                {
                    "jsonrpc": "2.0",
                    "id": 6,
                    "method": "skills/get",
                    "params": {"_meta": dict(CLIENT_META), "uri": "skill://triage-backbone"},
                }
            )
        )
        process.stdin.flush()
        try:
            got = json.loads(process.stdout.readline().decode("utf-8"))["result"]["skill"]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError, UnicodeDecodeError) as exc:
            failures.append(f"skills/get did not resolve an unlisted URI: {exc}")
        else:
            if got.get("frontmatter", {}).get("name") != "triage-backbone":
                failures.append(f"skills/get returned the wrong skill: {got.get('uri')}")
            # The two methods must agree. A host that lists and then gets a
            # different digest for the same file cannot cache anything, and would
            # report the skill as changed on every call.
            if entries and got.get("resources") != entries[0].get("resources"):
                failures.append("skills/get and skills/list disagree about the skill's resources")

        # The refusal, over the wire. Asserted as a *response* carrying an error
        # code because silence is the failure: a bare exception from a handler
        # produces no reply, which a client experiences as a hang.
        process.stdin.write(
            _frame(
                {
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "skills/get",
                    "params": {"_meta": dict(CLIENT_META), "uri": "skill://nope/SKILL.md"},
                }
            )
        )
        process.stdin.flush()
        # Bounded, because silence is the failure this block exists to catch, and
        # a blocking read would turn a caught bug into a *hung gate* - worse than a
        # failing one, since the job would then die on a timeout with no message
        # naming the cause. A watchdog kills the server if it does not answer, so
        # the read returns empty and the assertion below reports it by name.
        watchdog = threading.Timer(REFUSAL_TIMEOUT, process.kill)
        watchdog.start()
        refusal_line = process.stdout.readline()
        watchdog.cancel()
        if not refusal_line:
            failures.append(
                "skills/get for an unknown skill produced NO response; a client would "
                "hang rather than be told, and could not tell that from a wedged server"
            )
        else:
            try:
                refusal = json.loads(refusal_line.decode("utf-8"))
            except json.JSONDecodeError as exc:
                failures.append(f"the refusal was not JSON-RPC: {exc}")
            else:
                error = refusal.get("error")
                if not error:
                    failures.append(f"an unknown skill returned a result, not an error: {refusal}")
                elif error.get("code") != INVALID_PARAMS:
                    failures.append(
                        f"an unknown skill answered {error.get('code')}, not {INVALID_PARAMS}; "
                        f"a host cannot tell a typo from a server fault"
                    )
                elif "triage-backbone" not in str(error.get("message", "")):
                    failures.append(
                        "the refusal does not name what *is* available, so the caller has "
                        f"to guess: {error.get('message')!r}"
                    )

        # And the connection has to survive it. A handler that killed the dispatch
        # loop would pass every assertion above for the requests that came first,
        # so this is asked explicitly: one more ordinary request, after the error.
        process.stdin.write(_request(8, "skills/list"))
        process.stdin.flush()
        survivor = process.stdout.readline()
        try:
            survivors = json.loads(survivor.decode("utf-8"))["result"]["skills"]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError, UnicodeDecodeError) as exc:
            failures.append(
                f"the server stopped answering after a refused skills/get: "
                f"{exc or 'no response at all'}"
            )
        else:
            if not survivors:
                failures.append("skills/list answered after the refusal, but with no catalogue")

        # A refused *tool* call, which until now had never been asked over the
        # wire. The gap matters for the same reason the skills block does, and
        # the reason is not symmetry: `ScopeError` is a `ValueError`, which is
        # exactly the type whose escape already cost `skills/get` its response.
        # Only `ToolError` from `_refuse` stands between a refused command id and
        # a client that waits out its own timeout. In-process that conversion is
        # invisible either way - the test catches the `ScopeError` and passes -
        # so this question can only be asked here.
        process.stdin.write(
            _frame(
                {
                    "jsonrpc": "2.0",
                    "id": 9,
                    "method": "tools/call",
                    "params": {
                        "_meta": dict(CLIENT_META),
                        "name": "verify_network_output",
                        "arguments": {"command": "configure terminal", "output": "anything"},
                    },
                }
            )
        )
        process.stdin.flush()
        tool_watchdog = threading.Timer(REFUSAL_TIMEOUT, process.kill)
        tool_watchdog.start()
        refused_tool = process.stdout.readline()
        tool_watchdog.cancel()
        if not refused_tool:
            failures.append(
                "tools/call for a mutating command produced NO response; a client would "
                "hang rather than be refused, and could not tell that from a wedged server"
            )
        else:
            try:
                answer = json.loads(refused_tool.decode("utf-8"))
            except json.JSONDecodeError as exc:
                failures.append(f"the refused tool call was not JSON-RPC: {exc}")
            else:
                result = answer.get("result") or {}
                if not result.get("isError"):
                    failures.append(
                        "a mutating command id was not reported as a tool error, so the "
                        f"model is given no refusal to correct: {answer}"
                    )
                # The stable reason code, not prose. Grouping by prose is how a
                # dashboard stops matching, and the whole point of `REASON_*` is
                # that a client can branch on it.
                blob = json.dumps(result)
                if "not_in_allowlist" not in blob:
                    failures.append(
                        "the refusal does not carry its stable reason code, so a client "
                        f"cannot tell why it was refused: {blob[:200]!r}"
                    )
                if "configure terminal" in blob and "not in the allowlist" not in blob:
                    # Belt and braces: the refusal must not quote the rejected
                    # command back as though it were accepted.
                    failures.append(f"the refusal reads as an acceptance: {blob[:200]!r}")

        # A refused tool call has to be as survivable as a refused skill: one
        # more ordinary request, after the error.
        process.stdin.write(_request(10, "tools/list"))
        process.stdin.flush()
        after_refusal = process.stdout.readline()
        try:
            still = json.loads(after_refusal.decode("utf-8"))["result"]["tools"]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError, UnicodeDecodeError) as exc:
            failures.append(
                f"the server stopped answering after a refused tools/call: "
                f"{exc or 'no response at all'}"
            )
        else:
            if not still:
                failures.append("tools/list answered after the refusal, but with no tools")

        # A malformed line - not JSON at all - used to reach the session as a
        # parser exception, and the session answered exceptions with silence:
        # every later request hung while the process looked healthy. A log
        # line on the wrong pipe is all it takes. The framing guard
        # (server/framing.py) rewrites such a line into a request the server
        # refuses properly, so this asks the question only the real transport
        # can answer: garbage in, an answer out (id -1 first, then id 11),
        # and the connection still alive.
        process.stdin.write(b"this is not json at all\n")
        process.stdin.flush()
        process.stdin.write(_request(11, "tools/list"))
        process.stdin.flush()
        after_garbage = None
        for _ in range(4):
            line = process.stdout.readline()
            if not line:
                break
            try:
                message = json.loads(line.decode("utf-8", "replace"))
            except json.JSONDecodeError:
                failures.append(f"stdout carried non-JSON after a malformed line: {line[:120]!r}")
                break
            if message.get("id") == 11:
                after_garbage = message
                break
        try:
            survivors = after_garbage["result"]["tools"]
        except (KeyError, IndexError, TypeError) as exc:
            failures.append(
                f"the server never answered tools/list after a malformed line: "
                f"{exc or 'no response at all'} - a client would hang rather than "
                "be told, and could not tell that from a wedged server"
            )
        else:
            if not survivors:
                failures.append("tools/list answered after a malformed line, but with no tools")

        # Progress notifications, over the real wire, with a real token. This has
        # to live here for the same reason the audit correlation below does: the
        # unit tests drive the tool function and the SDK's worker thread, but
        # neither proves a `notifications/progress` message is ever *written to
        # stdout*. A server that computes progress and never sends it looks
        # identical from the inside, and the client sees a silent connection.
        process.stdin.write(
            _frame(
                {
                    "jsonrpc": "2.0",
                    "id": 78,
                    "method": "tools/call",
                    "params": {
                        "_meta": {**CLIENT_META, "progressToken": "batch-1"},
                        "name": "verify_capture",
                        "arguments": {
                            # Real ping text, not a plausible-looking placeholder: a
                            # fixture the checker cannot parse would make this a test
                            # of the fixture rather than of progress.
                            "commands": [
                                {"command": "ping", "output": PING_OK},
                                {"command": "ping", "output": PING_OK},
                                {"command": "ping", "output": PING_OK},
                            ]
                        },
                    },
                }
            )
        )
        process.stdin.flush()

        # Read until the response for this id, collecting the notifications that
        # arrive first. This is also the ordering assertion: the loop only stops
        # at the result, so anything in `progress_seen` provably preceded it. A
        # client rendering "3/3" under an answer that already arrived looks
        # broken, and that is what a fire-and-forget bridge produces.
        progress_seen: list[dict] = []
        batch_result = None
        for _ in range(24):  # bounded: 3 notifications + the response, with slack
            line = process.stdout.readline()
            if not line:
                break
            try:
                message = json.loads(line.decode("utf-8"))
            except json.JSONDecodeError:
                failures.append(f"stdout carried non-JSON during a batch: {line[:200]!r}")
                break
            if message.get("id") == 78:
                batch_result = message
                break
            if message.get("method") == "notifications/progress":
                progress_seen.append(message.get("params") or {})

        if batch_result is None:
            failures.append("verify_capture produced no response when given a progress token")
        elif batch_result.get("result", {}).get("structuredContent", {}).get("ok_count") != 3:
            failures.append(
                "verify_capture did not verify all three entries: "
                f"{batch_result.get('result', {}).get('structuredContent')}"
            )

        if len(progress_seen) != 3:
            failures.append(
                f"expected 3 progress notifications before the result, got {len(progress_seen)}; "
                "a client would see a silent wait"
            )
        for index, params in enumerate(progress_seen, start=1):
            if params.get("progressToken") != "batch-1":
                failures.append(
                    f"progress {index} carried token {params.get('progressToken')!r}, not "
                    "'batch-1'; a client that cannot correlate them ignores every one"
                )
            if params.get("progress") != index:
                failures.append(
                    f"progress {index} reported {params.get('progress')!r}, so the count "
                    "is not tracking the work"
                )

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
            else:
                # Scoped to request 77's own lines, rather than asserting that
                # *every* line is 77's. The previous form passed only because this
                # was the last call before the pipe closed, so what it really
                # asserted was "no other request has run yet" - which a second
                # call breaks without anything being wrong. The property that
                # matters is that each record carries the id of the call that
                # caused it, and that an uncorrelated record is visible.
                mine = [e for e in entries if e.get("request_id") == "77"]
                uncorrelated = [e for e in entries if e.get("request_id") is None]
                # "9" is the refused `tools/call` above. It is expected to write
                # an audit line - a refusal is exactly what an operator wants in
                # the log - so it belongs in the set of ids this script itself
                # issued. Leaving it out made the correlation check fail on its
                # own new request rather than on a real mis-correlation.
                unknown = [e for e in entries if e.get("request_id") not in (None, "9", "77", "78")]
                if not mine:
                    failures.append(f"no audit line carries request_id 77: {entries}")
                if uncorrelated:
                    failures.append(
                        f"an audit line has no request_id, so it cannot be tied to a "
                        f"call: {uncorrelated}"
                    )
                if unknown:
                    failures.append(f"audit lines for an unknown request id: {unknown}")

    # `OSError` rather than `BrokenPipeError` specifically, because a server that
    # has died leaves the pipe in a state Windows reports as `EINVAL` and POSIX
    # reports as `EPIPE`, and a gate that tracebacks instead of printing its
    # failures has thrown away the diagnosis it just collected.
    except OSError:
        failures.append("the server closed stdout before answering; it likely crashed")
    finally:
        # Every step here is best-effort and must not raise. A server that has
        # already died leaves the pipe unusable, and an exception out of `finally`
        # replaces the failure list this script just built with a traceback that
        # says nothing about what was actually wrong.
        try:
            process.stdin and process.stdin.close()
        except OSError:  # pragma: no cover - the pipe is already gone
            pass
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
    print(f"  {len(progress_seen)} progress notifications reached stdout before the result")
    print("  prompts/list returned the triage workflow over the wire")
    print("  resources/read served the skill as text, not base64")
    print("  skills/list returned the catalogue, and skills/get resolved an unlisted URI")
    print(f"  an unknown skill URI was refused with {INVALID_PARAMS}, and the server kept serving")
    print("  a refused tools/call was answered, not left silent, and carried its reason code")
    print("  a malformed (non-JSON) line was answered and the connection kept serving")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
