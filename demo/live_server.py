#!/usr/bin/env python3
"""The live demonstration server: actual MCP usage, observable, provable.

This is not a mock and not a report. It drives the real netverify MCP server
two ways, and the dashboard renders what comes back:

1. **In-process protocol stack** (`POST /api/call`) - a persistent
   `ClientSession` over the SDK's `InMemoryTransport`, the same session object
   a host holds. Every call is a real JSON-RPC round-trip through the real
   dispatcher; the SDK wraps it in a SERVER span; netverify records its own
   span and its counters. The OpenTelemetry providers from `demo/obs.py` were
   installed before any of it imported, so the telemetry section shows what
   the calls actually recorded.

2. **A real subprocess over a real pipe** (`POST /api/stdio-proof`) - spawns
   `python -m server` exactly the way a host would, sends newline-delimited
   JSON-RPC over stdin, and returns every frame in both directions with its
   latency. This is the defence that the server *really works*: stdout is the
   protocol channel, so a stray print or a handler that never answers is
   visible here by name, frame by frame.

Run:  python demo/live_server.py  (then open the printed URL)

stdlib HTTP; the only imports beyond the tree are `mcp` and `opentelemetry`,
which the venv already carries.
"""

from __future__ import annotations

import asyncio
import json
import pathlib
import queue
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import obs  # noqa: E402  (installs the OTel providers - must precede these)

from server.app import build_server  # noqa: E402

DEMO = pathlib.Path(__file__).resolve().parent
ROOT = DEMO.parent
DASHBOARD = DEMO / "dashboard.html"

PROTOCOL_VERSION = "2026-07-28"
CLIENT_META = {
    "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
    "io.modelcontextprotocol/clientInfo": {"name": "netverify-live-demo", "version": "1.2.0"},
    "io.modelcontextprotocol/clientCapabilities": {},
}

SAMPLES = {}
for name in ("interface-up", "interface-down", "ping-total-loss", "hostile-secret"):
    path = DEMO / "inputs" / f"{name}.txt"
    if path.exists():
        SAMPLES[name] = path.read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# The persistent in-process session, driven from the event-loop thread.
# --------------------------------------------------------------------------
class McpBridge:
    """One ClientSession on a background loop, plus the calls it can make.

    `ClientSession` is not thread-safe and wants its owning loop, so every
    HTTP handler thread hands a coroutine to the loop with
    `run_coroutine_threadsafe` and waits on the future. One session, held for
    the life of the process, is exactly what a host holds.
    """

    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        #: The connect coroutine sets `protocol_version`; assigning a default
        #: *after* the future resolves would clobber it, so it is set first.
        self.protocol_version: str | None = None
        self.ready = asyncio.run_coroutine_threadsafe(self._connect(), self.loop).result(30)

    async def _connect(self) -> None:
        from mcp import ClientSession
        from mcp.client._memory import InMemoryTransport

        transport = InMemoryTransport(build_server())
        self._cm = transport
        streams = await transport.__aenter__()
        client_read, client_write = streams
        self.session = ClientSession(client_read, client_write)
        await self.session.__aenter__()
        init = await self.session.initialize()
        self.protocol_version = init.protocol_version

    def run(self, coro, timeout: float = 30.0):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    def list_tools(self):
        return self.run(self.session.list_tools())

    def list_resources(self):
        return self.run(self.session.list_resources())

    def list_resource_templates(self):
        return self.run(self.session.list_resource_templates())

    def list_prompts(self):
        return self.run(self.session.list_prompts())

    def get_prompt(self, name: str, arguments: dict):
        return self.run(self.session.get_prompt(name, arguments or {}))

    def read_resource(self, uri: str):
        return self.run(self.session.read_resource(uri))

    def call_tool(self, name: str, arguments: dict):
        return self.run(self.session.call_tool(name, arguments or {}))


BRIDGE: McpBridge | None = None


def _tool_brief(tool) -> dict:
    return {
        "name": tool.name,
        "description": tool.description,
        "input_schema": tool.input_schema,
        "output_schema": tool.output_schema,
        "annotations": {
            "read_only_hint": tool.annotations.read_only_hint,
            "destructive_hint": tool.annotations.destructive_hint,
            "idempotent_hint": tool.annotations.idempotent_hint,
        }
        if tool.annotations
        else None,
    }


def bootstrap() -> dict:
    tools = BRIDGE.list_tools()
    resources = BRIDGE.list_resources()
    templates = BRIDGE.list_resource_templates()
    prompts = BRIDGE.list_prompts()
    self_check = BRIDGE.call_tool("self_check", {})
    return {
        "protocol_version": BRIDGE.protocol_version,
        "tools": [_tool_brief(t) for t in tools.tools],
        "resources": [{"uri": str(r.uri), "name": r.name} for r in resources.resources],
        "templates": [{"uri_template": t.uri_template} for t in templates.resource_templates],
        "prompts": [{"name": p.name, "description": p.description} for p in prompts.prompts],
        "self_check": self_check.structured_content,
        "telemetry": obs.telemetry_status(),
        "samples": SAMPLES,
    }


def do_call(kind: str, name: str, arguments: dict) -> dict:
    """One real round-trip, with the spans it produced and the metrics it moved."""
    cursor = obs.reset_span_cursor()
    before_metrics = {
        (m["name"], tuple(sorted(m["attributes"].items()))): m for m in obs.snapshot_metrics()
    }
    t0 = time.perf_counter()
    try:
        if kind == "tool":
            result = BRIDGE.call_tool(name, arguments)
            payload = {
                "is_error": result.is_error,
                "structured": result.structured_content,
                "text": "\n".join(c.text for c in result.content if getattr(c, "text", None)),
            }
        elif kind == "resource":
            result = BRIDGE.read_resource(name)
            payload = {
                "is_error": False,
                "structured": None,
                "text": "\n".join(
                    c.text if isinstance(c.text, str) else "<blob>" for c in result.contents
                ),
            }
        elif kind == "prompt":
            rendered = BRIDGE.get_prompt(name, arguments)
            payload = {
                "is_error": False,
                "structured": None,
                "text": "\n---\n".join(
                    f"{m.role}: {m.content.text}"
                    for m in rendered.messages
                    if getattr(m.content, "text", None)
                ),
            }
        else:
            raise ValueError(f"unknown kind {kind!r}")
    except Exception as exc:  # noqa: BLE001 - a refusal is a result, not a crash
        payload = {
            "is_error": True,
            "structured": None,
            "text": f"{type(exc).__name__}: {exc}",
        }
    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)

    spans, _total = obs.snapshot_spans(cursor)
    after = obs.snapshot_metrics()
    deltas = []
    for m in after:
        key = (m["name"], tuple(sorted(m["attributes"].items())))
        before = before_metrics.get(key)
        if m.get("is_histogram"):
            continue
        old = before["value"] if before else 0
        if m["value"] != old:
            deltas.append({**m, "delta": m["value"] - old})
    return {
        "kind": kind,
        "name": name,
        "arguments": arguments,
        "elapsed_ms": elapsed_ms,
        "result": payload,
        "spans": spans,
        "metric_deltas": deltas,
    }


# --------------------------------------------------------------------------
# The stdio proof: a real process, a real pipe, real frames both directions.
# --------------------------------------------------------------------------
#: Per-step read bound. Generous on purpose: a cold interpreter on Windows can
#: take ~30s to reach its first answer (measured 28.6s once the file cache had
#: been evicted), and a gate that mistakes a slow start for silence reports a
#: working server as a wedged one. Silence *within* this budget is still named.
STEP_TIMEOUT = 90.0


def _frame(message: dict) -> bytes:
    return (json.dumps(message) + "\n").encode()


def _request(message_id: int, method: str, params_extra: dict | None = None) -> bytes:
    params = {"_meta": dict(CLIENT_META)}
    if params_extra:
        params.update(params_extra)
    return _frame({"jsonrpc": "2.0", "id": message_id, "method": method, "params": params})


def stdio_proof() -> dict:
    """Drive `python -m server` over a real pipe and return every frame.

    Each step is: send request, timestamp it, read one line, timestamp the
    response. The frames are returned verbatim - the dashboard shows the wire,
    not a paraphrase of it. Reads are bounded by a per-step timeout so a server
    that answers nothing surfaces as a named, empty read rather than a mystery
    hang, and stderr is drained concurrently so whatever the child said about
    its own death arrives with the report.
    """
    steps = [
        (1, "server/discover", None),
        (2, "tools/list", None),
        (
            3,
            "tools/call",
            {
                "name": "verify_network_output",
                "arguments": {
                    "command": "srl_interface_brief",
                    "output": SAMPLES.get("interface-up", ""),
                    "interface": "ethernet-1/1",
                },
            },
        ),
        (
            4,
            "tools/call",
            {
                "name": "verify_network_output",
                "arguments": {"command": "configure terminal", "output": "anything"},
            },
        ),
        (5, "prompts/list", None),
        (6, "skills/list", None),
    ]
    env = {**__import__("os").environ, "NETVERIFY_AUDIT": "1"}
    process = subprocess.Popen(  # noqa: S603
        [sys.executable, "-m", "server"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=str(ROOT),  # the child resolves `-m server` from its cwd, not ours
    )
    frames: list[dict] = []
    assertions: list[dict] = []

    # stdout and stderr are drained on their own threads, so a slow *start*
    # (a cold interpreter on Windows can take ~30s before the first answer)
    # is a wait, not a false "silence", and a child that dies mid-handshake
    # can be quoted verbatim in the note instead of reported as an empty pipe.
    stdout_q: queue.Queue[bytes | None] = queue.Queue()
    stderr_buf: list[bytes] = []

    def pump_stdout() -> None:
        assert process.stdout
        for line in iter(process.stdout.readline, b""):
            stdout_q.put(line)
        stdout_q.put(None)  # EOF sentinel

    def pump_stderr() -> None:
        assert process.stderr
        for chunk in iter(lambda: process.stderr.read(1) or None, None):
            stderr_buf.append(chunk)

    threading.Thread(target=pump_stdout, daemon=True).start()
    threading.Thread(target=pump_stderr, daemon=True).start()

    def stderr_tail(limit: int = 300) -> str:
        return (b"".join(stderr_buf).decode("utf-8", "replace")[-limit:]).strip()

    try:
        assert process.stdin
        for mid, method, extra in steps:
            process.stdin.write(_request(mid, method, extra))
            process.stdin.flush()
            sent = time.perf_counter()
            try:
                raw = stdout_q.get(timeout=STEP_TIMEOUT)
            except queue.Empty:
                raw = None
            arrived = time.perf_counter()
            frames.append(
                {
                    "id": mid,
                    "method": method,
                    "direction": "out",
                    "raw": json.loads(_request(mid, method, extra).decode()),
                    "t_ms": 0.0,
                }
            )
            if raw is None:
                # Distinguish "the child is gone" (EOF) from "the child is
                # still thinking" (timeout) - a client needs to know which
                # promise was broken, and the stderr tail says why.
                still_running = process.poll() is None
                reason = (
                    "no response within the step timeout - the process is alive but silent"
                    if still_running
                    else "NO RESPONSE - EOF on the protocol channel"
                )
                tail = stderr_tail()
                frames.append(
                    {
                        "id": mid,
                        "method": method,
                        "direction": "in",
                        "raw": None,
                        "note": reason + (f"; server stderr: {tail}" if tail else ""),
                        "t_ms": round((arrived - sent) * 1000, 2),
                    }
                )
                assertions.append({"step": f"{method} (id {mid})", "ok": False, "detail": reason})
                break
            decoded = json.loads(raw.decode("utf-8"))
            frames.append(
                {
                    "id": mid,
                    "method": method,
                    "direction": "in",
                    "raw": decoded,
                    "t_ms": round((arrived - sent) * 1000, 2),
                }
            )
            ok = "error" not in decoded
            detail = "answered" if ok else f"error: {decoded['error'].get('message', '')[:90]}"
            assertions.append({"step": f"{method} (id {mid})", "ok": ok, "detail": detail})
            if method == "tools/call" and mid == 4:
                # A refusal is an *answer*. The assertion is that SOMETHING
                # came back - silence is the failure mode this exists to catch.
                assertions[-1]["detail"] = (
                    "refused - an answer, not silence"
                    if decoded.get("result") is not None or "error" in decoded
                    else "no refusal"
                )
    finally:
        try:
            if process.stdin:
                process.stdin.close()
            process.terminate()
            process.wait(timeout=5)
        except Exception:  # noqa: BLE001
            process.kill()
    return {
        "frames": frames,
        "assertions": assertions,
        "all_answered": all(a["ok"] for a in assertions),
        "protocol_version": PROTOCOL_VERSION,
    }


# --------------------------------------------------------------------------
# stdlib HTTP surface
# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj: dict, code: int = 200) -> None:
        self._send(code, json.dumps(obj, default=str).encode("utf-8"), "application/json")

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        if self.path in ("/", "/index.html"):
            self._send(200, DASHBOARD.read_bytes(), "text/html; charset=utf-8")
        elif self.path == "/favicon.ico":
            # Browsers ask for this unprompted; a 404 here is a console error
            # the dashboard did not cause.
            self._send(204, b"", "image/x-icon")
        elif self.path == "/api/bootstrap":
            try:
                self._json(bootstrap())
            except Exception as exc:  # noqa: BLE001
                self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)
        elif self.path == "/api/telemetry":
            spans, total = obs.snapshot_spans()
            self._json(
                {
                    "spans": spans[-120:],
                    "total_spans": total,
                    "metrics": obs.snapshot_metrics(),
                    "status": obs.telemetry_status(),
                }
            )
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}")
        try:
            if self.path == "/api/call":
                self._json(
                    do_call(
                        body.get("kind", "tool"), body.get("name", ""), body.get("arguments") or {}
                    )
                )
            elif self.path == "/api/stdio-proof":
                self._json(stdio_proof())
            else:
                self._json({"error": "not found"}, 404)
        except Exception as exc:  # noqa: BLE001
            self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)

    def log_message(self, fmt: str, *args) -> None:  # keep stdout quiet
        pass


def main() -> int:
    global BRIDGE
    BRIDGE = McpBridge()
    server = ThreadingHTTPServer(("127.0.0.1", 8765), Handler)
    print("netverify live demo:  http://127.0.0.1:8765")
    print(f"protocol {BRIDGE.protocol_version} · in-memory session up · telemetry live")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
