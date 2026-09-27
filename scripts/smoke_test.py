#!/usr/bin/env python3
"""End-to-end smoke test over the real MCP protocol.

The unit tests call the tool as a Python function, which cannot catch a broken
server: a bad tool registration, a schema the client cannot use, or a transport
that never starts would all pass. This script speaks actual MCP to the server
over an in-memory transport and asserts the three things a client depends on:

  1. the server starts and lists tools
  2. it lists exactly one, and it is the read-only verifier
  3. calling it returns a real verdict, and an out-of-scope call is refused

Exit codes: 0 pass, 1 fail.
"""

from __future__ import annotations

import asyncio
import pathlib
import sys

# Running `python scripts/smoke_test.py` puts scripts/ on sys.path, not the
# repository root, so the import below would fail without this.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from mcp.shared.memory import create_connected_server_and_client_session as connect  # noqa: E402

from server import mcp_server  # noqa: E402
from tests import fixtures as fx  # noqa: E402

EXPECTED_TOOL = "verify_network_output"


async def main() -> int:
    failures: list[str] = []

    server = mcp_server.build_server()
    async with connect(server._mcp_server) as client:
        listed = await client.list_tools()
        names = [tool.name for tool in listed.tools]

        if names != [EXPECTED_TOOL]:
            failures.append(f"expected exactly [{EXPECTED_TOOL!r}], got {names}")

        schema = listed.tools[0].inputSchema.get("properties", {})
        for required in ("command", "output"):
            if required not in schema:
                failures.append(f"tool schema is missing the {required!r} argument")

        healthy = await client.call_tool(
            EXPECTED_TOOL,
            {
                "command": "srl_interface_brief",
                "output": fx.SRL_INTERFACE_UP,
                "interface": "ethernet-1/1",
            },
        )
        if healthy.isError:
            failures.append(f"a valid call was refused: {healthy.content}")
        elif "ok" not in str(healthy.content[0].text):
            failures.append(f"verdict shape not recognisable: {healthy.content}")

        hostile = await client.call_tool(EXPECTED_TOOL, {"command": "configure", "output": "text"})
        if not hostile.isError:
            failures.append("an out-of-scope command was NOT refused")

    if failures:
        print("SMOKE TEST FAILED", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print("SMOKE TEST OK: server started, 1 tool listed, valid call verified,")
    print("               out-of-scope call refused.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
