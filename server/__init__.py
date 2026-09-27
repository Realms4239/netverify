"""Hardened MCP server for ISP backbone output verification (Project F1).

Layers, in dependency order:

- `scope`  - the closed allowlist and input limits. No third-party imports.
- `verify` - maps one allowlisted command to a verdict, via the vendored
             flagship parsers.
- `vendor` - a byte-identical pinned copy of the flagship's `pyats/parsers.py`,
             with a CI-enforced parity check.
- `mcp_server` - the thin MCP surface. Imports `mcp` lazily.

`scope` and `verify` hold every security property and are importable with no
third-party dependency, which is what lets the whole test suite run offline.
"""

__version__ = "0.1.0"
