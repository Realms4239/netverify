"""Guards on the vendored flagship parser.

These tests do not need the network. They assert the properties that make the
vendored copy trustworthy *offline*: that it is syntactically valid, that it
still declares the upstream provenance and pinned commit, and that its public
surface is the one `verify.py` depends on.

The live drift check is `scripts/check_upstream_parity.py`, which fetches the
pinned commit and diffs it. That one needs network, so it runs in CI rather
than here. The separation matters: this suite must stay green with no network
at all, which is the same offline-runnable property the flagship insists on.
"""

import ast
import pathlib
import unittest

VENDORED = pathlib.Path(__file__).resolve().parents[1] / "server" / "vendor" / "pyats_parsers.py"

#: Functions `verify.py` imports. If upstream renames or drops one, this fails
#: loudly at test time instead of at the first tool call in production.
EXPECTED_API = {
    "frr_bgp_peers",
    "frr_peer_is_healthy",
    "ping_succeeded",
    "srl_bgp_peer_established",
    "srl_interface_is_up",
    "srl_ospf_neighbor_is_full",
    "srl_route_is_installed",
}


class TestVendoredFile(unittest.TestCase):
    def setUp(self):
        self.text = VENDORED.read_text(encoding="utf-8")

    def test_file_exists_and_compiles(self):
        compile(self.text, str(VENDORED), "exec")

    def test_provenance_header_names_the_source_and_pin(self):
        header = self.text.split('"""')[0]
        self.assertIn("isp-network-as-code", header)
        self.assertIn("pyats/parsers.py", header)
        self.assertIn("71d3398207088ca67a15ddd3132cedfed81bd678", header)
        self.assertIn("DO NOT EDIT", header)

    def test_header_precedes_the_module_docstring(self):
        """The docstring must survive as the docstring, so the header has to be
        comments. This is what keeps the compared region well-defined."""
        module = ast.parse(self.text)
        self.assertIsInstance(module.body[0], ast.Expr)
        self.assertIsInstance(module.body[0].value, ast.Constant)

    def test_expected_public_functions_are_present(self):
        module = ast.parse(self.text)
        defined = {
            node.name
            for node in module.body
            if isinstance(node, ast.FunctionDef) and not node.name.startswith("_")
        }
        self.assertEqual(
            EXPECTED_API - defined,
            set(),
            "vendored parser is missing functions that verify.py imports",
        )

    def test_vendored_module_imports_and_runs(self):
        from server.vendor import pyats_parsers

        self.assertTrue(pyats_parsers.ping_succeeded("3 received, 0% packet loss"))
        self.assertFalse(pyats_parsers.ping_succeeded("100% packet loss"))

    def test_vendored_copy_imports_nothing_third_party(self):
        """Only json and re. A vendored file that grew a dependency would make
        the offline suite stop being offline."""
        module = ast.parse(self.text)
        imported = set()
        for node in ast.walk(module):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertEqual(imported, {"json", "re"})


if __name__ == "__main__":
    unittest.main()
