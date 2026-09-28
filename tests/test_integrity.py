"""Tests for `self_check`, the module that describes all the others.

This file exists because `netverify/integrity.py` claimed it did. The module
docstring and two inline comments asserted that "`test_integrity.py` asserts the
two versions agree" and that the test suite pins the commit - and there was no
such file. A comment citing a test that does not exist is worse than no
comment: it reads as a guarantee, and the guarantee was never made.

Covered here: the duplicated strings that could silently drift (version,
pinned commit), and the guarantees - specifically that the ones which *can* be
computed at runtime actually are, because a claim that cannot fail is a caption
rather than a control.
"""

import json
import pathlib
import unittest

import netverify
from netverify import self_check
from netverify.integrity import (
    ALLOWED_OPTIONAL,
    CREDENTIAL_CAPABLE,
    NETWORK_CAPABLE,
    PINNED_COMMIT,
    UPSTREAM_PATH,
    UPSTREAM_REPO,
    imported_roots,
)
from netverify.integrity import (
    __version__ as INTEGRITY_VERSION,
)

ROOT = pathlib.Path(__file__).resolve().parents[1]


class TestDuplicationCannotDrift(unittest.TestCase):
    def test_version_strings_agree(self):
        """`integrity.py` cannot import `__init__`, so the version is duplicated.

        Duplication without a test is just two versions waiting to disagree.
        """
        self.assertEqual(INTEGRITY_VERSION, netverify.__version__)

    def test_pinned_commit_matches_the_parity_script(self):
        """The script owns the pin; this module reports it. They must agree."""
        script = (ROOT / "scripts" / "check_upstream_parity.py").read_text(encoding="utf-8")
        self.assertIn(PINNED_COMMIT, script)

    def test_pinned_commit_matches_the_parity_test(self):
        test = (ROOT / "tests" / "test_vendor_parity.py").read_text(encoding="utf-8")
        self.assertIn(PINNED_COMMIT, test)

    def test_version_matches_the_packaging_metadata(self):
        """A released package reporting a different version to the one it was
        published under is a support problem that surfaces much later."""
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn(f'version = "{INTEGRITY_VERSION}"', pyproject)

    def test_server_reports_the_same_version(self):
        """A fourth copy of the version string, and the one a client actually
        sees. `serverInfo.version` is what a host displays and what a support
        thread quotes, so it is the worst place for it to drift - and it had,
        at 1.0.0 against a library at 1.2.0.
        """
        from server.app import SERVER_VERSION

        self.assertEqual(SERVER_VERSION, INTEGRITY_VERSION)

    def test_no_other_version_string_in_the_tree_disagrees(self):
        """Belt and braces over the whole tree.

        Pinning each copy individually is how a *new* copy gets added and
        forgotten. This walks the Python sources and fails on any project
        version declaration that is not the agreed one, so a new copy has to be
        accounted for rather than quietly drifting.
        """
        disagreeing: list[str] = []
        for path in sorted(ROOT.rglob("*.py")):
            if "__pycache__" in path.parts or ".git" in path.parts:
                continue
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                stripped = line.strip()
                if not stripped.startswith(("__version__ =", "SERVER_VERSION =")):
                    continue
                if '"' not in stripped:
                    continue
                value = stripped.split('"')[1]
                if value != INTEGRITY_VERSION:
                    disagreeing.append(f"{path.relative_to(ROOT)}: {value}")
        self.assertEqual(disagreeing, [], f"version drift: {disagreeing}")


class TestComputedGuarantees(unittest.TestCase):
    """The claims that can be checked offline, are.

    The point of splitting `declared` from `verified` is that this class can
    fail - which the previous shape could not.
    """

    def setUp(self):
        self.report = self_check()
        self.verified = self.report["guarantees"]["verified"]

    def test_no_network_module_is_imported_anywhere_in_the_package(self):
        self.assertEqual(self.report["guarantees"]["network_modules_found"], [])
        self.assertTrue(self.verified["no_network_module_imported"])

    def test_no_credential_module_is_imported(self):
        self.assertEqual(self.report["guarantees"]["credential_modules_found"], [])
        self.assertTrue(self.verified["no_credential_module_imported"])

    def test_no_third_party_module_is_imported(self):
        self.assertEqual(self.report["guarantees"]["third_party_modules_found"], [])
        self.assertTrue(self.verified["no_third_party_module_imported"])

    def test_the_static_scan_actually_sees_imports(self):
        """Negative control on the scanner itself.

        An import scanner that finds nothing because it is broken would report a
        clean bill of health forever. So assert it finds what the package really
        does import, which is a non-empty set.
        """
        roots = imported_roots()
        self.assertTrue(roots, "the scanner found no imports at all")
        for expected in ("re", "json", "pathlib"):
            with self.subTest(module=expected):
                self.assertIn(expected, roots)

    def test_the_network_list_is_not_vacuous(self):
        """A guard over an empty list always passes, so pin what it must catch."""
        for module in ("socket", "paramiko", "requests"):
            with self.subTest(module=module):
                self.assertIn(module, NETWORK_CAPABLE)
        for module in ("getpass", "subprocess"):
            with self.subTest(module=module):
                self.assertIn(module, CREDENTIAL_CAPABLE)

    def test_optional_instrumentation_is_not_a_dependency(self):
        """opentelemetry is imported defensively; its presence must not read as a
        runtime dependency, or the zero-dependency claim turns false the moment
        tracing is switched on."""
        self.assertIn("opentelemetry", ALLOWED_OPTIONAL)

    def test_live_guards_all_hold(self):
        for name in (
            "mutating_command_refused",
            "raw_cli_string_refused",
            "known_secret_masked",
        ):
            with self.subTest(guard=name):
                self.assertTrue(self.verified[name], f"{name} does not hold")


class TestReportedLimitsAreTheRealOnes(unittest.TestCase):
    """A limit a caller cannot see is a limit they cannot plan around."""

    def setUp(self):
        self.limits = self_check()["limits"]

    def test_reports_every_limit_in_force(self):
        for key in (
            "max_output_bytes",
            "max_batch_items",
            "max_total_input_bytes",
            "call_deadline_seconds",
        ):
            with self.subTest(limit=key):
                self.assertIn(key, self.limits)

    def test_the_numbers_match_the_constants(self):
        self.assertEqual(self.limits["max_output_bytes"], netverify.MAX_BYTES)
        self.assertEqual(self.limits["max_batch_items"], netverify.MAX_BATCH_ITEMS)
        self.assertEqual(self.limits["max_total_input_bytes"], netverify.MAX_TOTAL_INPUT_BYTES)

    def test_the_deadline_is_described_without_overclaiming(self):
        """It is enforced, and it cannot preempt. Saying only the first half
        would be the kind of claim this audit exists to catch."""
        self.assertTrue(self.limits["call_deadline_enforced"])
        self.assertFalse(self.limits["call_deadline_preemptive"])


class TestHonestyAboutTheNetwork(unittest.TestCase):
    def test_parity_is_not_claimed_to_be_verified_locally(self):
        """It needs the network, and claiming otherwise would be a green check
        that proves nothing."""
        vendored = self_check()["vendored_parser"]
        self.assertFalse(vendored["parity_verified_here"])
        self.assertEqual(vendored["pinned_commit"], PINNED_COMMIT)
        self.assertEqual(vendored["repo"], UPSTREAM_REPO)
        self.assertEqual(vendored["path"], UPSTREAM_PATH)

    def test_the_vendored_digest_is_reported(self):
        vendored = self_check()["vendored_parser"]
        self.assertTrue(vendored["present"])
        self.assertEqual(len(vendored["sha256"]), 64)

    def test_report_is_json_serialisable(self):
        """It is returned over MCP, so it has to survive the wire."""
        json.dumps(self_check())


if __name__ == "__main__":
    unittest.main()
