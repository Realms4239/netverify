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

import ast
import asyncio
import json
import pathlib
import re
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

    def test_the_registry_manifest_declares_the_same_version(self):
        """`server.json` is what an MCP registry reads to list this server, so a
        stale version there is the one a user sees before installing anything.

        This was 1.0.0 against a library at 1.2.0, and the tree-walk below missed
        it because it only ever looked at `*.py`. The manifest is a *published*
        version claim, so it is pinned here by name as well as by the sweep.
        """
        manifest = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["version"], INTEGRITY_VERSION)
        for package in manifest["packages"]:
            with self.subTest(package=package["identifier"]):
                self.assertEqual(package["version"], INTEGRITY_VERSION)

    def test_no_other_version_string_in_the_tree_disagrees(self):
        """Belt and braces over the whole tree.

        Pinning each copy individually is how a *new* copy gets added and
        forgotten. This walks the project and fails on any version declaration
        that is not the agreed one, so a new copy has to be accounted for rather
        than quietly drifting.

        Deliberately not Python-only. The original sweep globbed `*.py`, which
        meant `server.json` - a real, user-facing version claim - was invisible
        to it. Any file that declares a version in the project's own style is
        now in scope, and a file that looks like a declaration but disagrees is
        reported by path so the fix is obvious.
        """
        disagreeing: list[str] = []
        for path in sorted(ROOT.rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts or ".git" in path.parts:
                continue
            if path.suffix not in {".py", ".json", ".toml"}:
                continue
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                stripped = line.strip()
                if path.suffix == ".py":
                    if not stripped.startswith(("__version__ =", "SERVER_VERSION =")):
                        continue
                elif path.suffix == ".json":
                    # The manifest declares the server version twice - once at the
                    # top, once per package - and the registry reads both.
                    if '"version"' not in stripped:
                        continue
                elif not stripped.startswith("version"):
                    continue
                # Extract the value with a regex per format, rather than by
                # splitting on quotes and guessing which run is the value. JSON
                # is `"version": "1.2.0",` - the value is whatever follows the
                # colon, and a trailing comma means it is not simply the last
                # quoted run. Python and TOML are `version = "1.2.0"`, where the
                # value is the first quoted run. Guessing produced the key, then
                # a comma, before this got it right.
                pattern = r':\s*"([^"]+)"' if path.suffix == ".json" else r'"([^"]+)"'
                found = re.search(pattern, stripped)
                if not found:
                    continue
                value = found.group(1)
                if value != INTEGRITY_VERSION:
                    disagreeing.append(f"{path.relative_to(ROOT)}: {value}")
        self.assertEqual(disagreeing, [], f"version drift: {disagreeing}")


class TestTheReadmeDoesNotDrift(unittest.TestCase):
    """The README is the first thing anyone reads, and it states numbers.

    The same defect as a stale version string, in the place with the most
    readers: `server.json` said 1.0.0 against a library at 1.2.0, and the README
    said "35 declarative cases" in one place and "38" in another while the real
    number was 38. A number nobody checks is a number that is wrong by the time
    anyone relies on it.
    """

    def setUp(self):
        self.readme = (ROOT / "README.md").read_text(encoding="utf-8")

    def test_the_eval_case_count_is_accurate_and_stated_once(self):
        """Counts the cases on disk, and requires the README to agree.

        Also fails on the README contradicting *itself*, which is how the 35/38
        split survived: both numbers were plausible and nothing compared them.
        """
        total = 0
        for case in sorted((ROOT / "evals" / "cases").glob("*.json")):
            data = json.loads(case.read_text(encoding="utf-8"))
            total += len(data if isinstance(data, list) else data.get("cases", []))
        self.assertEqual(
            [n for n in re.findall(r"\b(\d+) declarative cases\b", self.readme)],
            [str(total)],
            f"the README must state {total} eval cases, exactly once",
        )

    def test_the_injection_family_count_is_accurate(self):
        """Counted from the module's own table, not by scraping the source.

        Two earlier attempts at this failed in instructive ways, and both
        failures were the guard doing its job - a number nobody computes is a
        number that is wrong.

        The first scraped the file with a regex requiring `re.compile` on the
        line after the name. Every pattern in the table is formatted that way, so
        it looked right - and it silently skipped the two entries whose `re.compile`
        call is preceded by a long comment block. It reported 8 when the table
        held 9, and the honest response to "the README says Nine but the code
        says Eight" is to check the code, not the prose.

        The second counted both pattern tables together, reporting 12 "injection
        families" when the README's original seven was correct: credentials are
        redacted, injections are neutralised, and counting them as one number
        would have had a correct README "fixed" to a wrong one.

        So this reads the compiled patterns, which is the only source that cannot
        drift from what actually runs.
        """
        import importlib

        module = importlib.import_module("netverify.sanitize")
        families = [name for name, _ in module._INJECTION_PATTERNS]
        self.assertEqual(
            len(families),
            len(set(families)),
            "duplicate family name in the injection table",
        )
        word = {
            6: "Six",
            7: "Seven",
            8: "Eight",
            9: "Nine",
            10: "Ten",
            11: "Eleven",
            12: "Twelve",
        }.get(len(families))
        self.assertIsNotNone(
            word, f"the README has no wording for {len(families)} families; update it"
        )
        self.assertIn(f"{word} injection families", self.readme)

    def test_the_tool_count_matches_the_server(self):
        """Seven tools, and the README says so by name and in words."""
        from server.app import build_server  # noqa: PLC0415

        server = build_server()
        tools = asyncio.run(server.list_tools())
        self.assertEqual(len(tools), 7)
        self.assertIn("The seven tools", self.readme)
        for tool in tools:
            with self.subTest(tool=tool.name):
                self.assertIn(tool.name, self.readme)


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


class TestNoTestIsSilentlyDisabled(unittest.TestCase):
    """A test that cannot be collected is not a test, and the suite cannot tell.

    This class exists because two tests in this suite were dead in exactly that
    way. `test_worst_offender_carries_its_own_reason` and
    `test_checker_signature_matches_declared_arguments` were written at the bottom
    of their files with a four-space indent, which put them inside the
    `if __name__ == "__main__":` block below `unittest.main()`. They parsed, they
    imported, they were named like tests, and no runner ever called them: a
    `def test_...` is only a test when it is a method of a TestCase.

    That failure is invisible in the one place everyone looks. The suite stays
    green, the count rises when someone adds a real test, and the invariant the
    dead test named has no guard at all - the same shape as the comment in
    `integrity.py` that cited a test file which did not exist. So the shape is
    checked mechanically rather than remembered.
    """

    def setUp(self):
        self.files = sorted((ROOT / "tests").glob("test_*.py"))
        self.assertGreater(len(self.files), 10, "the sweep found no test files")

    @staticmethod
    def _parents(tree):
        """Yield (node, enclosing statements) for every node in the module."""

        def walk(body, parents):
            for node in body:
                yield node, parents
                for attr in ("body", "orelse", "finalbody", "handlers"):
                    inner = getattr(node, attr, None)
                    if isinstance(inner, list):
                        yield from walk(inner, [*parents, node])

        yield from walk(tree.body, [])

    @classmethod
    def _testcase_names(cls, tree):
        """Every class in the module that is, transitively, a TestCase.

        Transitive because the alternative is not merely incomplete, it is wrong:
        most of the telemetry tests are methods of `TestMetricsAreRecorded`, which
        extends a local `_MetricsCase`, which extends `unittest.TestCase`. A check
        that read only a class's own bases would call those twenty tests dead.
        """
        bases = {
            node.name: [ast.unparse(base).split(".")[-1] for base in node.bases]
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef)
        }

        def is_case(name, seen=frozenset()):
            if name == "TestCase":
                return True
            if name in seen:
                return False
            return any(is_case(base, seen | {name}) for base in bases.get(name, ()))

        return {name for name in bases if is_case(name)}

    def _uncollectable(self, source):
        """Every `def test_*` in `source` no runner can reach, with the reason.

        Takes text, not a path, so the negative control below can be checked
        without being written to disk. It used to be written into `tests/`,
        which put it inside two things that read that directory: discovery
        collected its `test_a_real_one` as a real test (the count rose to 371),
        and this sweep globbed it as a real file. `addCleanup` deleted it -- so
        the bug only appeared when a run was interrupted and the file survived.
        Then every later run failed here, accusing the suite of a defect that
        the guard's own control had introduced. A control that must be cleaned
        up cannot be relied on to be.
        """
        tree = ast.parse(source)
        cases = self._testcase_names(tree)
        found = []
        for node, parents in self._parents(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not node.name.startswith("test"):
                continue
            classes = [p for p in parents if isinstance(p, ast.ClassDef)]
            enclosing = [p for p in parents if isinstance(p, ast.FunctionDef)]
            if enclosing:
                found.append((node, "nested inside a function"))
            elif not classes:
                where = ast.unparse(parents[-1]) if parents else "the module body"
                found.append((node, f"defined outside any class, under {where!r}"))
            elif not any(c.name in cases for c in classes):
                found.append((node, f"defined in {classes[-1].name!r}, not a TestCase"))
        return found

    def test_every_test_definition_is_collectable(self):
        """The sweep, reported per file so a failure names the file."""
        dead = {}
        for path in self.files:
            found = self._uncollectable(path.read_text(encoding="utf-8"))
            if found:
                dead[path.name] = [
                    f"{node.name} (line {node.lineno}): {why}" for node, why in found
                ]
        self.assertEqual(dead, {}, f"tests no runner will ever call: {dead}")

    def test_the_sweep_can_actually_see_a_dead_test(self):
        """Negative control, in the spirit of the import scanner's.

        A walk that finds nothing because it is broken would report a clean suite
        forever, which is the defect above wearing a uniform. So build the exact
        shape that was there - a test indented under `unittest.main()` - and
        require the sweep to catch it.
        """
        broken = (
            "import unittest\n"
            "\n"
            "class Real(unittest.TestCase):\n"
            "    def test_a_real_one(self):\n"
            "        pass\n"
            "\n"
            "if __name__ == '__main__':\n"
            "    unittest.main()\n"
            "\n"
            "    def test_never_called(self):\n"
            "        pass\n"
        )

        found = self._uncollectable(broken)

        self.assertEqual(
            [node.name for node, _ in found],
            ["test_never_called"],
            "the sweep cannot see the defect it exists to catch",
        )

    def test_the_sweep_sees_the_whole_suite(self):
        """Non-vacuity: a sweep that inspects no test functions passes trivially."""
        counted = 0
        for path in self.files:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            counted += sum(
                1
                for node, _ in self._parents(tree)
                if isinstance(node, ast.FunctionDef) and node.name.startswith("test")
            )
        self.assertGreater(
            counted,
            200,
            f"only found {counted} test functions across {len(self.files)} files",
        )


if __name__ == "__main__":
    unittest.main()
