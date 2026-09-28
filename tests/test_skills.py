"""Tests for the SEP-2640 skills extension.

Two things are being defended, and they are different in kind.

**Correctness against the spec.** Entry shape, digests, the `skill://` scheme,
`skills/list` and `skills/get`, and the per-skill limits hosts must be able to
accept. A host that cannot parse an entry will not report it, so a wrong shape
is a silently missing skill.

**The line between a skill and a control.** A skill is instructions to a model.
If the workflow it teaches were the only place a rule existed, deleting the
directory would remove a control. So the skill may teach the order and point at
the code, and `test_skills.py` asserts it keeps pointing rather than restating.
"""

import pathlib
import tempfile
import unittest

from netverify import MAX_BATCH_ITEMS, MAX_BYTES, MAX_TOTAL_INPUT_BYTES
from server.skills import (
    MAX_SKILL_BYTES,
    MAX_SKILL_RESOURCES,
    SKILL_SCHEME,
    SkillError,
    _name_from_uri,
    load_skills,
    parse_frontmatter,
)

ROOT = pathlib.Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"


class TestTheRealSkillIsWellFormed(unittest.TestCase):
    def setUp(self):
        self.skills = load_skills()

    def test_at_least_one_skill_ships(self):
        self.assertTrue(self.skills, f"no skills found under {SKILLS}")

    def test_the_triage_skill_exists(self):
        self.assertIn("triage-backbone", self.skills)

    def test_entry_shape_matches_sep_2640(self):
        """uri, frontmatter, and a resources array of {uri, digest, size}."""
        for name, skill in self.skills.items():
            with self.subTest(skill=name):
                entry = skill.entry()
                self.assertEqual(set(entry), {"uri", "frontmatter", "resources"})
                self.assertTrue(entry["uri"].startswith(SKILL_SCHEME))
                self.assertIn("name", entry["frontmatter"])
                self.assertIn("description", entry["frontmatter"])
                for resource in entry["resources"]:
                    self.assertEqual(set(resource), {"uri", "digest", "size"}, resource)
                    self.assertTrue(resource["digest"].startswith("sha256:"))
                    self.assertEqual(len(resource["digest"]), len("sha256:") + 64)
                    self.assertIsInstance(resource["size"], int)

    def test_the_manifest_is_listed_in_its_own_resources(self):
        """SEP-2640 counts SKILL.md in the limit and expects it in the array."""
        for name, skill in self.skills.items():
            with self.subTest(skill=name):
                uris = {r["uri"] for r in skill.entry()["resources"]}
                self.assertIn(f"{SKILL_SCHEME}{name}/SKILL.md", uris)

    def test_digest_matches_the_file_on_disk(self):
        """A digest that does not match its bytes is worse than none, because a
        host verifies against it and would trust a mismatch."""
        import hashlib

        for name, skill in self.skills.items():
            entry = next(r for r in skill.entry()["resources"] if r["uri"].endswith("SKILL.md"))
            with self.subTest(skill=name):
                actual = (
                    "sha256:"
                    + hashlib.sha256((skill.directory / "SKILL.md").read_bytes()).hexdigest()
                )
                self.assertEqual(entry["digest"], actual)

    def test_resource_listing_is_stable(self):
        """A host caches the entry; an unstable order means spurious diffs."""
        skill = self.skills["triage-backbone"]
        self.assertEqual([f.uri for f in skill.files()], [f.uri for f in skill.files()])

    def test_description_meets_the_agent_skills_length_limit(self):
        """The spec caps it at 1024 characters; over that, a host may not load
        the skill at all."""
        for name, skill in self.skills.items():
            with self.subTest(skill=name):
                self.assertLessEqual(len(skill.description), 1024)
                self.assertGreater(len(skill.description), 0)

    def test_name_meets_the_agent_skills_naming_rules(self):
        """Lowercase alphanumerics and hyphens, matching the directory."""
        import re

        for name in self.skills:
            with self.subTest(skill=name):
                self.assertLessEqual(len(name), 64)
                self.assertIsNotNone(re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", name))

    def test_within_the_per_skill_limits(self):
        for name, skill in self.skills.items():
            entry = skill.entry()
            with self.subTest(skill=name):
                self.assertLessEqual(len(entry["resources"]), MAX_SKILL_RESOURCES)
                self.assertLessEqual(sum(r["size"] for r in entry["resources"]), MAX_SKILL_BYTES)


def _limit_forms() -> set[str]:
    """How each limit is expected to appear in the skill's prose.

    Derived from the constants rather than hardcoded, so raising a limit without
    updating SKILL.md is what makes the test fail. That is the whole mechanism:
    the skill restates the numbers because a model planning a batch needs them,
    and staleness is caught here rather than prevented by silence.

    KiB where the value divides evenly, because that is how an operator reads a
    size limit; the raw byte count is noise to a human.
    """
    forms = set()
    for value in (MAX_BYTES, MAX_TOTAL_INPUT_BYTES, MAX_BATCH_ITEMS):
        if value >= 1024 and value % 1024 == 0:
            forms.add(f"{value // 1024} KiB")
        else:
            forms.add(str(value))
    return forms


class TestPathTraversalIsRefused(unittest.TestCase):
    """A skill file is addressed by URI, and a URI is caller-supplied.

    Without a containment check, `skill://triage-backbone/../../etc/passwd`
    would read outside the skill directory. The check is on the resolved path,
    not on the string, because string checks are trivially bypassed.
    """

    def setUp(self):
        self.skill = load_skills()["triage-backbone"]

    def test_traversal_out_of_the_skill_is_refused(self):
        for attempt in (
            "../prompts.py",
            "../../etc/passwd",
            "../__init__.py",
            "./../server/app.py",
        ):
            with self.subTest(path=attempt):
                with self.assertRaises(SkillError):
                    self.skill.read(attempt)

    def test_the_real_file_is_still_readable(self):
        """Negative control: the guard must not refuse everything."""
        self.assertIn("triage", self.skill.read("SKILL.md").decode("utf-8"))

    def test_a_missing_file_is_refused_distinctly(self):
        with self.assertRaises(SkillError) as caught:
            self.skill.read("references/NOPE.md")
        self.assertIn("not a file", str(caught.exception))


class TestUriParsing(unittest.TestCase):
    def test_a_full_skill_uri_yields_the_name(self):
        self.assertEqual(_name_from_uri("skill://triage-backbone/SKILL.md"), "triage-backbone")

    def test_a_bare_name_is_accepted(self):
        """SEP-2640 expects a host to be able to hand a model a URI from
        anywhere, so refusing the bare name fails a legitimate call."""
        self.assertEqual(_name_from_uri("triage-backbone"), "triage-backbone")

    def test_a_nested_uri_takes_the_first_segment(self):
        self.assertEqual(_name_from_uri("skill://acme/billing/refunds/SKILL.md"), "acme")


class TestMalformedSkillsAreRefusedLoudly(unittest.TestCase):
    """A half-served catalogue is worse than none.

    A host cannot distinguish a skill that was never written from one that failed
    to load, and that difference matters most when the missing document is the
    one telling a model how to use the server.
    """

    def _write(self, root, name, manifest):
        directory = root / name
        directory.mkdir(parents=True)
        (directory / "SKILL.md").write_text(manifest, encoding="utf-8")
        return directory

    def test_a_missing_frontmatter_fence_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._write(pathlib.Path(tmp), "broken", "# no frontmatter here\n")
            with self.assertRaises(SkillError):
                load_skills(pathlib.Path(tmp))

    def test_an_unclosed_frontmatter_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._write(pathlib.Path(tmp), "broken", "---\nname: broken\ndescription: x\n")
            with self.assertRaises(SkillError):
                load_skills(pathlib.Path(tmp))

    def test_a_name_that_disagrees_with_its_directory_is_refused(self):
        """The spec requires them to match, and a mismatch makes the skill
        addressable by a URI that contradicts its own metadata."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self._write(
                root,
                "directory-name",
                "---\nname: something-else\ndescription: x\n---\nbody\n",
            )
            with self.assertRaises(SkillError) as caught:
                load_skills(root)
            self.assertIn("does not match", str(caught.exception))

    def test_a_missing_description_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self._write(root, "nodesc", "---\nname: nodesc\n---\nbody\n")
            with self.assertRaises(SkillError) as caught:
                load_skills(root)
            self.assertIn("description", str(caught.exception))

    def test_an_empty_directory_is_not_a_skill(self):
        """A directory with no SKILL.md is ignored, not an error - it may be a
        `references/` folder at the top level, and failing would make the skill
        layout unforgiving to extend."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "references").mkdir()
            self.assertEqual(load_skills(root), {})


class TestFrontmatterParserIsPartial(unittest.TestCase):
    """The cases the loud-refusal class above does not cover.

    Kept separate because these are about the *parser* rather than the
    catalogue: a parser that guesses produces a wrong-but-plausible skill, which
    is worse than a refusal.
    """

    def test_splits_frontmatter_from_body(self):
        front, body = parse_frontmatter("---\nname: a\n---\n# Body\n")
        self.assertEqual(front["name"], "a")
        self.assertEqual(body, "# Body\n")

    def test_parses_one_level_of_nesting(self):
        """The Agent Skills spec nests under `metadata:`."""
        front, _ = parse_frontmatter('---\nname: a\nmetadata:\n  version: "1"\n---\nx\n')
        self.assertEqual(front["metadata"], {"version": "1"})

    def test_a_line_that_is_not_a_pair_is_refused(self):
        with self.assertRaises(SkillError):
            parse_frontmatter("---\nname a\n---\nbody\n")

    def test_comments_and_blank_lines_are_skipped(self):
        front, _ = parse_frontmatter("---\n# a comment\n\nname: a\n---\nbody\n")
        self.assertEqual(front, {"name": "a"})


class TestSkillIsNotAControl(unittest.TestCase):
    """The line this feature must not cross.

    A skill teaches a workflow. If the workflow's rules lived only here,
    removing the directory would remove a control. So the skill points at the
    code, and these tests keep it pointing.
    """

    def setUp(self):
        self.body = load_skills()["triage-backbone"].body

    def test_skill_points_at_code_enforcement(self):
        lowered = self.body.lower()
        self.assertIn("enforced", lowered)
        self.assertIn("not by this document", lowered)

    def test_skill_teaches_sanitise_before_verify(self):
        self.assertLess(
            self.body.index("sanitize_device_output"),
            self.body.index("verify_capture"),
        )

    def test_skill_does_not_claim_to_be_the_allowlist(self):
        """It may name the ids, but the allowlist is the registry's job."""
        self.assertNotIn("the allowlist is this document", self.body)

    def test_skill_reports_the_real_limits(self):
        """Stale numbers here would be worse than none: a model planning around
        them would be planning around fiction.

        The forms are derived from the constants, so this fails the day a limit
        is raised and SKILL.md is not updated - which is the drift this whole
        class exists to catch.
        """
        for expected in sorted(_limit_forms()):
            with self.subTest(limit=expected):
                self.assertIn(expected, self.body)

    def test_skill_says_the_code_wins_on_disagreement(self):
        """The two will eventually drift. Saying so here means the loser of that
        drift is unambiguous, rather than whichever a model happens to read
        last."""
        self.assertIn("the code is right", self.body.lower())

    def test_skill_points_at_the_contract_as_the_live_source(self):
        """The numbers above are a convenience; `netverify://contract` is the
        source. A model that needs an exact figure should be sent there."""
        self.assertIn("netverify://contract", self.body)


class TestExtensionSurface(unittest.TestCase):
    def setUp(self):
        try:
            from server.app import build_server
        except ImportError:  # pragma: no cover - only when mcp is absent
            self.skipTest("the mcp SDK is not installed")
        self.server = build_server()

    def _capabilities(self):
        return self.server._lowlevel_server.get_capabilities()  # noqa: SLF001

    def test_extension_is_advertised(self):
        """A skill nobody can discover is a file, not a feature."""
        extensions = getattr(self._capabilities(), "extensions", {}) or {}
        self.assertIn("io.modelcontextprotocol/skills", extensions)

    def test_directory_read_is_not_advertised(self):
        """This server does not implement it, and advertising a capability that
        404s is worse than not advertising it."""
        settings = self._capabilities().extensions["io.modelcontextprotocol/skills"]
        self.assertFalse(settings["directoryRead"])

    def test_skill_file_is_readable_as_a_resource(self):
        import asyncio

        listed = [str(r.uri) for r in asyncio.run(self.server.list_resources())]
        self.assertIn("skill://triage-backbone/SKILL.md", listed)

    def test_skill_file_serves_as_text_not_base64(self):
        """A bytes-returning resource becomes a blob, so a host would get base64
        for a file whose mime type says markdown."""
        import asyncio

        contents = list(asyncio.run(self.server.read_resource("skill://triage-backbone/SKILL.md")))
        content = contents[0].content
        self.assertIsInstance(content, str, "skill served as a blob, not as text")
        self.assertIn("triage-backbone", content)

    def test_extension_answers_list_and_get(self):
        import asyncio

        extension = self.server._extensions[0]  # noqa: SLF001
        listing = asyncio.run(extension.list_skills(None, None))
        self.assertEqual(listing["resultType"], "complete")
        self.assertTrue(listing["skills"])

        class Params:
            uri = "skill://triage-backbone/SKILL.md"

        got = asyncio.run(extension.get_skill(None, Params()))
        self.assertEqual(got["skill"]["uri"], "skill://triage-backbone/SKILL.md")

    def test_get_resolves_a_uri_that_was_never_listed(self):
        """SEP-2640 requires this: a host may hand over a URI it never listed."""
        import asyncio

        extension = self.server._extensions[0]  # noqa: SLF001

        class Params:
            uri = "skill://triage-backbone"

        got = asyncio.run(extension.get_skill(None, Params()))
        self.assertEqual(got["skill"]["frontmatter"]["name"], "triage-backbone")

    def test_get_on_an_unknown_skill_names_what_is_available(self):
        import asyncio

        extension = self.server._extensions[0]  # noqa: SLF001

        class Params:
            uri = "skill://nope/SKILL.md"

        with self.assertRaises(SkillError) as caught:
            asyncio.run(extension.get_skill(None, Params()))
        self.assertIn("triage-backbone", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
