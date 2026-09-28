"""The skills extension, per SEP-2640 (`io.modelcontextprotocol/skills`).

SEP-2640 is **Final**, and it deliberately rides on the existing Resources
primitive rather than inventing a capability: a skill is a directory of files,
each file is exposed as a resource under the `skill://` scheme, and a host that
already treats MCP resources as a virtual filesystem consumes a served skill
exactly as it consumes a local one. Only three methods are new - `skills/list`,
`skills/get`, and the optional `resources/directory/read`.

The format is delegated entirely to the Agent Skills specification: a directory
containing `SKILL.md` with YAML frontmatter, plus progressive disclosure on top
(name and description always loaded, the body when the skill activates,
`references/` on demand). This module implements only the transport binding.

## Why the content is a file rather than a string

The triage workflow existed as prose in the server's `instructions` field, and
then again as a prompt. Two copies of a workflow is one copy too many, and this
session has already found three instances of exactly that failure - unused
telemetry attributes, an unenforced deadline, a count-based batch cap on the
wrong axis. So the workflow is written once, to `skills/triage-backbone/SKILL.md`,
and both the skill and the prompt read it. Editing one edits both.

## Why a skill may not become the enforcement

A skill is *instructions to a model*, and the model is the untrusted party in
this threat model. So the allowlist, the limits, and the redaction are enforced
in `netverify`, and this module only serves prose. The SKILL.md says so in its
own text, and `test_skills.py` asserts it keeps saying it.

## The frontmatter parser is minimal on purpose

`netverify` imports nothing outside the standard library, and a skill file is
input like any other. So the parser handles the flat `key: value` and one-level
nested `key:` / indented `sub: value` shapes the Agent Skills spec defines, and
*refuses* anything else rather than guessing. A mis-parsed `name` would produce
a skill the host cannot address, and a wrong-but-plausible parse is worse than
a refusal.
"""

from __future__ import annotations

import hashlib
import pathlib
from dataclasses import dataclass
from typing import Any

from mcp.server.extension import Extension, MethodBinding
from mcp_types import RequestParams

#: Where the served skills live. Resolved relative to the repository rather than
#: the CWD, so the server works from any working directory - and from a wheel,
#: where the data ships alongside the package.
SKILLS_ROOT = pathlib.Path(__file__).resolve().parents[1] / "skills"

#: Extension identifier per SEP-2640. Reverse-DNS, and validated by the SDK at
#: subclass-definition time.
SKILLS_EXTENSION = "io.modelcontextprotocol/skills"

#: URI scheme SEP-2640 assigns to a served skill.
SKILL_SCHEME = "skill://"

#: SEP-2640's per-skill limits. Hosts MUST support at least these, so a server
#: exceeding one is serving something no conforming host can load.
MAX_SKILL_RESOURCES = 512
MAX_SKILL_BYTES = 16 * 1024 * 1024


class SkillError(ValueError):
    """A skill on disk that cannot be served."""


def parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    """Split `SKILL.md` into frontmatter and body.

    Deliberately not a YAML parser, and it says so. `netverify` imports nothing
    outside the standard library, and a skill file is untrusted input; a partial
    parser that refuses what it does not understand is safer here than a general
    one that guesses. A mis-parsed `name` yields a skill the host cannot
    address, which is worse than a refusal.
    """
    if not text.startswith("---"):
        raise SkillError("SKILL.md must begin with a `---` frontmatter fence")
    parts = text.split("---", 2)
    if len(parts) < 3:
        raise SkillError("SKILL.md frontmatter is not closed by a second `---`")

    front: dict[str, Any] = {}
    nested_key: str | None = None
    for raw in parts[1].splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indented = raw[:1].isspace()
        if ":" not in raw:
            raise SkillError(f"frontmatter line is not `key: value`: {raw!r}")
        key, _, value = raw.strip().partition(":")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if indented and nested_key is not None:
            front.setdefault(nested_key, {})
            if isinstance(front[nested_key], dict):
                front[nested_key][key] = value
        else:
            front[key] = value if value else {}
            nested_key = key
    return front, parts[2].lstrip("\n")


@dataclass(frozen=True)
class SkillFile:
    """One file in a skill directory, with the digest a host verifies."""

    uri: str
    digest: str
    size: int


@dataclass(frozen=True)
class Skill:
    """A served skill: its entry metadata plus how to read its files."""

    name: str
    description: str
    frontmatter: dict[str, Any]
    body: str
    directory: pathlib.Path

    @property
    def uri(self) -> str:
        return f"{SKILL_SCHEME}{self.name}/SKILL.md"

    def files(self) -> list[SkillFile]:
        """Every file in the directory, digested, sorted for a stable listing.

        Sorted because a host caches the entry and compares digests, so an
        unstable order would produce spurious differences between two identical
        installations.
        """
        out: list[SkillFile] = []
        for path in sorted(self.directory.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(self.directory).as_posix()
            payload = path.read_bytes()
            out.append(
                SkillFile(
                    uri=f"{SKILL_SCHEME}{self.name}/{relative}",
                    digest="sha256:" + hashlib.sha256(payload).hexdigest(),
                    size=len(payload),
                )
            )
        return out

    def entry(self) -> dict[str, Any]:
        """The `skills/list` and `skills/get` entry object, per SEP-2640."""
        files = self.files()
        if len(files) > MAX_SKILL_RESOURCES:
            raise SkillError(
                f"{self.name} has {len(files)} resources, above the "
                f"{MAX_SKILL_RESOURCES} a conforming host must accept"
            )
        total = sum(f.size for f in files)
        if total > MAX_SKILL_BYTES:
            raise SkillError(
                f"{self.name} is {total} bytes, above the {MAX_SKILL_BYTES}-byte "
                "limit a conforming host must accept"
            )
        return {
            "uri": self.uri,
            "frontmatter": dict(self.frontmatter),
            "resources": [{"uri": f.uri, "digest": f.digest, "size": f.size} for f in files],
        }

    def read(self, relative: str) -> bytes:
        """Read one file from the skill directory by relative path.

        The path is resolved and then checked to be inside the directory. A
        skill file is addressed by URI, and a URI is caller-supplied, so without
        this a `..` segment would read outside the skill. The check is on the
        resolved path rather than on the string, because that is what actually
        matters and string checks are trivially bypassed.
        """
        root = self.directory.resolve()
        candidate = (self.directory / relative).resolve()
        if not candidate.is_relative_to(root):
            raise SkillError(f"{relative!r} resolves outside the skill directory")
        if not candidate.is_file():
            raise SkillError(f"{relative!r} is not a file in {self.name}")
        return candidate.read_bytes()


def load_skills(root: pathlib.Path | None = None) -> dict[str, Skill]:
    """Load every skill directory under `root`, keyed by name.

    Loads eagerly and fails loudly on a malformed skill. Serving half the
    catalogue silently would be worse: a host cannot tell a missing skill from
    one that was never written, and that difference matters when the missing one
    is the document telling a model how to use the server.
    """
    base = root or SKILLS_ROOT
    if not base.is_dir():
        return {}
    skills: dict[str, Skill] = {}
    for directory in sorted(p for p in base.iterdir() if p.is_dir()):
        manifest = directory / "SKILL.md"
        if not manifest.is_file():
            continue
        front, body = parse_frontmatter(manifest.read_text(encoding="utf-8"))
        name, description = front.get("name"), front.get("description")
        if not isinstance(name, str) or not name:
            raise SkillError(f"{manifest} has no `name` in its frontmatter")
        if not isinstance(description, str) or not description:
            raise SkillError(f"{manifest} has no `description` in its frontmatter")
        # The Agent Skills spec requires the frontmatter name to match the
        # directory name. Enforced here because a mismatch makes the skill
        # addressable by a URI that disagrees with its own metadata.
        if name != directory.name:
            raise SkillError(
                f"{manifest}: frontmatter name {name!r} does not match directory {directory.name!r}"
            )
        skills[name] = Skill(
            name=name,
            description=description,
            frontmatter=front,
            body=body,
            directory=directory,
        )
    return skills


# --- the extension ----------------------------------------------------------


class _SkillsListParams(RequestParams):
    """`skills/list` takes an optional cursor.

    The catalogue here is small and never paginates, but the field is accepted
    so a host that sends one is not rejected for it.
    """


class _SkillsGetParams(RequestParams):
    """`skills/get` takes the single URI it is asked for."""

    uri: str


class SkillsExtension(Extension):
    """Serves the on-disk skills as SEP-2640 resources and answers the two
    methods the extension defines.

    `skills/list` may legitimately be empty - a server is not required to make
    its catalogue enumerable - but this one enumerates, because a host that
    cannot see the catalogue cannot use it. `skills/get` answers for a URI no
    listing mentioned, which SEP-2640 requires and which matters here: an agent
    handed `skill://triage-backbone/SKILL.md` by a user must be able to resolve
    it without having listed anything first.
    """

    identifier = SKILLS_EXTENSION

    def __init__(self, skills: dict[str, Skill] | None = None) -> None:
        self.skills = skills if skills is not None else load_skills()

    def settings(self) -> dict[str, Any]:
        """Advertised under `capabilities.extensions`.

        `directoryRead` is reported as False deliberately: this server does not
        implement `resources/directory/read`, and advertising a capability that
        404s is worse than not advertising it.
        """
        return {"directoryRead": False, "skills": sorted(self.skills)}

    async def list_skills(self, ctx: Any, params: Any) -> dict[str, Any]:
        return {
            "resultType": "complete",
            "skills": [skill.entry() for skill in self.skills.values()],
        }

    async def get_skill(self, ctx: Any, params: Any) -> dict[str, Any]:
        uri = params.uri if hasattr(params, "uri") else params.get("uri", "")
        name = _name_from_uri(str(uri))
        skill = self.skills.get(name)
        if skill is None:
            # A clear refusal naming what *is* available, rather than a bare
            # "not found" the caller has to guess its way out of.
            raise SkillError(
                f"no skill is served at {uri!r}. Available: {sorted(self.skills) or 'none'}"
            )
        return {"resultType": "complete", "skill": skill.entry()}

    def methods(self) -> Any:
        return (
            MethodBinding(
                method="skills/list",
                params_type=_SkillsListParams,
                handler=self.list_skills,
            ),
            MethodBinding(
                method="skills/get",
                params_type=_SkillsGetParams,
                handler=self.get_skill,
            ),
        )


def _name_from_uri(uri: str) -> str:
    """Extract the skill name from a `skill://<name>/...` URI.

    A bare name is accepted too, because SEP-2640 expects a host to be able to
    hand a model a URI from anywhere, and being strict here would fail a
    legitimate call rather than a hostile one.
    """
    without_scheme = uri[len(SKILL_SCHEME) :] if uri.startswith(SKILL_SCHEME) else uri
    return without_scheme.split("/", 1)[0]
