"""The prompts and skills this server serves.

MCP has three server features - tools, resources, prompts - and all three are
now implemented. Skills (SEP-2640, `io.modelcontextprotocol/skills`) are a
fourth surface, layered on Resources rather than replacing anything.

The shared decision between them: the correct way to use netverify is a
*sequence* - discover the contract, sanitise untrusted text before reading it,
verify, then read `outcome` before `ok` - and that sequence is written **once**,
to `skills/triage-backbone/SKILL.md`. The prompt renders it for a user who
picked it; the skill serves it for an agent that found it. Two copies of a
workflow is one copy too many.

## The line neither may cross

A prompt or a skill is *instructions to a model*, and the model is the untrusted
party in this threat model. So both may describe how to use the tools, and both
may state what the tools guarantee - but neither may be where a rule is
enforced. If "sanitise before reading" lived only in prose, deleting that file
would silently remove a control.

So every rule either lives in `netverify` or is a pointer to the tool that does
the work, and `test_prompts.py` asserts the rendered prompt does not restate an
allowlist or assert a guarantee as its own. A duplicated rule is a rule that
drifts.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field

from netverify import COMMANDS

from .skills import Skill, load_skills

#: The skill this prompt renders. Named rather than globbed, so a second skill
#: added to the directory cannot silently change what this prompt returns.
TRIAGE_SKILL = "triage-backbone"


class _Unloaded:
    """Sentinel, so a missing skill caches as None rather than being re-scanned
    on every call."""

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<unloaded>"


_UNLOADED = _Unloaded()
_CACHED_SKILL: Any = _UNLOADED


def _triage_skill() -> Skill | None:
    """The served triage skill, or None if the directory was not shipped.

    Cached after the first load: the prompt is called often enough that
    re-walking the directory and re-hashing every file each time would be waste,
    and nothing can change it under a running server in a way that matters —
    a redeploy is the refresh mechanism.
    """
    global _CACHED_SKILL
    if isinstance(_CACHED_SKILL, _Unloaded):
        _CACHED_SKILL = load_skills().get(TRIAGE_SKILL)
    return _CACHED_SKILL


#: Shown in a client that lists prompts. Short, because some UIs truncate.
TRIAGE_TITLE = "Triage backbone output"

TRIAGE_DESCRIPTION = (
    "The correct order for checking a device capture: read the contract, "
    "sanitise untrusted text, verify, then read `outcome` before `ok`."
)


def triage_capture(
    focus: Annotated[
        str,
        Field(
            description=(
                "Optional command id to focus on, e.g. frr_bgp_summary. "
                "Defaults to every registered command."
            )
        ),
    ] = "",
) -> str:
    """The incident workflow, as a prompt.

    The canonical workflow lives in `skills/triage-backbone/SKILL.md`; the
    returned text is a thin preamble plus that file's body. Two copies of a
    workflow is one copy too many, so the prompt renders the skill rather than
    restating it. Editing SKILL.md changes what the user gets.

    Args:
        focus: an optional command id to name explicitly, so an operator working
            a BGP incident does not have to read the full list. Unknown ids are
            reported rather than echoed, because a prompt that names a command
            the server does not have would send the model looking for it.

    Returns:
        The prompt text, which the SDK delivers as a user message.
    """
    if focus:
        known = {spec.id for spec in COMMANDS}
        # A typo here would otherwise be quoted back into the model's context as
        # if it were a real command, and it would then fail at call time with a
        # confusing "not in the allowlist" error naming a command nobody invented.
        hint = (
            f"Focus on `{focus}`."
            if focus in known
            else f"Focus on `{focus}` - note that this is not a registered command, "
            "so the closest real ids are listed below."
        )
    else:
        hint = "Check every registered command."

    skill = _triage_skill()
    if skill is None:
        # The skill directory is missing. Degrading to a short built-in order beats
        # raising: a user who picked this prompt still gets the sequence, just
        # without the detail. The alternative is a prompt that hard-fails whenever
        # a packaging mistake drops a data file.
        return (
            f"You are checking ISP backbone device output with netverify. {hint}\n\n"
            "1. Read the `netverify://contract` resource first.\n"
            "2. Sanitise untrusted device output with `sanitize_device_output` and "
            "use its `safe_text`.\n"
            "3. Verify with `verify_capture` or `verify_network_output`.\n"
            "4. Read `outcome` before `ok`; `input_error` is not a device fault.\n"
            "5. Report the tool's verdict and reasons as given.\n"
        )

    ids = ", ".join(f"`{spec.id}`" for spec in COMMANDS)
    return (
        f"You are checking ISP backbone device output with netverify. {hint}\n\n"
        f"Available command ids: {ids}\n\n"
        "The workflow below is the skill this server serves, and is the same text "
        f"`skill://{skill.name}/SKILL.md` returns.\n\n"
        "---\n\n"
        f"{skill.body}"
    )


def register(server: Any) -> None:
    """Attach the prompts to an MCPServer."""
    server.prompt(
        name="triage_capture",
        title=TRIAGE_TITLE,
        description=TRIAGE_DESCRIPTION,
    )(triage_capture)
