"""The boundary between "an argument" and "text forged into the verdict".

`_require_text` is the security check that arguments cannot smuggle a line break
into the verdict's `check` and `reasons` fields, where an agent would read it as
a separate finding. It is tested directly, against a field with *no* registry
pattern, so what is under test is the check itself rather than a pattern that
happens to exclude the character.
"""

import unittest

from netverify.errors import REASON_BAD_ARGUMENT, ScopeError
from netverify.scope import _require_text

#: A field with no registry pattern, so a refusal here is this check and not a
#: shape check. Patterns live in a separate dict from the arguments, so an
#: argument added to a CommandSpec without one has only this defence.
PATTERNLESS_FIELD = "no_such_field"

#: Escapes, not literals: a literal ZWSP or bidi override is stripped by most
#: editors and by some file writes, and a test whose inputs were silently altered
#: tests nothing while looking like it does. A probe run caught exactly that.
LINE_BREAKS_AND_ESCAPES = [
    ("LF", "\n"),
    ("CR", "\r"),
    ("TAB", "\t"),
    ("VT", "\v"),
    ("FF", "\f"),
    ("BEL", "\a"),
    ("ESC", "\x1b"),
    ("DEL", "\x7f"),
    ("NEL", "\x85"),
    ("LINE SEPARATOR", "\u2028"),
    ("PARAGRAPH SEPARATOR", "\u2029"),
]

INVISIBLE_FORMATS = [
    ("ZERO WIDTH SPACE", "\u200b"),
    ("ZERO WIDTH JOINER", "\u200d"),
    ("RIGHT-TO-LEFT OVERRIDE", "\u202e"),
    ("LEFT-TO-RIGHT EMBEDDING", "\u202a"),
    ("BOM", "\ufeff"),
    ("SOFT HYPHEN", "\u00ad"),
]


class TestNonPrintableArgumentsAreRefused(unittest.TestCase):
    """The stated rule is "non-printable", so the test asserts the rule.

    The check used to test for `\\r\\n\\t` while its docstring claimed the defence
    was about arguments forging a line in the verdict. A probe found the gap: with
    a patternless field, VT, FF, NEL, U+2028 and U+2029 all passed - every one of
    them a line break to a terminal, a JSON renderer or a Markdown engine. The
    registry patterns hid it, which is the dangerous part: they live in a separate
    dict, so the next patternless argument would have had no defence at all.
    """

    def _refused(self, char: str) -> str:
        with self.assertRaises(ScopeError) as caught:
            _require_text(f"ethernet-1/1{char}tail", PATTERNLESS_FIELD)
        return str(caught.exception)

    def test_every_line_break_and_escape_is_refused(self):
        for name, char in LINE_BREAKS_AND_ESCAPES:
            with self.subTest(char=name):
                self._refused(char)

    def test_the_invisible_format_characters_are_refused(self):
        """Cf: invisible, and the reason the sanitizer hunts them in device output.

        An argument carrying a zero-width space or a bidi override is quoted into
        the verdict, where it renders as nothing while changing what a reader - or
        a model - sees.
        """
        for name, char in INVISIBLE_FORMATS:
            with self.subTest(char=name):
                self._refused(char)

    def _slipped_through(self, codepoint: int) -> bool:
        """True when `_require_text` *accepted* a value carrying this code point.

        Named for the bad outcome rather than the neutral one on purpose: a helper
        called `_accepted` reads as the desirable case, and this test then asserted
        the exact opposite of what it meant to - the five failures it first produced
        were that, not a hole in the check.
        """
        try:
            _require_text(f"a{chr(codepoint)}b", PATTERNLESS_FIELD)
        except ScopeError:
            return False
        return True

    #: Outside the BMP the non-printable code points are few and enumerable, so
    #: they are listed rather than swept. The sweep itself covers the whole BMP.
    SUPPLEMENTARY_NON_PRINTABLE = [
        (0xE0001, "LANGUAGE TAG"),
        (0xE0020, "TAG SPACE"),
        (0xE007F, "CANCEL TAG"),
        (0x1D173, "MUSICAL BEGIN BEAM"),
        (0x1D17A, "MUSICAL END BEAM"),
    ]

    def test_no_non_printable_code_point_survives(self):
        """The sweep, because the point is the rule rather than a list of characters.

        Iterating the Basic Multilingual Plane is what makes this a test of
        `isprintable()` rather than a test of eleven characters somebody
        remembered: every code point Unicode does not consider printable must be
        refused, including the ones nobody thought of.

        The BMP rather than all 0x110000, because the full sweep costs 5.5s - and
        the mutation harness runs this suite fifteen times, so the exhaustive
        version made every gate run a minute and a half slower in exchange for
        covering supplementary format characters, which are listed explicitly
        below instead. Stating the bound beats quietly claiming more than the test
        does.
        """
        accepted = [
            codepoint
            for codepoint in (cp for cp in range(0x10000) if not chr(cp).isprintable())
            if self._slipped_through(codepoint)
        ]
        self.assertEqual(
            accepted,
            [],
            f"{len(accepted)} non-printable BMP code points were accepted, "
            f"first U+{accepted[0]:04X}"
            if accepted
            else "",
        )

    def test_the_non_printable_code_points_outside_the_bmp(self):
        for codepoint, name in self.SUPPLEMENTARY_NON_PRINTABLE:
            with self.subTest(char=name):
                # Asserting the premise as well as the outcome: if a Unicode
                # update made one of these printable, the test should say so
                # rather than quietly stop covering it.
                self.assertFalse(
                    chr(codepoint).isprintable(),
                    f"U+{codepoint:04X} is printable, so it has left this test's scope",
                )
                self.assertFalse(
                    self._slipped_through(codepoint), f"U+{codepoint:04X} was accepted"
                )

    def test_the_refusal_message_cannot_itself_be_a_forged_line(self):
        """The message quotes the value back, so its rendering is part of the defence.

        `repr` escapes every control and separator character, which is what keeps
        the message on one line. If a future Python stopped doing that, the error
        would become the very thing this check exists to prevent - and a test that
        only checked the exception type would still pass.
        """
        breakers = "\n\r\v\f\x85\u2028\u2029"
        for name, char in [("NEL", "\x85"), ("LINE SEPARATOR", "\u2028"), ("VT", "\v")]:
            with self.subTest(char=name):
                message = self._refused(char)
                for breaker in breakers:
                    self.assertNotIn(
                        breaker, message, f"the message for {name} carries a line break"
                    )

    def test_a_plain_space_is_still_trimmed_rather_than_refused(self):
        """The one whitespace case that is a habit, not an attack.

        Trailing whitespace in a JSON argument is a formatting habit; refusing it
        would break callers for no security gain, so the fix has to keep the trim.
        """
        self.assertEqual(_require_text("  ethernet-1/1  ", PATTERNLESS_FIELD), "ethernet-1/1")

    def test_printable_non_ascii_passes_this_check(self):
        """Accented and CJK text is not an attack.

        A *pattern* may still refuse these, and that must not be mistaken for this
        check refusing them: they are different layers, and blurring them is how a
        future edit makes one silently stand in for the other.
        """
        for value in ["ethernet-1/1\u00e9", "\u4ee5\u592a\u7f51", "ethernet-1/1 \u2713"]:
            with self.subTest(value=value):
                try:
                    _require_text(value, PATTERNLESS_FIELD)
                except ScopeError as exc:
                    self.assertNotIn(
                        "control characters",
                        str(exc),
                        f"{value!r} was refused as a control character",
                    )

    def test_the_reason_code_is_the_published_one(self):
        """A refusal that is not counted is a refusal nobody can act on."""
        with self.assertRaises(ScopeError) as caught:
            _require_text("a\u2028b", PATTERNLESS_FIELD)
        self.assertEqual(caught.exception.reason, REASON_BAD_ARGUMENT)


if __name__ == "__main__":
    unittest.main()
