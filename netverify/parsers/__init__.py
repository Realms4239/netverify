"""Vendored and additional parsers.

`upstream` is a byte-identical copy of the flagship's `pyats/parsers.py`, pinned
to one commit and verified by `scripts/check_upstream_parity.py`. It is
vendored rather than depended on because upstream is not a distributable
package. Nothing in this package may be edited locally: the whole value of a
vendored copy is that it cannot silently diverge from the code that already
passed the flagship's own CI.
"""

