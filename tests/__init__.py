"""Test suite for netverify.

This is a package (rather than a bare directory) so that both runners work from
the repository root with no PYTHONPATH set:

    python -m unittest discover -s tests -t .
    python -m pytest tests

`pytest` also collects these unchanged, which is what CI uses.
"""

import os

# Quieten the audit log before anything imports it. The suite makes thousands of
# calls, and without this a green run is buried under thousands of JSON lines
# that nobody reads - which trains people to ignore stderr entirely, including
# the warnings that matter. Tests that assert on audit behaviour construct their
# own enabled `AuditLog`, so this does not weaken them.
os.environ.setdefault("NETVERIFY_AUDIT", "0")
