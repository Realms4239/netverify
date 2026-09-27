"""Test suite for the hardened MCP verifier.

This is a package (rather than a bare directory) so that both runners work from
the repository root with no PYTHONPATH set:

    python -m unittest discover -s tests -t .
    python -m pytest tests

`pytest` also collects these unchanged, which is what CI uses.
"""
