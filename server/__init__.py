"""MCP adapter over the `netverify` library.

Nothing in this package makes a decision. It translates protocol calls into
library calls and back. All policy - the command allowlist, the verdicts, the
sanitisation, the work limits - lives in `netverify`, which is importable and
testable with no MCP installed.

`app.py`       the MCPServer: tools, annotations, resources, prompt, middleware
`prompts.py`   the triage workflow, as a user-invocable prompt
`__main__.py`  `python -m server`

The version is not declared here on purpose. It is stated once in
`netverify.__version__` and once in `app.SERVER_VERSION` - the two a client can
actually observe - and `tests/test_integrity.py` walks the tree to assert every
copy agrees. This file previously carried a third copy that had drifted to
0.1.0 while the library was at 1.2.0.
"""
