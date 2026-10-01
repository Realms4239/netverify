<!--
Keep the subject a sentence: what changed, and why it had to.
The body carries the evidence - gate output, not intention.
-->

**What changed, and why**

**Which gates ran** (all must pass before review; all are offline)

```sh
python -m unittest discover -s tests -t .
python evals/run_evals.py
python scripts/smoke_test.py
python scripts/stdio_check.py
python scripts/check_upstream_parity.py
ruff check . && ruff format --check .
bandit -q -r netverify server -ll -x netverify/parsers
```

**Contract check**

If this touches the MCP surface (tool names, arguments, schemas, resource
URIs), `tests/test_contract.py` is updated in this commit.

- [ ] Gates green (paste the tail of the run below if anything failed and you
      want help reading it)
- [ ] No new network dependencies; tests stay offline
- [ ] Docs updated where behaviour changed (README / demo/README / DESIGN)
