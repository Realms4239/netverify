# Contributing to netverify

Thanks for wanting to help. This repo has one unusual property worth knowing
before you start: **the gates are the product too.** A change that makes the
code better but the gates weaker is a regression.

## Setup

```sh
git clone https://github.com/Realms4239/netverify.git
cd netverify
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[mcp]" -r requirements-dev.txt
```

Then run the full gate set — all of it is offline and needs no secrets:

```sh
python -m unittest discover -s tests -t .   # 370 tests
python evals/run_evals.py                   # 46 eval cases
python scripts/smoke_test.py                # MCP round trip, in-memory
python scripts/stdio_check.py               # real process, real pipe
python scripts/check_upstream_parity.py     # vendored copy vs pinned upstream
ruff check . && ruff format --check .
bandit -q -r netverify server -ll -x netverify/parsers
```

`scripts/mutation_test.py` (the suite must *fail* on each applied mutant) runs
on the default branch rather than per-PR, because it re-runs everything once
per mutant — but run it locally if you touch `netverify/` core behaviour.

## The rules

1. **New checks are one `CommandSpec`** in `netverify/registry.py`. The
   allowlist, tool schemas, contract resource and verifier all read from that
   list. If your change edits a handler and the allowlist in lockstep, the
   design is being bypassed.
2. **MCP-surface changes update `tests/test_contract.py` in the same commit.**
   Tool names, argument names, output schemas and resource URIs are pinned so
   a rename is a visible diff, not a client that quietly stops working.
3. **No network in tests, ever.** Tests, evals and the smoke gate run with no
   model key and no device. If your change needs a network to be tested, the
   design is wrong for this repo.
4. **Refusals carry stable reason codes.** A new refusal site gets a case in
   `tests/test_refusal_reasons.py`.
5. **`netverify/parsers/upstream.py` is never edited.** It is byte-identical
   to the pinned upstream commit; diverge the copy and the parity gate fails
   on purpose.
6. **Behaviour changes to the live console update the browser suite** in the
   same commit (see `DESIGN.md` — the console's design contract is enforced,
   not assumed).

## Commit messages

Say what changed and why it had to, in the subject; the body carries the
evidence. Look at `git log` for the house style — subjects are sentences, and
"why" outranks "what".

## Reporting issues

Include: the command id involved, the raw device output that triggered it,
the expected verdict and the actual one, and the reason code from the refusal
if there was one. Output text is treated as hostile — please mask real
secrets before pasting; the sanitizer helps but does not replace judgement.
