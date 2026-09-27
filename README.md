# Hardened MCP & Evals — F1

**One read-only MCP tool that verifies ISP backbone device output, with an eval
gate that runs offline.**

This is stage F1 of Project F in the [AIR vault](https://github.com/Realms4239/AIR).
The vault's build order puts this second, immediately after the flagship
(`isp-network-as-code`), and it is the prerequisite for Project B — the
Zero-Trust API Gateway, which the vault ranks #1 of 8 but gates on this
existing first.

## What it does

The flagship automates an ISP backbone. Its verification core is
`pyats/parsers.py`: pure functions that take SR Linux and FRR *output text* and
return a verdict, testable offline with no lab. That core is proven. What was
missing is a way for an AI agent to use it safely.

This server exposes exactly one MCP tool:

```
verify_network_output(command, output, <one argument>)
  -> { ok, check, observed, reasons[], command_id, command, arguments }
```

You collect the device output; the tool tells you whether it means the network
is healthy. The six allowlisted command ids are `srl_interface_brief`,
`srl_ospf_neighbor`, `srl_bgp_neighbor_detail`, `frr_bgp_summary`,
`srl_route_detail`, and `ping`.

## Why one tool, and why read-only

The vault's own guidance: *"one tool done right beats five half-hardened"*, and
*"extra tools multiply attack surface faster than proof."* A test asserts the
tool count is exactly 1, so scope creep has to be a deliberate change.

Two properties do the security work:

1. **The server holds no device credentials and opens no sockets.** It is a
   pure function over text you already have. An agent cannot talk it into
   changing device state, because that capability is not present in the process
   at all. This is stronger than filtering dangerous commands — there is nothing
   to filter.
2. **The command set is a closed allowlist of ids, not free-form CLI strings.**
   "Only read-only commands" is enforced by the *type* of the input, not by a
   regex a prompt could talk its way around. `scope.py` has a structural test
   asserting no allowlisted entry contains a mutating verb.

This is the OWASP LLM Top 10 *Excessive Agency* mitigation for F1. Human
approval for writes and audience-bound tokens are F3, and are absent here
because there is nothing to write to.

## Two design decisions worth defending

**A failing network is data; a malformed input is an error.** If a broken FRR
payload and an unhealthy peer both surfaced as `ok: false`, an agent would
report a device fault that does not exist. So `ok` is only ever `false` because
the *network* failed a check, and malformed JSON is labelled
`input error, not a network fault`.

**Zero BGP peers is never reported healthy.** Upstream deliberately returns an
empty peer map for "no neighbours" because its callers assert on emptiness. A
network verifier that answers "healthy" about a router with no BGP sessions is
the most dangerous possible answer, so the conservative direction wins.


## Layout

| Path | Purpose |
|---|---|
| `server/scope.py` | Closed allowlist, input limits, secret redaction. Stdlib only. |
| `server/verify.py` | Command → structured verdict, via the vendored parsers. |
| `server/vendor/` | Byte-identical pinned copy of the flagship's `pyats/parsers.py`. |
| `server/mcp_server.py` | The thin MCP surface. Imports `mcp` lazily. |
| `evals/` | Declarative eval cases and the offline runner. |
| `scripts/` | Parity check, end-to-end MCP smoke test. |
| `tests/` | 54 tests, stdlib `unittest`. |

## Running it

```sh
pip install -r requirements.txt

python -m server.mcp_server     # serve over stdio
```

Verify it:

```sh
python -m unittest discover -s tests -t .   # 54 tests
python evals/run_evals.py                   # 22 eval cases
python scripts/smoke_test.py                # real MCP round trip
python scripts/check_upstream_parity.py     # vendored copy vs pinned upstream
```

The first three need no network, no model, and no secrets. That is deliberate:
a gate that cannot run is indistinguishable from no gate.

## The vendored parser, and why it is pinned

`pyats/parsers.py` is not a distributable package upstream, so it cannot be a
dependency. It is vendored — and a vendored copy is only worth something if it
cannot silently diverge, because a local edit here would make this server
disagree with the flagship's own CI assertions about the same device output.

So the comparison is enforced by `scripts/check_upstream_parity.py`, which
fetches the pinned commit `71d3398` and diffs it, ignoring the provenance
header. Any difference fails the build and prints a diff. It has three
distinct exit codes on purpose: `0` identical, `1` drifted, `2` could not
verify. "We could not check" must never be reported as "we checked and it is
fine."

```sh
python scripts/check_upstream_parity.py --offline   # header checks, no network
```

## What the eval gate is, and is not

`evals/cases.json` is 22 fixed input/expected-verdict pairs. It is
**model-free**, which is why CI is green on every commit instead of being
skipped when an API key is absent. Cases assert on the tool boundary — what an
agent receives — so they survive refactors.

This found two real bugs during the build, which is the argument for having it:

- The upstream parser's `no entries found` branch returns a reason with no
  prefix in it, contradicting its own docstring promise to report what it saw.
  Fixed by guaranteeing the response always identifies the prefix via `check`
  and `arguments`.
- An argument valid for one command but not another was being dropped silently
  by the tool. The eval case caught it; now it is refused.

**F2 replaces this with promptfoo trajectory evals** that score a real agent's
tool *choice*, with Langfuse self-hosted tracing. That needs a model API key, so
it needs a secret, so it will be a job that can be skipped. The CI file
documents that as a deliberate placeholder rather than shipping a green badge
that means nothing.

## CI

`.github/workflows/ci.yml`, three jobs:

- **quality** — ruff, vendored-parity header check, 54 tests, eval gate, MCP
  smoke test. No network, no secrets.
- **parity** — the live comparison against the pinned upstream commit. Separate
  so a GitHub outage fails one job loudly instead of blocking everything.
- **security** — Bandit, Gitleaks, Trivy. `server/vendor` is excluded from
  Bandit: it is third-party code verified byte-for-byte by the parity job, and
  reporting its issues as ours would be noise.

## Known gaps, stated plainly

- The tool **does not fetch output**. It verifies text you pass it. Fetching
  would mean holding device credentials, which is exactly what this design
  refuses to do.
- `mcp` is pinned to **1.28.1**, the version this was developed and verified
  against, not the 2.x line. Bump it in its own commit with the smoke test as
  evidence.
- The vendored file carries **no upstream LICENSE**, since the flagship has
  none. It is vendored from the same author's public repository. If the
  flagship adds a license, this copy inherits it and the header must say so.
- Command output is modelled on the flagship's lab. Real SR Linux releases vary
  in wording, which is why the parsers accept several forms.


Verified: the check reports parity OK against the live upstream, and when the
vendored file was deliberately perturbed it exited 1 with a diff naming the
changed line. A checker that cannot fail is not a checker.
