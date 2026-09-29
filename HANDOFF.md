# netverify — session handoff

Read this first. It is the state of the work, what is proven, and what the
next session should do first.

**Supersedes the previous handoff.** That one was stale in three ways: its
commit list stopped four commits short, its "uncommitted, ready to commit"
section described work that has since landed, and it had a corrupted orphan
fragment mid-file. All corrected below.

## Where things are

- Project: `C:\work\hardened-mcp-evals` (branch `main`, clean, **no remote**)
- Vault: `C:\AIR` (separate repo, clean at `d3dbbb3`)
- Reference clone: `C:\isp-ref` (upstream `isp-network-as-code`)
- SEP-2640 text: `C:\work\sep2640.md` · SDK source: `C:\work\mcp2x`

`netverify` is a **zero-dependency Python library** plus a thin **read-only MCP
server** that verifies ISP backbone device output (SR Linux, FRR). It holds no
credentials, opens no sockets, and cannot mutate a device. Version 1.2.0.

## Verified state

Full gate set green as of `90a1a99`:

```
251 tests · 46/46 evals · ruff check · ruff format · bandit -ll ·
zero-dependency · mutation 10/10 · smoke · parity · stdio · wheel-install
```

## What the five requested items actually are

Two of the five were **already done**. Verified, not assumed — check before
re-implementing anything here.

| # | Item | Status | Evidence |
|---|---|---|---|
| 1 | Agent Skill (SEP-2640) | **DONE** | `skills/triage-backbone/SKILL.md`, `server/skills.py`, `tests/test_skills.py` |
| 2 | Adversarial finding counters | **NOT DONE** | `telemetry.py` has spans only — no `Counter`/`Histogram` anywhere |
| 3 | Progress notifications on `verify_capture` | **NOT DONE** | no `report_progress` in `server/` |
| 4a | `cache_hints` | **NOT DONE** | not passed to `MCPServer(...)` |
| 4b | "no payloads in telemetry" test | **PARTIAL** | guard exists for the *audit log* only (`tests/test_limits_audit.py:89`); **no guard on telemetry spans** |
| 5 | Aggregate metrics | **NOT DONE** | no metrics at all — see below |
| — | Prompts (found in review) | **DONE** | `server/prompts.py`, `tests/test_prompts.py` |
| — | Batch size cap (found in review) | **DONE** | `MAX_BATCH_ITEMS`; burst derived from it |

**Metrics are the single biggest gap.** `netverify/telemetry.py` currently emits
*spans only* (`span()`, `configure_from_env()`, `status()`). Every one of items
2, 4a and 5 lands in that one module, and the tracer provider is already
configured — so this is instrumentation work, not a plumbing project.

## Next work, in order

### 1. Metrics (`netverify/telemetry.py`)

Add OTel counters and histograms alongside the existing spans. Aggregate
questions are the ones traces cannot answer — during an incident you need
"failure rate by command across 400 interfaces", not "what happened to this
call".

Suggested instruments:

- `netverify.verdicts` counter, attributes `command_id` + `outcome`
  (`pass` / `fail` / `input_error`)
- `netverify.findings` counter, attributes `kind` + `severity`
- `netverify.call.duration` histogram, attributes `tool`
- `netverify.rate_limited` counter
- `netverify.refused` counter, attributes `reason`

Keep the existing `ATTR_*` names as the single source of truth for the
vocabulary — a telemetry vocabulary defined only at call sites drifts, and
dashboards then quietly stop matching.

### 2. Adversarial finding counters (the differentiator)

Item 1 is the one worth doing properly. Because the library treats device output
as hostile, findings-by-kind are a **security signal**, not a perf metric: a
spike in `verdict_coercion` or `exfiltration` across a fleet means someone is
attempting prompt injection against your infrastructure.

No generic MCP server has this metric, because no generic MCP server treats its
tool output as untrusted. It maps to the `prompt injection / PII / HITL / audit`
line in the $175K posting recorded in `C:\AIR\03 - Research\Evidence\Evidence - Agentic Era Skills.md`.

### 3. Progress notifications

`verify_capture` is the slow path. `ctx.report_progress(progress, total, message)`
is available in `mcp/server/mcpserver/context.py:113` and unused. Roughly one
line. Verify the progress token is honoured by a client before claiming it works.

### 4. `cache_hints` and the telemetry payload guard

`MCPServer.__init__` accepts `cache_hints: Mapping[CacheableMethod, CacheHint]`.
We already return tools in a deterministic order *for* cache friendliness
(tools/list is a SEP-2549 cacheable method) — declaring the hint is the missing
half of work already half-done.

**The payload guard matters more than the cache hint.** The audit log has
`test_never_records_the_payload`. Telemetry does not. Enabling an OTel exporter
moves data *out of the process* to a collector, which changes the trust boundary
that "we never log payloads" currently depends on. `Finding.detail` is a
description rather than matched text, so the code is on the right side of that
line — but it is currently an accident, not an invariant. Add a test that fails
if anyone puts raw text into a span attribute.


## MCP capability surface — full status

Verified against `mcp` 2.2.0 and spec revision **2026-07-28**.

| Capability | Status | Notes |
|---|---|---|
| Tools | done | 7 tools; annotations accurate; all have `outputSchema` |
| Resources | done | incl. `netverify://contract`, `netverify://security` |
| Prompts | done | `server/prompts.py` |
| Skills (SEP-2640) | done | ext id `io.modelcontextprotocol/skills`; rides on Resources via `skill://` URIs |
| `server/discover` | done | advertises 2026-07-28; verified over the real stdio pipe |
| Structured output | done | declared schema per tool |
| Rate limiting | done | token bucket, burst derived from `MAX_BATCH_ITEMS` |
| Audit logging | done | JSONL on **stderr** (stdout is the protocol channel) |
| Progress | **todo** | `ctx.report_progress` unused |
| `cache_hints` | **todo** | not declared |
| Metrics | **todo** | none |
| Resource templates | not used | if added, `ResourceSecurity` (traversal / absolute path / **NUL bytes**) becomes live — `mcp/server/mcpserver/resources/templates.py` |
| Tasks | not used | ext id `io.modelcontextprotocol/tasks`; `tasks/get` + `tasks/update`, no `tasks/list`. Nothing is long-running yet |
| MCP Apps | not used | wrong shape for a verifier |
| Elicitation | not used | nothing worth asking mid-call |
| OAuth 2.1 / transport security | out of scope | stdio is local; trust boundary is the OS process. Remote auth is **Project B** (Go gateway) — not this repo |
| Roots / Sampling / Logging | deprecated | correctly avoided. Spec says use stderr or OTel; we do both |

## Observability — what already comes free

Do not rebuild this. The SDK emits OpenTelemetry itself:

- `mcp/shared/_otel.py` — tracer `mcp-python-sdk`, `otel_span()`, plus
  `inject_trace_context()` / `extract_trace_context()` (W3C `traceparent`)
- `mcp/server/_otel.py` — a **SERVER span per inbound request**, attributes
  `gen_ai.operation.name="execute_tool"`, `gen_ai.tool.name`, `gen_ai.prompt.name`,
  `jsonrpc.request.id`, and on failure `error.type` + `rpc.response.status_code`

Trace context rides in **`_meta`**, which is per-request in 2026-07-28 — so
`traceparent` propagates **even over stdio**, giving one continuous trace from
the agent's own call into our spans. The cost is configuring a tracer provider,
not writing instrumentation.

## Known risks and open questions

1. **`skills/list` and `skills/get` have never run over the real stdio
   JSON-RPC wire.** Exercised in-process only. `scripts/stdio_check.py` covers
   `resources/read` for the skill but not the two extension methods.
   **Cheapest high-value fix available.**
2. **No client host has been confirmed to support the Final SEP-2640
   extension.** Untested against a real host.
3. **Not thread-safe.** Bucket is module-global, `AuditLog` writes to a shared
   stream. Stress-tested at 250k iterations with `sys.setswitchinterval` and
   found no over-issue — *not claimed as a defect* — but a `threading.Lock`
   closes it for near-zero cost.
4. **Rate limiting is per-process.** Correct for single-process stdio; needs
   shared state before any multi-replica move. Stated as a limitation in the
   security resource rather than papered over.
5. **PATs pasted into an earlier chat session should be revoked and rotated
   before publication.** No token appears in this repo or this file.

## Conventions worth keeping

- **A test never seen red is not known to detect anything.** Each guard in
  `tests/test_stress_regressions.py` was verified to fail against the unfixed
  code before the fix landed.
- **Record what you saw, not what you expected.** Every docstring there cites
  the measured output that produced the bug.
- **A failing test is not automatically a bug in the code.** Twice here the
  *test* was wrong. Read the failure against the source first.
- **Two guards were rewritten after falsely accusing correct code**, and both
  rewrites are recorded in place. A guard that cries wolf gets ignored, and
  then protects nothing.
- Prefer fixing a guard over weakening it; record the reasoning inline.


## How to run the gates

```powershell
cd C:\work\hardened-mcp-evals
$env:NETVERIFY_AUDIT = '0'          # silences the audit log during tests
$env:PYTHONIOENCODING = 'utf-8'     # em-dashes crash cp1252 output

python -m unittest discover -s tests -t .   # 251 tests
python evals/run_evals.py                   # 46/46
python scripts/check_wheel_install.py       # build + install + run
python scripts/mutation_test.py             # 10/10
python scripts/stdio_check.py
python scripts/smoke_test.py
python scripts/check_upstream_parity.py
python scripts/check_dependencies.py
python -m ruff check . ; python -m ruff format --check .
python -m bandit -q -r netverify server scripts -ll -x netverify\parsers
```

**Bandit must run with `-ll`.** Without it, `-ll`-clean code reports eight B105
"hardcoded password" false positives on severity strings and prose.


## Environment gotchas

- PowerShell heredocs (`<<'MSG'`) do not work. Write the commit message to a
  file, then `git commit -F <file>`.
- **Long commands time out at 30s.** Building a wheel, creating a venv, or
  installing packages: use `Start-Process` in the background and poll.
- `python scripts/x.py` puts `scripts/` on `sys.path`, not the repo root —
  bootstrap it explicitly.
- `build/` and `netverify.egg-info/` are untracked artefacts from the wheel
  gate. They are not source; **do not read `build/lib/` to learn the current
  shape of the code** — it is a stale copy.
- **Never edit a UTF-8 file with `Get-Content | Set-Content -Encoding UTF8`.**
  PowerShell 5.1 reads it as cp1252 and re-encodes, so every non-ASCII
  character is double-encoded. The result is still *valid* UTF-8, so a
  decode check will not catch it — `HANDOFF.md` lost all 26 of its em-dashes
  this way and looked fine. Use the editor tool, or Python, for any file
  containing non-ASCII. The console will still *display* UTF-8 as mojibake;
  judge by the bytes, not the render.

## Suggested skills for the next session

- `codebase-design` — item 1 adds a new *kind* of thing to `telemetry.py`
  (instruments alongside spans). The interface question is whether metrics
  belong in the same interface or a sibling module.
- `verification-before-completion` — before claiming the stdio extension methods
  work, they must be seen red first, per the convention above.
- `simplify` — after metrics land, check whether `status()` and the new
  instruments can share one vocabulary definition.

## Committed this cycle

```
90a1a99  Prove the installed wheel works, and accept --json on either side
6238e27  Refuse a mistyped argument instead of answering from it
0de091c  Fix three defects stress testing found, and guard them
74485f7  Stop the published numbers from drifting
8714629  Serve a skill, and write the workflow down exactly once
04917c5  Audit self_check: make the claims computed, and fix the drift it found
```

The most important thing the previous session learned: **every gate ran from
the checkout**, where `skills/` happens to sit next to `server/`. A wheel that
omitted it would have passed all 251 tests while shipping a server that starts
normally and serves an empty catalogue. Hence `scripts/check_wheel_install.py`.

`SKILLS_ROOT = Path(__file__).resolve().parents[1] / "skills"` is correct for
this layout and **silently wrong** the moment the package is vendored, frozen,
or nested — that is the class of bug to keep hunting.

