# netverify — session handoff

Read this first. It is the state of the work, what is proven, and what the
next session should do first.

**Supersedes the previous handoff.** That one was stale in three ways: its
commit list stopped four commits short, its "uncommitted, ready to commit"
section described work that has since landed, and it had a corrupted orphan
fragment mid-file. All corrected below.

## Where things are

- Project: `C:\work\hardened-mcp-evals` (branch `main`, **no remote** — verified,
  `git remote -v` is empty)
- Vault: `C:\AIR` (separate repo, at `d3dbbb3` — verified this round)
- Reference clone: `C:\isp-ref` (upstream `isp-network-as-code`)
- SEP-2640 text: `C:\work\sep2640.md` · SDK source: `C:\work\mcp2x`

"Clean" is checked, not asserted. At the start of this round the tree was **not**
clean (`demo/` untracked) and the suite was **not** green (one failure), while
the handoff claimed both.

`netverify` is a **zero-dependency Python library** plus a thin **read-only MCP
server** that verifies ISP backbone device output (SR Linux, FRR). It holds no
credentials, opens no sockets, and cannot mutate a device. Version 1.2.0.

## Verified state

Full gate set green at `31939c2`, and re-verified unchanged this round:

```
370 tests · 46/46 evals · ruff check · ruff format · bandit -ll ·
zero-dependency · mutation 21/21 · smoke · parity · stdio · wheel-install
```

### The demonstrability round (this cycle)

The wrap-up demo existed but was not reliably runnable: its PNG step raised
`ModuleNotFoundError` for Pillow *after* every command had already succeeded —
a passing demonstration made non-demonstrable by its decoration. The render is
now optional and says so when skipped; `transcript.txt` is the canonical
record. Two new artefacts make the claims watchable rather than documented:

- **`demo/stress_demo.py`** — six adversarial scenarios, each with a written
  expectation and an assertion (exit 1 if reality disagrees): hostile capture
  (injection + exfiltration + a real secret on a healthy interface — verdict
  stays `pass`, all three attacks named, the secret never emitted), the
  allowlist refusal with its bounded metric label, the typo-argument refusal,
  a token-bucket burst/refuse/recover, oversize truncation dropping the tail
  secret, and the empty-table vs missing-row classification. Writes
  `demo/stress_results.json`. Found by running it: `TokenBucket`'s method is
  `consume`, not `spend`, and a script under `demo/` needs the repo root
  bootstrapped onto `sys.path` — the same gotcha the scripts note describes.
- **`demo/build_dashboard.py` → `demo/dashboard.html`** — a self-contained
  dark-theme page whose every value is read from `transcript.txt` and
  `stress_results.json`. It renders what the tool did; it asserts nothing
  that was not executed. Rebuild it after re-running either demo.

Also this round: the mutation gate went 20/20 → 21/21 (the refused-
`tools/call` mutant), the E501 in the mutation anchor was fixed by splitting
the literal (content byte-identical), `scripts/stdio_check.py` was reformatted
(no anchors target it), and `pyproject.toml` gained two scoped
`per-file-ignores` with rationale (`demo/stress_demo.py` S105 for the decoy
secret, `demo/build_dashboard.py` E501 for inline HTML). Full gates re-run
green this round: 370/370 tests, 46/46 evals, stdio, smoke, parity,
zero-dependency, ruff, bandit -ll, mutation 21/21.

**Environment correction:** the interpreter the gates require is the hermes
venv (`C:\Users\ASUS\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe`)
— it is the one that has `mcp`, `anyio`, `pydantic` and `opentelemetry`. A
bare `python` on this machine resolves to a managed 3.13 without them and
reports 15 phantom import errors and 78 skips. Every command in "How to run
the gates" means that interpreter.

### The live console (added after the demonstrability round)

The static report above is a recording. `demo/live_server.py` + the
redesigned `demo/dashboard.html` (Ferrari design system, `DESIGN-ferrari.md`,
Tailwind) are the live demonstration, and they are verified end to end:
7/7 endpoint checks and 7/7 headless-browser checks against the running
server, zero console errors, full gate set green with the new files in tree.

- **In-process usage:** a persistent `ClientSession` over the SDK's
  in-memory transport drives real `tools/call`, `resources/read` and
  `prompts/get`; `POST /api/call` returns the result, the spans that call
  produced and the counters it moved. Verified: a valid verify returns
  `outcome: pass` with 3 spans (SDK SERVER span + `netverify.verify` + the
  client-side send span) and a `netverify.verdicts` delta; `configure
  terminal` returns `is_error: true` with `[reason=not_in_allowlist]`.
- **Wire proof:** `POST /api/stdio-proof` spawns `python -m server` as a
  real subprocess and returns every JSON-RPC frame both directions with
  latency; all six steps answered, including the refusal — asserted as *an
  answer, not silence*, which is the failure mode only a real pipe can show.
- **Observability is real:** `demo/obs.py` installs the OpenTelemetry SDK
  providers before any netverify/server import and never swaps them; the
  telemetry section reads the SDK's own in-memory exporters, so the numbers
  on the page are the numbers recorded. The `metrics_state:
  not-configured` chip is honest (env-based export is unconfigured; the
  in-memory host provider is collecting) — do not fake it.

Two traps this round cost real time; both are fixed in the code and worth
not re-learning: `process.communicate()` returns **two** values, so a
`_, err, _ =` unpack silently discarded the child's stderr (the EOF branch
looked informative and said nothing); and a cold `python -m server` on
Windows took **28.6s** to its first answer, which a 20s watchdog reported as
silence — per-step reads are now bounded at 90s with concurrent stderr
drain, so a slow start reads as a wait and a real death is quoted verbatim.
A favicon route was added because a browser 404 reads as a console error.

The interpreter note above applies to the live server too: it is the hermes
venv or nothing, and `python -m server` inside the wire proof resolves from
its cwd (the repo root), never `sys.path[0]`.

## What the five requested items actually are

Two of the five were **already done**. Verified, not assumed — check before
re-implementing anything here.

| # | Item | Status | Evidence |
|---|---|---|---|
| 1 | Agent Skill (SEP-2640) | **DONE** | `skills/triage-backbone/SKILL.md`, `server/skills.py`, `tests/test_skills.py` |
| 2 | Adversarial finding counters | **DONE** | `telemetry.record_findings`, called from `sanitize.scan`; `tests/test_telemetry.py` |
| 3 | Progress notifications on `verify_capture` | **DONE** | `verify_many(progress=...)`, `server/app.py:_progress_reporter`, `tests/test_protocol_extensions.py` |
| 4a | `cache_hints` | **DONE** | `server/app.py:CACHE_HINTS`, passed to `MCPServer(...)`; `tests/test_protocol_extensions.py` |
| 4b | "no payloads in telemetry" test | **DONE** | `tests/test_telemetry_payloads.py` (spans *and* metrics) |
| 5 | Aggregate metrics | **DONE** | `telemetry.record_verdict/record_findings/record_duration/record_rate_limited/record_refused` |
| — | Prompts (found in review) | **DONE** | `server/prompts.py`, `tests/test_prompts.py` |
| — | Batch size cap (found in review) | **DONE** | `MAX_BATCH_ITEMS`; burst derived from it |
| — | Stable refusal codes (found in review) | **DONE** | `errors.REASON_*`, `ScopeError.reason`/`.command`; `tests/test_refusal_reasons.py` |
| — | Thread safety for global state (found in review) | **DONE** | locks in `TokenBucket` and `AuditLog`; `tests/test_limits_audit.py` |

### A fourth, added after the first gate run

**`status()` reports what happened, not what was asked for.** The first version
of the metrics wiring consulted only `NETVERIFY_OTEL_CONSOLE`, so in the
configuration this library is actually deployed in — `OTEL_EXPORTER_OTLP_ENDPOINT`,
the collector the traces go to — it returned immediately. Traces exported, every
counter went nowhere, and the console path that *did* work is the one nobody
deploys with. `metrics_state` exists so that failure is visible from `self_check`
instead of inferred from an empty dashboard: `exporting:<name>`,
`not-configured`, `host-provider`, or `failed:no-metric-exporter (...)`. Pinned
by mutation #14, which flips the OTLP check back to console-only.

Two traps found by running it rather than reading it: `ImportError.name` for a
missing subpackage is the *outermost* missing module (`opentelemetry.exporter`),
so the state names the intent as well as the cause; and the OTLP *metric*
exporter is an optional package the trace exporter does not pull in, so
`failed:` is a real state here, not a hypothetical one.

### Three design points worth not undoing

**The library cannot import `asyncio`.** `integrity.py` lists it among the
network-capable modules — it *can* open a socket. So `verify_many` takes a
**plain sync callback** (`ProgressFn`), and the only coroutine in the feature
lives in the server adapter, which bridges to a loop. Two bridges, because the
call shape differs: under the SDK, `anyio.from_thread.run` hands the coroutine
back to the owning loop and blocks the worker; called directly (tests, REPL),
there is no host loop, so it runs on a throwaway one. Use `from_thread.run`,
**not** `run_sync` — the latter returns the coroutine un-awaited in this anyio
version, which looks like success and reports nothing.

**Refusal labels must stay bounded.** `ScopeError.command` is set only once the
id is known to be in the allowlist. For `not_in_allowlist` the id is whatever
the caller invented, and labelling with it lets an attacker mint a metric series
per request. The test for that is in `tests/test_refusal_reasons.py`.

**`CACHE_HINTS` keys are `Literal` strings, not enum members.** `CacheableMethod`
is a `Literal` of method names; `CacheableMethod.TOOLS_LIST` raises
`AttributeError` at import. The SDK validates keys at construction, so a typo
would otherwise be a hint that silently applies to nothing.

## Found by hunting, not by a failing gate

Three defects that every existing test agreed were fine. Recorded because the
*shape* of them is the lesson, not the instances.

**A control that tested three characters while documenting a rule about line
breaks.** `_require_text` refused `\r\n\t`; U+2028, U+2029, NEL, VT and FF all
passed, and each is a line break to a terminal, a JSON renderer or a Markdown
engine. The registry patterns hid it - they are a separate dict from the
arguments, so the next patternless argument would have had no defence at all. Now
`isprintable()`, which is the rule the docstring always claimed.

**A bare boolean where the meaning needed two values.** `srl_interface_is_up()`
returns `True` or `False`, so "not in this text" and "in this text and down" are
indistinguishable to it. An operator who asked about `ethernet-1/6` and pasted a
capture that scrolled past it was told the link was **down**. That is the mirror
image of the failure the README calls most dangerous, and it pages people. The
parsers are vendored and byte-pinned by the parity gate, so the classification
now happens in `registry.py`, which owns the meaning. Same fix for OSPF, BGP,
routes and ping.

**Masking without reporting.** `verify` sanitised the caller's text and returned a
clean verdict, so a credential in the capture was protected and *silent*. The
operator never learned they had pasted a password into a chat window. Every
verdict now carries `findings` - `kind` and `severity` only, never the matched
text. It costs about 75ms on a maximal capture, which is why that cost is written
down next to the code rather than left for someone to rediscover as a regression.

All three are mutation-pinned, and all three were found by a probe or a rehearsal
rather than by reasoning about the code.

### A second pass, after the first was written up

The first absence-classification fix had the right idea and the wrong test. Its
presence check asked whether the subject was *mentioned anywhere* in the capture,
which is true of `! ethernet-1/1 is down for maintenance` — a comment, no table, no
state — so the checker answered "interface ethernet-1/1 is not admin-enabled and
up", a fault claim read off text containing no interface state at all. Presence is
now the **row**, mirroring the opening of the vendored parser that will read it:
`_interface_row`, `_cell`, `_peer_line`, `_route_row`.

**That tightening immediately broke the opposite case, which is the useful part.**
`No entries found for prefix 10.20.30.0/24` has no route row, so a presence test
that runs first reads a rendered-but-empty table as an *unreadable capture* and
tells the operator their paste was wrong — while a route is genuinely missing. The
device answering "no" and the device saying nothing look identical to a row search,
and only the former is a fault. `_check_route` therefore tests `_NO_ENTRIES`
*before* the row check. Both directions are pinned, per command, in
`tests/test_verdict_direction.py`: eleven genuine faults that must be `fail`, five
captures that must be `input_error`, and one assertion that **nothing** in either
table is ever `pass`.

**Two green tests were never collected.** `test_checker_signature_matches_declared_arguments`
and `test_worst_offender_carries_its_own_reason` were defined *after* a module-level
`unittest.main()` call, so they were nested inside the `if __name__ == "__main__"`
block and had never run. They pass, so the invariants they name do hold — they were
just decoration. `tests/test_integrity.py` now walks every test module's AST and
fails on any `test_*` function below module level, with a negative control compiled
from a string so the guard itself is proven to fire.

**A latent `RecursionError` in the telemetry tests, found by the new file tripping
over it.** `tests/test_telemetry.py` saved the previous provider with
`trace.get_tracer_provider()` — which does not merely read. With no provider set it
*creates and installs* a `ProxyTracerProvider`, and restoring that in `tearDown`
left the import-time `_TRACER` (a `ProxyTracer`) resolving against a proxy provider:
each asks the other for a tracer until the stack is gone. A fresh process is healthy
because the provider is `None` and the proxy falls back to a no-op tracer. So the
whole suite passed while leaving a process where **any later `verify()` call dies**,
and the casualty was whichever module sorted last. Fixed by saving the raw global;
pinned by `TestTracerStateSurvivesProviderSwaps`, which asserts both the structural
invariant and that `verify()` still returns a verdict. It had to be named to sort
after the class that creates the bad state, because `loadTestsFromModule` orders
classes alphabetically.

**A third finding, and the gate itself was the victim.** Closing the "never run
over the wire" gap above needed a guard that could *detect* silence — and the first
version could not, because it used a blocking `readline()`. Against the unfixed
server the gate hung rather than failed, so the job would have died on a timeout
with no message naming the cause. Three layers fixed it, and each was found by
running the guard against the bug rather than by reasoning about it:

- a watchdog bounds the wait and kills the server, so silence surfaces as an
  empty read and the failure is reported by name;
- the outer handler catches `OSError`, not just `BrokenPipeError`, because Windows
  reports a dead pipe as `EINVAL` and POSIX as `EPIPE`;
- the `finally` cleanup no longer raises, because an exception there replaced the
  whole failure list with a traceback that said nothing about the actual fault.

Verified in both directions: with the fix reverted the gate prints
*"skills/get for an unknown skill produced NO response; a client would hang rather
than be told, and could not tell that from a wedged server"*, and with the fix in
place it passes.

## Found this cycle — three, by running it rather than reading it

**A guard that accuses itself.** `tests/test_integrity.py` sweeps `tests/*.py`
for `def test_*` no runner can reach, and its negative control *wrote its control
file into that same directory*. Two things then read it: discovery collected its
`test_a_real_one` as a real test (the count read 371 instead of 370), and the
sweep globbed it as a real file and failed — naming, as a dead test, the file the
guard itself had just created. It passed on a clean run because `addCleanup`
deleted the file, so the defect only appeared when a run was **interrupted** and
the file survived: from then on every later run failed here. Found because the
baseline was re-established and the suite re-run, not because anyone reasoned
about it. Fixed by taking source text instead of a path, so the control is never
written to disk at all. A control that must be cleaned up cannot be relied on to
be.

**`_refuse` was dead code, and dead for a reason.** Its docstring said "every
refusal path funnels through here". No path did. It called
`AUDIT.record(..., tool=...)`, and `AuditLog.record` has no `tool` parameter, so
its first call would have raised `TypeError` — which is *why* nothing called it.
Meanwhile `verify_network_output` re-implemented the translation inline, and the
inline version put the **caller's raw command id** into the
`netverify.refusal.command` metric label. For `not_in_allowlist` that id is
whatever the caller invented, which is precisely the unbounded-cardinality hole
`ScopeError.command`'s own docstring exists to close: one fresh name per request
is one new metric series per request. The guard was real and tested in the
library, and the adapter walked around it. Both fixed by making `_refuse` work
and calling it; the audit line keeps what was attempted (prose, unbounded is
fine there) while the metric gets the bounded label.

**The refusal carried no reason code on the wire.** `ScopeError.reason` reached
the metrics and nothing else — the model received a sentence of prose and had to
parse it to decide whether to correct an argument, back off, or give up, which is
exactly where this project says meaning must not live. Refusal text now carries
`[reason=...]`, from both the single tool and `verify_capture`'s per-entry
results.

### And the gate that should have caught it

`scripts/stdio_check.py` asked `skills/get` for a URI naming nothing — the call
that found the silence bug — but had **never asked a refused `tools/call`**. Same
question, same transport, and `ScopeError` is a `ValueError`, the exact type
whose escape cost `skills/get` its response. It is now asked, and it was made to
go red first: with the translation removed the gate reports *"tools/call for a
mutating command produced NO response; a client would hang rather than be
refused"*, and the server then stops answering altogether. Pinned by mutation
#21.

`resources/read` was probed the same way and is sound: `skill://nope/SKILL.md`,
a traversal (`skill://triage-backbone/../README.md`), and a missing file all
answer `-32602` rather than nothing.

**A toothless mutation.** The `findings` mutation was anchored on `findings = ()` —
an initialiser the next line reassigns, so mutating it changed nothing and the
harness reported a survivor. Re-anchored on the assignment. Two mutations were
added for the new presence code (dropping the sub-interface form; loosening the
route row to a substring), both of which the new table catches.

## Work queued, in order

1. ~~**Nothing above is uncommitted**~~ — false when this was written: `demo/`
   was untracked, so the tree was not clean and the claim above it was wrong.
   `demo/` is real content (a wrap-up demonstration, `demo/wrap_up_demo.py`,
   exits 0) and is committed, not deleted.
2. ~~Scratch files `mut.txt`, `o*.txt`, `pid.txt`~~ — none of them exist. The
   only untracked thing in the root was `demo/`. Do not carry this forward.
3. If progress notifications are ever extended to another tool, the two bridges
   in `_progress_reporter` are the reusable part; do not move that logic into
   the library.
4. **`build/` poisoned the wheel gate.** A run interrupted mid-build leaves
   `build/bdist.win-amd64/wheel/netverify-1.2.0.dist-info` behind, and the *next*
   run then fails with `[WinError 183] Cannot create a file that already exists`
   — a stale artefact masquerading as a packaging bug. Remove `build/` and
   `netverify.egg-info/` before the wheel gate, not after. See "Environment
   gotchas".

## Previously-planned work (superseded)

Items 1–5 are done; the detail below is kept only to show what was planned.
`netverify/telemetry.py` previously emitted *spans only*; it now emits
counters and histograms as well.

## Next work, in order

Everything that used to be listed here — metrics, the adversarial finding
counters, progress notifications, `cache_hints` and the payload guard — is
**done**, and the list above was left behind by it. Kept once, below, so the
change is visible rather than silent; do not re-plan it.

### Superseded (all five landed)

1. Metrics — `netverify/telemetry.py`, five instruments sharing the `ATTR_*`
   vocabulary.
2. Adversarial finding counters — `telemetry.record_findings` from
   `sanitize.scan`; the differentiator, because no generic MCP server treats its
   own tool output as untrusted.
3. Progress notifications — `verify_many(progress=...)`, bridged in the adapter.
4. `cache_hints` — declared for all six cacheable methods.
5. Telemetry payload guard — `tests/test_telemetry_payloads.py`, spans and
   metrics.

### Queued now

1. **`prompts/get` has never been asked over the wire.** `stdio_check.py` lists
   prompts and never fetches one, so the rendered messages are unverified on the
   transport an agent actually uses. Probed and working; not yet pinned.
2. **`resources/list` is not asked over the wire either.** The gate reads one
   skill by exact URI, so a registration change that dropped skills from the
   listing would still pass.
3. **The adapter still has two refusal shapes.** `verify_capture` builds its
   per-entry `{"refused": ...}` string itself, while a single tool call goes
   through `_refuse`. They now agree on the reason code, but the duplication is
   the same class of drift `_refuse` was written to end. Consider one helper for
   both.
4. **Revoke and rotate the PATs** pasted into earlier chat sessions, before any
   publication. Carried forward; still not done.


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
| Progress | done | `verify_many(progress=...)`; 3 notifications seen on stdout |
| `cache_hints` | done | `server/app.py:CACHE_HINTS`, all six cacheable methods |
| Metrics | done | 5 instruments; `metrics_state` reported by `self_check` |
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

1. ~~**`skills/list` and `skills/get` have never run over the real stdio
   JSON-RPC wire.**~~ **Closed, and it found a shippability blocker.** Both methods
   now run over a real pipe in `scripts/stdio_check.py`, and the first thing that
   asked was: `skills/get` for a URI naming no skill. It raised a bare
   `SkillError` (a `ValueError`), and the SDK's dispatcher maps **only** `MCPError`
   onto the wire — anything else is logged as a crash and gets *no response at
   all*. Over stdio that is a client hanging until its own timeout, unable to
   distinguish a refusal from a wedged server, on the single call an agent is most
   likely to get wrong because the URI comes from wherever the user pasted it.
   In-process the same call raised a clean exception and every test passed.
   Fixed by converting at the handler boundary (`_as_protocol_error`), and the
   refusal is now `-32602` with the available skills named. See the "A third
   finding" section for why the gate itself needed hardening too.
2. **No client host has been confirmed to support the Final SEP-2640
   extension.** Untested against a real host. Now the only gap in this area:
   our own wire behaviour is proven, a third party's is not.
3. **Shared mutable state is lock-guarded; rate limiting remains per-process.**
   `TokenBucket`, `AuditLog`, and lazy telemetry instruments use `threading.Lock`
   around their global updates, and dedicated concurrency tests race exact budget
   debits, atomic audit lines, and one-time instrument creation. This is not a
   claim that every future global will be safe by default—only that the current
   process-wide sinks are explicitly serialized, with witnesses in the suite.
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

python -m unittest discover -s tests -t .   # 370 tests
python evals/run_evals.py                   # 46/46
python scripts/check_wheel_install.py       # build + install + run
python scripts/mutation_test.py             # 20/20
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
  shape of the code** — it is a stale copy, and it is stale in a way that bites:
  a wheel run interrupted part-way leaves
  `build/bdist.win-amd64/wheel/netverify-1.2.0.dist-info` on disk, and the next
  run then dies with `[WinError 183] Cannot create a file that already exists`
  while reporting `could not build a wheel; is setuptools available?`. That reads
  as a toolchain problem and is nothing of the kind. **Remove `build/` before
  the wheel gate**, and treat "stale build artefact" as a suspected cause of any
  packaging failure, not as housekeeping to do afterwards.
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

The current cycle (`fd21b69` through `603fc60`) is fully represented by the
latest commit subjects. The previous handoff stopped at `31939c2` and so omitted
the most recent one:

```sh
603fc60 Reconcile the handoff with the code it claims to describe
31939c2 Ask for a skill that is not there, and the answer was silence.
669b647 Read a verdict as "down" and you page someone at 3am about a healthy link. Read it as "healthy" and you hide a dead one. Both are wrong, and the first version of this fix traded the first for the second.
e73ad9a Stop reporting a fault for text the tool never saw
1ed5adc Prove the progress notifications reach a real client
0abaccb Export the metrics in the configuration we actually deploy in
6a7e6e9 Instrument the library, and make its refusals countable
fd21b69 Rewrite the handoff: verify status instead of inheriting it
```

The earlier entries in this repository are:

90a1a99  Prove the installed wheel works, and accept --json on either side
6238e27  Refuse a mistyped argument instead of answering from it
0de091c  Fix three defects stress testing found, and guard them
74485f7  Stop the published numbers from drifting
8714629  Serve a skill, and write the workflow down exactly once
04917c5  Audit self_check: make the claims computed, and fix the drift it found
```

The most important thing the previous session learned: **every gate ran from
the checkout**, where `skills/` happens to sit next to `server/`. A wheel that
omitted it would have passed the entire test suite while shipping a server that
starts normally and serves an empty catalogue. Hence `scripts/check_wheel_install.py`.

`SKILLS_ROOT = Path(__file__).resolve().parents[1] / "skills"` is correct for
this layout and **silently wrong** the moment the package is vendored, frozen,
or nested — that is the class of bug to keep hunting.

