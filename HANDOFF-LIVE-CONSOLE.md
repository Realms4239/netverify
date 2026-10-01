# HANDOFF — netverify live console (Ferrari design + OpenTelemetry)

**Read this first. It is self-contained.** A fresh agent can resume from it
with no knowledge of any prior session. The project's older handoff,
`HANDOFF.md` (same directory), describes the *library* and its gates; this one
describes the current in-flight round and what is left to finish it.

---

## 1. Project overview and objectives

`C:\work\hardened-mcp-evals` (git, branch `main`, no remote) contains
**netverify**: a zero-dependency Python library plus a thin, read-only MCP
server that verifies ISP backbone device output (SR Linux, FRR). It holds no
credentials, opens no sockets, and cannot mutate a device. Version 1.2.0.
The library imports only the standard library; `mcp` and `opentelemetry` are
optional runtime dependencies used by the server adapter.

**This round's objective** (user request, verbatim intent): enhance the demo
dashboard into an **actual, live demonstration** —

1. Restyle it with **`DESIGN-ferrari.md`** (repo root) as the design system and
   **Tailwind** for styling.
2. Make it **actual usage**: real MCP calls against the real server, not
   static artifacts.
3. Wire **OpenTelemetry and all observability**: real spans and metrics,
   collected and displayed.
4. **Defend and verify that the MCP server really works**: prove it on a real
   stdio wire, frame by frame.

Everything below was built this round and is **uncommitted**. The last
committed state is `bfb0c8b` ("Make the demonstration runnable, and attack it
live") — the tree was clean at that commit, all gates green.

---

## 2. Completed work this round (and its outcomes)

### 2.1 `demo/obs.py` — observability bootstrap (DONE, verified)

Installs real OpenTelemetry SDK providers **before** `netverify`/`server` are
imported:

- `TracerProvider` + `SimpleSpanProcessor` → `InMemorySpanExporter`
  (`span_exporter` module attribute).
- `MeterProvider` + `InMemoryMetricReader` (`metric_reader` module attribute).
- Then imports `netverify.telemetry` and `server.app.build_server`, and calls
  `telemetry.reset_instruments()` so the lazy instruments bind to this
  provider.

Verified working: after one real `tools/call`, the exporter contains the SDK's
SERVER span (`tools/call verify_network_output` with
`gen_ai.operation.name=execute_tool`) and netverify's own span
(`netverify.verify` with `netverify.verdict.outcome`, `netverify.command.id`,
input/output byte counts). The metric reader returns
`netverify.verdicts` (per outcome), `netverify.refused` (per reason), and
`netverify.call.duration` (histogram).

**APIs it exposes:** `snapshot_spans(since=0)` → `(list_of_span_dicts,
total_count)`; `snapshot_metrics()` → list of dicts (histograms carry
`value`=count and `mean_ms`); `telemetry_status()` → the library's
`telemetry.status()` plus `spans_recorded` and an honest
`host_provider` field; `reset_span_cursor()` → the index to pass as `since`.

### 2.2 `demo/live_server.py` — the live MCP driver (DONE, endpoints verified)

stdlib `ThreadingHTTPServer` on **`127.0.0.1:8765`**. Run:

```powershell
cd C:\work\hardened-mcp-evals
$env:NETVERIFY_AUDIT = '0'; $env:PYTHONIOENCODING = 'utf-8'
C:\Users\ASUS\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe demo\live_server.py
```

- **`GET /`** — serves `demo/dashboard.html`.
- **`GET /api/bootstrap`** — through a persistent in-process `ClientSession`
  (`McpBridge`: one background asyncio loop, all calls funneled via
  `run_coroutine_threadsafe`): protocol version, the 7 tools with
  schemas/annotations, 4 resources, 1 template, 1 prompt, `self_check`
  structured result, telemetry status, and the 4 sample captures from
  `demo/inputs/`. **Verified**: protocol `2025-11-25`, all 7 tool names exact.
- **`POST /api/call`** `{kind: "tool"|"resource"|"prompt", name, arguments}` —
  one real round-trip; returns `elapsed_ms`, structured/text result (refusals
  surface as `is_error: true` with the message carrying `[reason=...]`),
  the **spans this call produced** (sliced by exporter cursor), and
  **metric deltas** (counters that moved). **Verified**: valid verify call →
  `pass`; `configure terminal` → refusal with reason; prompt render and
  resource read work (resource read was fixed last — see §4).
- **`POST /api/stdio-proof`** — spawns `python -m server` as a real
  subprocess (`cwd` **must** be the repo root), pipes newline-delimited
  JSON-RPC to stdin, returns every frame both directions with latency, plus
  per-step assertions. Steps: `server/discover`, `tools/list`, a valid
  `tools/call`, a refused `tools/call` (asserted as *an answer, not
  silence*), `prompts/list`, `skills/list`. **Verified:
  `all_answered: true`, 6/6.** On EOF it terminates the child and surfaces
  its stderr tail in the frame's `note`.

### 2.3 `demo/dashboard.html` — Ferrari-design live console (DONE, needs browser check)

Tailwind Play CDN + Inter/JetBrains Mono via Google Fonts. Design tokens per
`DESIGN-ferrari.md`: canvas `#181818`, elevated `#303030`, hairline `#303030`,
ink `#ffffff`, body `#969696`, Rosso Corsa `#da291c` used **scarcely** (run
button, live accent, hero verdict counter), semantic success `#03904a` /
warning `#f13a2c` / info `#4c98b9`. Sharp 0px corners everywhere; pill radii
only on badges; buttons uppercase with 1.4px tracking; display weight 500;
8px spacing ladder; spec-cell number displays (80px/700/−1.6px).

Sections: top nav (live pill + protocol) → hero with 4 live spec cells →
**Console** (tool list, JSON args editor, capture textarea with sample
loaders, RUN → verdict/outcome chip, findings pills, `[reason=...]` badges,
metric-delta pills, per-call spans) → **Wire proof** (RUN OVER STDIO → raw
frames `→ out` / `← in` with latency + assertions checklist) → **Telemetry**
(status chips, grouped metrics table, newest-first spans table, 3s polling) →
footer.

**Not yet verified in a browser.** The JS was written against the verified
API shapes but has not been exercised end-to-end visually.

### 2.4 Housekeeping (DONE)

- The old static dashboard was `git mv`'d to `demo/static_report.html`;
  `demo/build_dashboard.py` was patched to write that name.
- The older round (wrap-up demo, stress demo, handoff reconciliation) is
  fully committed at `bfb0c8b`.

---

## 3. Remaining tasks, in priority order (with acceptance criteria)

### P1 — Verify the two endpoints fixed last, and the live server end-to-end

The resource-read fix (`c.text` on `ReadResourceResult.contents`) and the
telemetry endpoint were applied and the server restarted, but the final
verification **returned an empty response** — the server may still have been
starting (the bridge connect happens before `serve_forever`) or a new failure
surfaced. Nothing else was checked after that point.

**Do:**

1. Start the server (command in §2.2), wait until
   `GET http://127.0.0.1:8765/api/bootstrap` returns JSON.
2. `POST /api/call` `{"kind":"resource","name":"netverify://contract"}`
   → must return `is_error: false` with contract text.
3. `POST /api/call` `{"kind":"prompt","name":"triage_capture"}` → prompt text.
4. `POST /api/call` with a valid verify (use sample `interface-up`) →
   structured verdict `pass`, spans non-empty, metric deltas non-empty.
5. `POST /api/call` `{"kind":"tool","name":"verify_network_output",
   "arguments":{"command":"configure terminal","output":"anything"}}` →
   `is_error: true`, text contains `[reason=not_in_allowlist]`.
6. `POST /api/stdio-proof` → `all_answered: true`.
7. `GET /api/telemetry` → `total_spans > 0`, non-empty `metrics`.

**Acceptance:** all seven checks pass in one server session; fix whatever
fails first (shapes are in §4) before moving on.

### P2 — Exercise the dashboard in a browser and fix what breaks

Serve `/` from the running server, open it (the WorkBuddy `present_files`
tool with `http://127.0.0.1:8765` opens the built-in browser preview), and:

- bootstrap populates the tool list, spec cells, live pill ("Live"),
- RUN on `verify_network_output` with the "Healthy interface" sample shows a
  green `pass` chip + finding/metric pills + span rows,
- RUN with `configure terminal` shows the refusal badge with
  `reason=not_in_allowlist`,
- RUN OVER STDIO renders 12 frames (6 out + 6 in) and the all-answered banner,
- Telemetry tables fill and refresh every 3s.

**Acceptance:** every section renders with real data and zero console errors;
any JS bug is fixed in place.

### P3 — Lint the new Python files

```powershell
C:\Users\ASUS\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe -m ruff check .
C:\Users\ASUS\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe -m ruff format demo/
```

Expect E501s and possibly B-rules in `demo/live_server.py` / `demo/obs.py`
(inline frames, subprocess). The repo convention is: fix real issues;
per-file-ignores in `pyproject.toml` **only with a rationale comment**
(see the existing `demo/stress_demo.py` S105 and `demo/build_dashboard.py`
E501 entries for the house style). The stdio-proof Popen has
`# noqa: S603` already.

**Acceptance:** `ruff check .` and `ruff format --check .` both clean.
`bandit -q -r netverify server scripts -ll -x netverify/parsers` must also
stay clean (`demo/` is not in bandit's target list today — leave that as is).

### P4 — Full gate re-run (the demo files must not have broken anything)

With the hermes venv interpreter (§5):

```
python -m unittest discover -s tests -t .     # 370 tests
python evals/run_evals.py                     # 46/46
python scripts/stdio_check.py
python scripts/smoke_test.py
python scripts/check_upstream_parity.py
python scripts/check_dependencies.py
python -m ruff check . ; python -m ruff format --check .
python -m bandit -q -r netverify server scripts -ll -x netverify/parsers
```

Skip `check_wheel_install.py` and `mutation_test.py` unless `netverify/`,
`server/`, or `tests/` were touched — they were not this round. If they were,
run them too (mutation takes ~28 min; build/ + netverify.egg-info/ must be
deleted before the wheel gate — see HANDOFF.md "Environment gotchas").

**Acceptance:** everything green.

### P5 — Document, then commit

1. Update `demo/README.md`: document `live_server.py` (URL, endpoints,
   what it proves), `obs.py`, and the new `dashboard.html` /
   `static_report.html` split.
2. Append a short entry to `HANDOFF.md`'s demonstrability section: the live
   console exists, what it proves, and the interpreter note (§5).
3. Write the commit message to a file (PowerShell heredocs do not work) and
   `git commit -F <file>`. Stage `demo/obs.py`, `demo/live_server.py`,
   `demo/dashboard.html`, `demo/static_report.html` (rename),
   `demo/build_dashboard.py`, `demo/README.md`, `HANDOFF.md`, and any
   `pyproject.toml` ignore entries.

**Acceptance:** `git status` clean; one commit with a message in the repo's
voice (evidence-first, no marketing).

---

## 4. Known issues, traps, and exact API shapes (learned by running it)

All of these were **hit and fixed** this round; they will bite again if
re-factored blindly:

- **OTel ordering is load-bearing.** The providers in `demo/obs.py` must be
  installed *before* `netverify`/`server` import; `reset_instruments()` must
  run once after import. Never swap or restore the provider afterwards —
  see the ProxyTracerProvider RecursionError story in `HANDOFF.md`.
- **`InMemoryMetricReader`:** read via **`get_metrics_data()`**, *not*
  `collect()` (which is a push into the reader and returns `None` on 1.45.0).
- **`ClientSession` pydantic shapes:** `list_resources()` → `.resources`;
  `list_resource_templates()` → `.resource_templates`; `list_prompts()` →
  `.prompts`; `read_resource()` → `.contents`, each item has `.text`
  (and `.mime_type`). `list_tools()` → `.tools`. All snake_case:
  `init.protocol_version` (the negotiated value in-process is
  **`2025-11-25`**; the *stdio* transport under `stdio_check.py` uses
  `server/discover` with **`2026-07-28`** in `_meta` — two different surfaces,
  both correct).
- **`McpBridge` field order:** the constructor line setting
  `self.protocol_version = None` must come **before**
  `run_coroutine_threadsafe(...).result(30)` or it clobbers the value the
  connect coroutine just set.
- **stdio child cwd:** `python -m server` resolves from its **cwd** — pass
  `cwd=str(ROOT)` explicitly, never `sys.path[0]` (it is `demo/` here). An
  EOF on the child's stdout with no stderr output is the signature of this
  mistake.
- **`metrics_state` reads `not-configured`** in the live server. That is
  *honest*: the library's env-based configuration is not configured, and the
  **host** provider (obs.py's, in-memory) is collecting instead. The
  dashboard shows both chips deliberately. Do not fake this value.
- **The dashboard console currently exposes only tools.** Resources and
  prompts are reachable via `/api/call` with `kind`, but have no UI yet —
  a reasonable enhancement, not a blocker.
- The client-side `spec-verdicts` counter counts calls made from *this*
  browser tab only; `spec-spans` is server-side truth.
- `ThreadingHTTPServer` answers `GET`/`POST` only; `HEAD` returns 501
  (harmless).
- `netverify.refusal.command` metric labels are bounded by design — never
  "fix" the `None` command label on `not_in_allowlist` refusals (unbounded
  cardinality hole; see `netverify/errors.py` docstring).

## 5. Environment and setup notes

- **Interpreter:** every gate and demo runs with
  `C:\Users\ASUS\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe`
  (3.11, has `mcp`, `anyio`, `pydantic`, `opentelemetry`, `ruff`, `bandit`).
  A bare `python` resolves to a managed 3.13 **without** them → 15 phantom
  import errors, 78 skips. This is now documented in `HANDOFF.md`.
- Env vars for runs: `NETVERIFY_AUDIT=0` (silence audit JSONL in tests),
  `PYTHONIOENCODING=utf-8` (em-dashes crash cp1252).
- Live server port `127.0.0.1:8765` (hardcoded in `live_server.py`).
- Tailwind is the Play CDN — the dashboard needs internet at view time.
- PowerShell heredocs do not work; long commands time out; `build/` poisons
  the wheel gate. Full list: `HANDOFF.md` §"Environment gotchas".
- Git: no remote; commit messages via `git commit -F <file>`.

## 6. Codebase context (where things live)

```
C:\work\hardened-mcp-evals\
├── HANDOFF.md                  # library-level handoff (gates, gotchas, history)
├── HANDOFF-LIVE-CONSOLE.md     # this file
├── DESIGN-ferrari.md           # the design system this round implements
├── netverify\                  # the zero-dependency library (tests pin it)
├── server\                     # MCP adapter: app.py (tools), prompts.py, skills.py
├── scripts\                    # gates: stdio_check, smoke, parity, mutation, wheel
├── tests\                      # 370 tests; fixtures.py has the payloads
├── evals\run_evals.py          # 46 behavioral evals
└── demo\
    ├── dashboard.html          # NEW live console (Ferrari + Tailwind)
    ├── live_server.py          # NEW HTTP + MCP driver (port 8765)
    ├── obs.py                  # NEW OTel bootstrap (in-memory exporters)
    ├── static_report.html      # the old static dashboard (renamed)
    ├── build_dashboard.py      # regenerates static_report.html
    ├── wrap_up_demo.py         # committed: operator-story transcript (+ PNG)
    ├── stress_demo.py          # committed: 6 asserted adversarial scenarios
    ├── stress_results.json     # committed: machine-readable stress record
    └── inputs\                 # sample captures used by everything
```

Reference clone for the vendored parser: `C:\isp-ref`. SEP-2640 text:
`C:\work\sep2640.md`. SDK sources: `C:\work\mcp2x`.

## 7. Recommended next steps for the fresh agent

1. Work P1 → P5 in order; do not commit until P4 is green.
2. When editing the dashboard JS, keep it vanilla and verify against the real
   endpoints — the API shapes in §4 are the contract.
3. After committing, update `C:\work\.workbuddy-ai\memory\` daily log with the
   commit hash and any new traps discovered.
4. Longer-term queue (from `HANDOFF.md`, still open): pin `prompts/get` and
   `resources/list` over the wire in `scripts/stdio_check.py`; revoke the PATs
   mentioned there before any publication.
