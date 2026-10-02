"use strict";
// ---------------------------------------------------------------------------
// netverify console — drives the real server through /api/* and renders what
// comes back. No framework, no build step, no inline script: the server sends
// a strict CSP, so everything here runs from this file and nothing else.
// ---------------------------------------------------------------------------
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

let BOOT = null;
let CURRENT_TOOL = null;

// ---------- live indicator ----------
function setLive(ok, label) {
  $("live-dot").className = `dot ${ok ? "on" : "off"}`;
  $("live-label").textContent = label;
}

// ---------- bootstrap ----------
async function loadBootstrap() {
  try {
    const r = await fetch("/api/bootstrap");
    BOOT = await r.json();
    if (BOOT.error) throw new Error(BOOT.error);
    $("nav-protocol").textContent = "MCP " + BOOT.protocol_version;
    const nRes = BOOT.resources.length + BOOT.templates.length;
    $("session-facts").innerHTML = [
      `${BOOT.tools.length} tools`,
      `${nRes} resources & templates`,
      `${BOOT.prompts.length} prompt`,
      `MCP ${BOOT.protocol_version}`,
      "telemetry on",
    ].map((f) => `<span>${esc(f)}</span>`).join("");
    setLive(true, "live");
    renderTools();
    renderSamples();
    renderTelStatus(BOOT.telemetry);
  } catch (e) {
    setLive(false, "offline");
    $("session-facts").textContent = "server unreachable — start it with: python demo/live_server.py";
  }
}

// ---------- console ----------
function renderTools() {
  $("tool-list").innerHTML = BOOT.tools.map((t) =>
    `<button type="button" class="tool-btn" data-name="${esc(t.name)}" aria-pressed="false">${esc(t.name)}</button>`
  ).join("");
  document.querySelectorAll(".tool-btn").forEach((b) =>
    b.addEventListener("click", () => pickTool(b.dataset.name)));
  pickTool("verify_network_output");
}

function pickTool(name) {
  CURRENT_TOOL = name;
  const t = BOOT.tools.find((x) => x.name === name);
  document.querySelectorAll(".tool-btn").forEach((b) =>
    b.setAttribute("aria-pressed", String(b.dataset.name === name)));
  $("tool-desc").textContent = t ? (t.description || "") : "";
  $("args").value = sampleArgs(name);
  $("result").innerHTML = "";
  $("run-status").textContent = "";
  $("run-status").className = "";
}

// The placeholder is what the sample loaders fill. It is spliced into `output`
// fields only, so a capture lands where the tool reads it and never in a field
// like `interface` that means something else.
const PLACEHOLDER = "«paste or load a capture»";

// Runnable defaults shaped against each tool's own input schema —
// `verify_capture` takes a `commands` list, `compare_captures` takes
// `before`/`after`, so an empty default would only produce a refusal that
// says nothing about the tool.
function sampleArgs(name) {
  const s = BOOT.samples;
  const up = (s["interface-up"] || "").trim();
  const down = (s["interface-down"] || "").trim();
  const loss = s["ping-total-loss"] || "";
  const batch = [
    { command: "srl_interface_brief", interface: "ethernet-1/1", output: up },
    { command: "ping", output: loss },
  ];
  const shapes = {
    verify_network_output: { command: "srl_interface_brief", interface: "ethernet-1/1", output: PLACEHOLDER },
    sanitize_device_output: { output: PLACEHOLDER },
    audit_device_output: { output: PLACEHOLDER },
    verify_capture: { commands: batch },
    synthesize_health: { commands: batch },
    compare_captures: { before: up, after: down },
    self_check: {},
  };
  return JSON.stringify(shapes[name] !== undefined ? shapes[name] : {}, null, 2);
}

const SAMPLE_NAMES = {
  "interface-up": "Healthy interface",
  "interface-down": "Disabled interface",
  "ping-total-loss": "Ping loss",
  "hostile-secret": "Hostile + secret",
};

function renderSamples() {
  $("sample-buttons").innerHTML = Object.keys(SAMPLE_NAMES).filter((k) => BOOT.samples[k]).map((k) =>
    `<button type="button" class="chip-btn" data-s="${esc(k)}">${esc(SAMPLE_NAMES[k])}</button>`
  ).join("");
  document.querySelectorAll("#sample-buttons button").forEach((b) =>
    b.addEventListener("click", () => {
      $("capture").value = BOOT.samples[b.dataset.s];
      try {
        // Show exactly what Run will send: the capture spliced into every
        // declared `output` that still holds the placeholder or is empty.
        $("args").value = JSON.stringify(splice(JSON.parse($("args").value), BOOT.samples[b.dataset.s]), null, 2);
      } catch { /* leave the arguments as they are until they parse */ }
    }));
}

function splice(node, cap, key) {
  if (typeof node === "string") {
    return (key === "output" && (node === "" || node === PLACEHOLDER)) ? cap : node;
  }
  if (Array.isArray(node)) return node.map((v) => splice(v, cap, key));
  if (node && typeof node === "object") {
    const out = {};
    for (const [k, v] of Object.entries(node)) out[k] = splice(v, cap, k);
    return out;
  }
  return node;
}

$("run").addEventListener("click", async () => {
  if (!CURRENT_TOOL) return;
  let args;
  try {
    const cap = $("capture").value;
    args = splice(JSON.parse($("args").value), cap);
    $("args").value = JSON.stringify(args, null, 2);
  } catch (e) {
    $("run-status").textContent = "Arguments are not valid JSON — " + e.message;
    $("run-status").className = "err";
    return;
  }
  $("run").disabled = true;
  $("run-status").textContent = "answering…";
  $("run-status").className = "";
  $("result").innerHTML = "";
  try {
    const r = await fetch("/api/call", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ kind: "tool", name: CURRENT_TOOL, arguments: args }),
    });
    const d = await r.json();
    if (d.error) throw new Error(d.error);
    renderResult(d);
  } catch (e) {
    $("run-status").textContent = "failed — " + e.message;
    $("run-status").className = "err";
  } finally {
    $("run").disabled = false;
  }
});

function verdictChipClass(outcome) {
  return outcome === "pass" ? "v-pass" : outcome === "fail" ? "v-fail" : outcome === "input_error" ? "v-neutral" : "v-refused";
}

function renderResult(d) {
  const res = d.result || {};
  const sc = res.structured || {};
  const parts = [];

  // Head row: verdict + timing. A refusal is a verdict too — it means the
  // guard the tool claims to have actually fired.
  const head = [];
  if (sc.outcome) {
    head.push(`<span class="verdict ${verdictChipClass(sc.outcome)}">${esc(sc.outcome)}</span>`);
  } else if (res.is_error) {
    head.push(`<span class="verdict v-refused">refused</span>`);
    const reason = (res.text.match(/\[reason=([a-z_]+)\]/) || [])[1];
    if (reason) head.push(`<span class="verdict v-refused">reason=${esc(reason)}</span>`);
  } else {
    head.push(`<span class="verdict v-neutral">answered</span>`);
  }
  head.push(`<span class="timing">${esc(d.elapsed_ms)} ms · ${d.spans.length} span${d.spans.length === 1 ? "" : "s"}</span>`);

  if (sc.observed) parts.push(`<div class="observed">${esc(sc.observed)}</div>`);
  if (sc.reasons && sc.reasons.length) {
    parts.push(`<ul class="reasons">${sc.reasons.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>`);
  }
  if (res.text) parts.push(`<pre class="pre-block">${esc(res.text)}</pre>`);

  const findings = sc.findings || [];
  if (findings.length) {
    const sev = { critical: "v-refused", high: "v-refused", medium: "v-neutral" };
    parts.push(`<div class="findings">${findings.map((f) =>
      typeof f === "object"
        ? `<span class="verdict ${sev[f.severity ?? f[1]] || "v-neutral"}">${esc(`${f.kind ?? f[0]} · ${f.severity ?? f[1]}`)}</span>`
        : `<span class="verdict v-neutral">${esc(f)}</span>`
    ).join("")}</div>`);
  }
  if (d.metric_deltas && d.metric_deltas.length) {
    parts.push(`<div class="findings">${d.metric_deltas.map((m) => {
      const attrs = Object.values(m.attributes || {}).join(" ");
      return `<span class="verdict v-neutral">${esc(m.name)} +${esc(m.delta)}${attrs ? " · " + esc(attrs) : ""}</span>`;
    }).join("")}</div>`);
  }
  if (d.spans.length) {
    parts.push(`<div><h3>Spans this call</h3>${d.spans.map((s) =>
      `<div class="kv"><span class="k">${esc(s.name)}</span><span class="v dur">${esc(s.duration_ms)} ms</span></div>`
    ).join("")}</div>`);
  }

  $("result").innerHTML = `<div class="result-block"><div class="result-head">${head.join("")}</div><div class="result-body">${parts.join("")}</div></div>`;
  $("run-status").textContent = `answered in ${d.elapsed_ms} ms`;
}

// ---------- protocol transcript ----------
$("proof-run").addEventListener("click", async () => {
  $("proof-run").disabled = true;
  $("proof-status").textContent = "starting the server process…";
  $("proof-out").innerHTML = "";
  try {
    const r = await fetch("/api/stdio-proof", { method: "POST" });
    const d = await r.json();
    if (d.error) throw new Error(d.error);
    renderProof(d);
  } catch (e) {
    $("proof-status").textContent = "failed — " + e.message;
  } finally {
    $("proof-run").disabled = false;
  }
});

function renderProof(d) {
  const frames = d.frames.map((f) => {
    const cls = f.direction === "out" ? "out" : (f.raw ? "in-ok" : "in-bad");
    const dir = f.direction === "out" ? "→ out" : "← in";
    // Truncate the raw text BEFORE escaping, so an entity is never cut in half.
    let body = f.raw ? JSON.stringify(f.raw) : (f.note || "");
    if (body.length > 400) body = body.slice(0, 400) + " …";
    const who = f.raw && f.raw.result && f.raw.result.tools ? `#${f.id} ${esc(f.method)} — ${f.raw.result.tools.length} tools` : `#${f.id} ${esc(f.method)}`;
    return `<div class="frame ${cls}">
      <span class="dir">${dir}</span>
      <span class="who">${who}</span>
      <span class="payload">${esc(body)}</span>
      <span class="lat">${f.direction === "in" ? f.t_ms + " ms" : ""}</span>
    </div>`;
  }).join("");

  const checks = d.assertions.map((a) =>
    `<div class="check ${a.ok ? "" : "bad"}">
      <span class="mark">${a.ok ? "✓" : "✗"}</span>
      <span class="what">${esc(a.step)}</span>
      <span class="how">${esc(a.detail)}</span>
    </div>`).join("");

  const unanswered = d.assertions.find((a) => !a.ok);
  const verdict = d.all_answered
    ? `<span class="verdict v-pass">${d.assertions.length}/${d.assertions.length} answered · MCP ${esc(d.protocol_version)}</span>`
    : `<span class="verdict v-refused">no answer for ${esc(unanswered ? unanswered.step : "?")}</span>`;

  $("proof-out").innerHTML = `
    <div class="frames">${frames || '<div class="empty">no frames</div>'}</div>
    <div class="tx-checks">
      <h3>Checks</h3>
      ${checks}
      <div class="tx-verdict">${verdict}</div>
    </div>`;
  $("proof-status").textContent = "";
}

// ---------- telemetry ----------
function renderTelStatus(s) {
  const items = [
    ["Tracer", s.tracer], ["Meter", s.meter], ["Metrics state", s.metrics_state],
    ["Host provider", s.host_provider], ["Spans (recent)", s.spans_recorded],
    ["SDK SERVER spans", s.sdk_emits_server_spans ? "yes" : "no"],
  ];
  $("tel-status").innerHTML = items.map(([k, v]) =>
    `<span class="item">${esc(k)}<b>${esc(v)}</b></span>`).join("");
}

async function refreshTelemetry() {
  try {
    const r = await fetch("/api/telemetry");
    const d = await r.json();
    setLive(true, "live");
    renderTelStatus(d.status);

    const groups = {};
    for (const m of d.metrics) {
      const key = m.name + (m.is_histogram ? " (histogram)" : "");
      groups[key] = groups[key] || {};
      const label = Object.values(m.attributes).join(" ") || "total";
      groups[key][label] = m.is_histogram ? `${m.value} calls · mean ${m.mean_ms} ms` : m.value;
    }
    $("tel-metrics").innerHTML = Object.entries(groups).map(([name, vals]) =>
      `<div><div class="metric-name">${esc(name)}</div>${Object.entries(vals).map(([k, v]) =>
        `<div class="row"><span class="k">${esc(k)}</span><span class="v">${esc(v)}</span></div>`).join("")}</div>`
    ).join("") || `<div class="empty">No metrics yet — run a tool call.</div>`;

    const spans = d.spans.slice().reverse().slice(0, 24);
    $("tel-spans").innerHTML = spans.map((s) => {
      const key = Object.entries(s.attributes)
        .filter(([k]) => k.includes("gen_ai") || k.includes("netverify"))
        .slice(0, 2).map(([, v]) => v).join(" · ");
      return `<div class="row"><span class="k">${esc(s.name)}${key ? " — " + esc(key) : ""}</span><span class="v">${esc(s.duration_ms)} ms</span></div>`;
    }).join("") || `<div class="empty">No spans yet.</div>`;
  } catch {
    setLive(false, "offline");
  }
}

// ---------- service status (footer) ----------
function fmtUptime(seconds) {
  const s = Math.max(0, Math.floor(seconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  return h
    ? `${h}:${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}`
    : `${m}:${String(sec).padStart(2, "0")}`;
}

async function refreshHealth() {
  try {
    const r = await fetch("/api/health");
    const d = await r.json();
    $("svc-status").innerHTML =
      `<span class="dot on"></span>in-memory session · MCP ${esc(d.protocol_version)} · up ${fmtUptime(d.uptime_s)} · read-only`;
  } catch {
    $("svc-status").innerHTML = `<span class="dot off"></span>server unreachable`;
  }
}

// Poll while the page is visible; catch up immediately on return.
setInterval(() => {
  if (!document.hidden) {
    refreshTelemetry();
    refreshHealth();
  }
}, 3000);
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) {
    refreshTelemetry();
    refreshHealth();
  }
});
loadBootstrap().then(() => {
  refreshTelemetry();
  refreshHealth();
});
