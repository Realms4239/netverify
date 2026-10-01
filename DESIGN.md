# DESIGN — the netverify console

## Core purpose

**netverify exists to prove what an MCP server really does before a model
depends on it.** The console is that proof made interactive: it drives the
real server in-process and over stdio, shows the actual protocol frames, and
reports the telemetry each call produced. Every element on the page serves
that purpose; anything that does not was removed.

Who it serves: engineers evaluating or hardening an MCP server — the same
person running `evals/` and the gates — at the moment they are deciding
whether the server is safe to wire to a host.

## Direction: modest instrument

The previous design (Ferrari: near-black canvas, Rosso Corsa, 80px numerals,
uppercase tracking) was a statement. A verification console is not a
statement; it is an instrument. The redesign trades intensity for precision:

- **Light, warm paper** (`#f7f6f3`) instead of near-black — matches how the
  page is actually read (alongside an IDE), and prints legibly.
- **Ink text on paper, hairlines, one radius** — structure comes from type
  and spacing, not boxes and tints. No shadows, no section tinting.
- **One accent, used only for interaction** (`#2b5db9`: focus rings, the
  outbound-frame mark). Green/red/amber appear only as verdict semantics —
  colour is information, never decoration.
- **Ink primary button** instead of a red CTA. The loudest element on the
  page is the thing you click most; everything else recedes.

## Tokens

Colour (`demo/dashboard.html` `:root`): paper `#f7f6f3`, surface `#ffffff`,
ink `#26241f` (14.8:1), body `#57534a` (7.3:1), muted `#6b675e` (5.2:1),
line `#e3e0d8`, wash `#efede7`, accent `#2b5db9`, ok `#1a7f37`,
refuse `#b42318`, warn `#b54708`, info `#175cd3`. Every text colour meets
WCAG AA on paper.

Type: system stack for identity (`system-ui` + `Cascadia Code`/
`ui-monospace` for data). Two families, three weights (400/500/600), five
sizes (12/13/15/16/22px). `rem` throughout so browser zoom and user settings
hold. No uppercase shouting — labels are sentence case, 12px, weight 500.

Spacing: 4/8/12/16/24/32/48/64, plus an airy section rhythm — sections
breathe on `clamp(64px, 9vw, 96px)` of vertical padding, and the intro gets
the most (clamp up to 96/72). Line-height 1.6. Radius: 6px everywhere.
Motion: 120ms ease-out on colour/border only, disabled under
`prefers-reduced-motion`.

Brand: the mark is a chevron in a rounded ink square (header, favicon) —
one glyph, reused everywhere, never decorated. The wordmark is mono:
`netverify / console`. The footer carries a live service line — session,
protocol, uptime, posture — every value measured from `/api/health`; a
status line that cannot lie is the brand.

Structure: the page ships as three files — `dashboard.html` (markup only),
`console.css`, `console.js` — because the server sends a strict CSP and
there is no inline script or style to excuse.

Touch/keyboards: interactive elements ≥ 44px tall; visible 2px focus ring on
`:focus-visible`; status line is `aria-live="polite"`; tool selection is
`aria-pressed`; the result panel is a labelled region.

## Voice

Plain sentences, active verbs, no marketing. The page states its purpose
once (the intro), explains a section only where the explanation changes what
you do (why the transcript exists, why the telemetry is trustworthy), and
never repeats a claim it already made. No static numbers that will rot: the
only counts shown are the ones the running server just reported. Verdicts
are concrete ("6/6 answered · MCP 2026-07-28"), never theatrical ("SILENCE
ON THE WIRE").

## Hardening (the server is part of the design)

`demo/live_server.py` follows the same discipline the page does — a console
that proves a server must not itself be a liability:

- **Strict CSP, no unsafe fallbacks**: `default-src 'none'`, scripts and
  styles from `'self'` only, no `frame-ancestors`, no `form-action`. The
  browser enforces the no-inline rule; the suites assert zero console
  errors, so a CSP violation fails the build.
- **Static serving is a whitelist** (`/console.css`, `/console.js`,
  `/favicon.svg`): a request path is looked up as a key, never joined onto
  a directory — the traversal class of bug needs a join to exist.
- **Bodies are capped and validated**: over 1 MiB is refused with 413
  (draining up to 8 MiB first so the client gets the answer cleanly, then
  closing if anything remains unread); invalid JSON and non-object bodies
  get 400 with the parse position.
- **Errors do not leak**: unexpected failures return a short message plus
  an 8-hex id; the detail goes to stderr. The `Server` header says
  "netverify", never the interpreter version.
- **One proof at a time**: the stdio proof spawns an interpreter, so a
  second overlapping request is answered 409 rather than stacked.
- **One measurement window at a time**: `/api/call` slices telemetry by a
  cursor, so concurrent calls used to read each other's spans and counter
  deltas (a stress harness caught a 3-span call reporting 28). Calls and
  bootstrap are serialized under one lock; attribution is now exact.
- **The Host header must be this console's** (`127.0.0.1:8765` or
  `localhost:8765`): DNS rebinding lets a web page point a name it owns at
  127.0.0.1 and, same-origin rules satisfied, read responses and invoke
  tools. A foreign Host gets 403, a missing one 400.
- **HTTP/1.1 keep-alive with a 30s socket timeout**: a connection that
  sends nothing is closed, not held.
- **No assert() control flow**: startup invariants are explicit raises;
  `assert` vanishes under `python -O`.

## Rules for changes

1. Every element must serve the core purpose above; delete what does not.
2. New colour must be semantic or it must not exist. Interaction = accent.
3. Copy: cut it in half, then again; if a sentence repeats the data next to
   it, delete the sentence.
4. Claims on the page must be measured at runtime, not hard-coded.
5. Zero external requests: no CDNs, no webfonts fetched at runtime. The
   page must work with the server on an air-gapped machine.
6. No inline script or style — the CSP forbids it and the suites enforce it.
7. New endpoints validate their input, cap their bodies, and never return
   exception detail to the client.
8. A behaviour change to the page updates `p2_browser.js` in the same
   commit; the browser suite is the design contract's enforcement.

## Verification

The headless-browser suite asserts the design contract, not just the DOM:
paper/ink tokens from computed styles, no Tailwind, 44px targets, 6px
radius, zero uppercase ≥14px, focus ring present, no horizontal scroll at
390px, zero external requests and zero console errors — alongside the
functional checks (verify, refusal, transcript, telemetry poll).
