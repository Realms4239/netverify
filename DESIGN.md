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

Spacing: 4/8/12/16/24/32/48/64. Radius: 6px everywhere. Motion: 120ms
ease-out on colour/border only, disabled under `prefers-reduced-motion`.

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

## Rules for changes

1. Every element must serve the core purpose above; delete what does not.
2. New colour must be semantic or it must not exist. Interaction = accent.
3. Copy: cut it in half, then again; if a sentence repeats the data next to
   it, delete the sentence.
4. Claims on the page must be measured at runtime, not hard-coded.
5. Zero external requests: no CDNs, no webfonts fetched at runtime. The
   page must work with the server on an air-gapped machine.
6. A behaviour change to the page updates `p2_browser.js` in the same
   commit; the browser suite is the design contract's enforcement.

## Verification

The headless-browser suite asserts the design contract, not just the DOM:
paper/ink tokens from computed styles, no Tailwind, 44px targets, 6px
radius, zero uppercase ≥14px, focus ring present, no horizontal scroll at
390px, zero external requests and zero console errors — alongside the
functional checks (verify, refusal, transcript, telemetry poll).
