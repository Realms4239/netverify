---
name: Bug report
about: A verdict is wrong, a refusal is missing, or something broke
title: ''
labels: bug
assignees: ''
---

**What happened**

A clear, one-paragraph description. What did you expect the verdict to be, and what did you get?

**Command and arguments**

The command id (e.g. `srl_interface_brief`) and the arguments you passed.

**The raw device output**

Paste the capture as-is. It is treated as hostile text here — but please mask
real secrets first; the sanitizer helps and does not replace judgement.

**Result**

- Verdict: `pass` / `fail` / `input_error`
- Refusal reason code, if refused: `[reason=...]`
- Gate results if you ran them (`python -m unittest discover -s tests -t .`)

**Environment**

OS, Python version, how you ran it (library / CLI / MCP host / live console).
