---
name: New check request
about: Ask for a new command to be verified (one CommandSpec)
title: ''
labels: enhancement
assignees: ''
---

**The command**

The exact read-only CLI command and platform (e.g. `show bgp summary`, `frr`).

**What a healthy answer looks like, and what a fault looks like**

Be specific about both directions: what the output shows when the state is
good, what it shows when it is genuinely faulty, and what it shows when the
capture simply cannot answer (that one must become `input_error`, never a
fault — see "Known gaps" in the README).

**Sample output**

Real or realistic output, pasted as text. Mask real secrets first.

**Willingness to contribute it**

New checks are one `CommandSpec` in `netverify/registry.py` plus tests — see
[CONTRIBUTING.md](../../CONTRIBUTING.md). Say if you plan to open the PR.
