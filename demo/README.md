# netverify demonstrations

Three runnable artefacts, all read-only and offline:

- **`wrap_up_demo.py`** — the operator story: `verify` on healthy, faulted and
  hostile input, `self-check`, and the MCP smoke test. Writes `transcript.txt`
  and, when Pillow is installed, `transcript.png` (Pillow is optional; its
  absence is reported, not fatal). Exits 0.
- **`stress_demo.py`** — the tool under attack: prompt injection + a real
  secret on a healthy capture, allowlist and unknown-argument refusals, a
  token-bucket burst, oversize truncation, and the empty-table vs missing-row
  classification. Each scenario carries a written expectation and an
  assertion; writes `stress_results.json`. Exits 0 only if reality matched
  every expectation.
- **`build_dashboard.py`** — renders `dashboard.html` from the two artefacts
  above. Every number on the page is measured output; nothing is asserted
  that was not executed.

Reproduce:

```sh
python demo/wrap_up_demo.py      # transcript.txt (+ transcript.png)
python demo/stress_demo.py       # stress_results.json
python demo/build_dashboard.py   # dashboard.html
```

## Inputs

1. `verify` on a healthy interface, a disabled interface, and total ping loss.
2. `sanitize` on hostile text with an exfiltration instruction and a secret.
3. `self-check` proving the installation's guards hold.
4. `smoke_test.py`, which exercises the MCP surface the way a host would.

Every command below is read-only and offline. Expected result: this script exits 0.

