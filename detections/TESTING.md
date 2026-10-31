# Testing the detections

Two kinds of test, both scoped to the detections themselves: **regression** (the rules keep
catching the behaviour and keep ignoring normal activity) and **reproduction** (confirm a
rule fires end-to-end on a real occurrence of the behaviour).

## Regression (automated)

```bash
python detections/validate.py      # exit 0 = 0 false positives AND all exfil caught
```

Runs the policy over `tests/benign_ml_ops.txt` (routine ML-ops that must stay clean) and
`tests/malicious_egress.txt` (the behaviour + variants that must all alert), and prints
precision plus a jurisdiction breakdown. Wire it into CI as a gate.

- **Guard against allowlist drift:** add your environment's own routine egress commands to
  `benign_ml_ops.txt`. If a future allowlist/jurisdiction edit starts alerting on them, the
  build fails.
- **Guard against coverage loss:** add new exfil shapes you care about to
  `malicious_egress.txt`. If a rule change stops catching one, the build fails.

```bash
sigma check detections/sigma/        # lint the canonical Sigma rules in CI too
```

## Reproduction (confirm a rule fires on the real behaviour)

Ideas, in rough order of effort — pick what fits your environment. All stay on infrastructure
you control; never send data to a destination you do not own.

1. **Replay a published trace through the detector.** Download the investigation trace and
   run the shift-left detector against it:
   ```bash
   python detections/agent_trace_detector.py path/to/qwen-investigation.jsonl
   ```
   Expect a HIGH finding for the Beijing-region destination — confirms the detector catches
   the documented occurrence.

2. **Replay your own agent/eval logs.** Point the same detector at a JSONL export of your
   model/agent rollouts. Any unsanctioned or watched-jurisdiction egress surfaces as a
   finding; wire it into the eval pipeline so a rollout that tries to egress fails the gate.

3. **Fire a canary against a sink you own.** On a monitored host or sandbox, emit the
   behaviour's command shape toward a sinkhole/bucket **you control** (never a real external
   host), e.g. a `curl -X PUT --data-binary <canary>` to a DNS name you point at your own
   listener, and confirm your deployed EDR/Sigma rule raises the expected alert. This tests
   the telemetry path end-to-end (see `DATA_SOURCES.md`).

4. **Jurisdiction watchlist check.** Add a line targeting a watched-jurisdiction host (e.g.
   `*.yandexcloud.net`) to a test trace and confirm it is flagged; then add it to
   `allowlist.json` and confirm the flag is suppressed — proving the customization path works.

5. **Model sampling (optional, if you have inference access).** Run the dataset's published
   repro to sample completions from the model, then feed the captured completions to the
   detector. Reproduction is probabilistic; absence in a batch is not evidence the behaviour
   is gone.
