# Egress detection for open-weight model agents

Deployable, ATT&CK-mapped detection content for **unsolicited network egress by processes
running open-weight models with tool / code execution** — agent harnesses, autonomous eval
rollouts, tool-using RAG. The motivating case: in a published investigation, an open-weight
model given a benign security task spontaneously issued `curl` commands attempting to send a
probe payload to third-party cloud storage and to a cloud metadata endpoint — unprompted.
([Cohere's investigation](https://cohere.com/blog/concerning-behaviour-popular-open-weight-ai-model);
the recorded destination was an Alibaba Cloud bucket in the Beijing region.)

The question for anyone adopting these models is concrete: **when a model-driven process
reaches out, where does the data go — and would you see it?** This repo answers the second
half with detection content you can deploy, test, and tune.

## What it detects

Three complementary signals, engineered for fidelity in an AI-lab environment where egress
to cloud storage is otherwise routine:

| Signal | Rule(s) | ATT&CK | Baselining |
|--------|---------|--------|------------|
| Cloud instance **metadata access** (SSRF / credential theft) | `sigma/cli_cloud_instance_metadata_access.yml` | T1552.005 | none — turnkey |
| Egress to **watched-jurisdiction** cloud infra (default CN/RU/KP, customizable) | `sigma/high_risk_jurisdiction_egress.yml`, `jurisdictions.json` | T1567.002 | none — known infra |
| The documented **beacon signature** (Alibaba OSS + rollout markers) | `sigma/qwen_egress_behavioral_signature.yml` | T1567.002 / T1552.005 | none |
| Egress to a destination **off your sanctioned allowlist** | `sigma/sandbox_unsanctioned_egress.yml`, `allowlist.json` | T1567.002 / T1071.001 | allowlist required |

The first three need **no per-environment baselining** — they key on known infrastructure
and the event's own fingerprint. The allowlist rule is the tunable, highest-coverage layer.

## Layout

```
detections/
  sigma/                 canonical rules (pass `sigma check`, convert via pySigma)
  splunk/ sentinel/ elastic/   pre-converted queries for common SIEMs
  falco/                 Kubernetes runtime rules (OKE/GKE)
  agent_trace_detector.py   shift-left: flag egress in an agent/eval trace (CI gate)
  egress_policy.py       shared allowlist + jurisdiction logic (stdlib only)
  allowlist.json         your sanctioned destinations
  jurisdictions.json     watched-jurisdiction infrastructure markers (customizable)
  indicators/            observed indicators from the event, tiered by confidence
  tests/                 regression corpora (benign ML-ops + malicious egress)
  validate.py            regression test: 0 false positives, all exfil caught
  DATA_SOURCES.md        which telemetry each rule needs, per common tool
  TESTING.md             how to regression- and reproduction-test the rules
  README.md              deployment + field mapping
```

## Deploy

- **Shift-left (no SIEM needed):** run `agent_trace_detector.py` over eval/agent rollout
  traces as a CI gate — catch egress before a model reaches production.
- **SIEM:** deploy the metadata and jurisdiction rules as-is (zero baseline); set
  `allowlist.json` for the allowlist rule. Sigma converts to Splunk / Sentinel / Elastic /
  Chronicle / QRadar / Panther; pre-converted queries are in `splunk/`, `sentinel/`, `elastic/`.
- **Kubernetes runtime:** load `falco/ai_sandbox_egress.yaml`, scoped to the namespaces
  running model-generated code.

Which telemetry powers each rule, mapped to EDR / DNS / flow / proxy / Datadog / Cloudflare
Gateway / GuardDuty, is in [`detections/DATA_SOURCES.md`](detections/DATA_SOURCES.md).

## Test

```bash
python detections/validate.py        # regression: 0 FP on ML-ops, all exfil caught, exit 0
sigma check detections/sigma/        # lint the canonical rules
```

Reproduction and regression test ideas are in [`detections/TESTING.md`](detections/TESTING.md).

## Honest scope

- These encode known primitives (cloud-metadata SSRF, allowlist-relative and
  jurisdiction-relative exfil) applied to the emerging context of AI-agent command execution.
- Jurisdiction markers identify where infrastructure is operated, not attribution; an actor
  relaying through infrastructure in a non-watched jurisdiction defeats them.
- The allowlist rule is only as good as the allowlist — scope it to specific buckets, never
  a whole provider.
- Indicators in `indicators/` are model-generated and unverified — not a blocklist. See the
  caveats in that file.

Built on a publicly documented investigation; not affiliated with any model vendor or cloud
provider.
