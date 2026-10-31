# Detection content — unsolicited egress from AI eval / agent sandboxes

Deployable detections for the behaviour behind Cohere's "Qwen 3.8 Flash Next" finding: a
model-driven process that, mid-task, attempts to beacon out to third-party storage or probe
a cloud metadata endpoint. These are engineered for **fidelity in an AI-lab environment** —
not a wall of alerts a SOC will mute in a week.

## The fidelity principle (why these aren't noise)

In an AI lab, `curl`/`wget` to cloud object storage runs constantly — weights, datasets and
checkpoints move to OCI Object Storage and GCS all day. So **"egress to cloud storage" is
not a signal.** Two things are:

1. **Access to a cloud instance metadata endpoint** (`169.254.169.254`, Alibaba's
   `100.100.100.200`, `metadata.google.internal`). Workloads use workload identity; a shell
   or sandbox hitting the metadata IP is credential theft / SSRF. Near-zero false positives,
   turnkey.
2. **Egress to a destination off the sanctioned allowlist**, from a context whose egress
   should be short and known (an eval/agent sandbox). The detection is therefore
   **allowlist-relative** — it alerts on what is *not* sanctioned, not on "storage."

Measured on the corpora in `tests/`: **0 false positives on 10 routine ML-ops commands,
6/6 true positives on the exfil set, 100% precision.** `detections/validate.py` enforces it.

## Why this maps to Cohere's stack

Cohere trains and serves on **Kubernetes** — Oracle **OKE on OCI**, plus **GCP/TPUs**
([Oracle case study](https://www.oracle.com/customers/yourorg-case-study/)); their security
roles list OCI/GCP/AWS/Azure, Kubernetes, Terraform and CI/CD. No public SIEM, so the
content is **SIEM-agnostic Sigma** plus a **K8s-native runtime** path and a **shift-left**
path that needs no SIEM at all:

| Deploy point | Artifact | Why it fits, and FP posture |
|---|---|---|
| **Eval / agent pipeline (shift-left)** | `agent_trace_detector.py` | Runs over rollout traces in CI *before a model ships*. A sandboxed eval should make no unsanctioned egress, so FP ≈ 0. Catches the behaviour at the source. |
| **K8s runtime (OKE/GKE)** | `falco/ai_sandbox_egress.yaml` | Falco DaemonSet — the standard runtime sensor for these clusters. Scoped to sandbox namespaces; metadata rule is turnkey-CRITICAL. |
| **SIEM** | `sigma/` → `splunk/` `sentinel/` `elastic/` | Canonical Sigma, converts to any backend. Metadata rule turnkey; egress rule allowlist-relative. |

## Deploy tomorrow

**1 — Shift-left, in the eval harness (highest leverage, no SIEM needed):**
```bash
python detections/agent_trace_detector.py <rollout-trace.jsonl>   # exit 2 on any finding
```
Run it as a CI gate on every eval rollout. Pointed at CohereLabs' own published trace it
flags the Beijing upload (record 4) as HIGH / T1567.002 — i.e. it would have caught this.

**2 — Falco on the clusters:** load `falco/ai_sandbox_egress.yaml`, set
`ai_sandbox_namespaces` and `sanctioned_egress_domains`. Pair with a default-deny egress
NetworkPolicy on those namespaces — Falco is the tripwire for anything that gets out.

**3 — SIEM:** deploy the **metadata** rule as-is (turnkey). For the **egress** rule, fill
the sanctioned-destinations allowlist (`filter_sanctioned` / the watchlist) with your
buckets and mirrors, scope to sandbox hosts, and start with the upload-only variant.

## Rules and ATT&CK

| Rule | ATT&CK | Baselining |
|------|--------|------------|
| `cli_cloud_instance_metadata_access` | T1552.005 | none — turnkey |
| `high_risk_jurisdiction_egress` (CN/RU/KP default, customizable via `jurisdictions.json`) | T1567.002 | none — known infra |
| `qwen_egress_behavioral_signature` (Alibaba OSS + rollout markers) | T1567.002, T1552.005 | none |
| `sandbox_unsanctioned_egress` (allowlist-relative) | T1567.002, T1071.001, T1105 | allowlist required |

Canonical source is **Sigma**; they pass `sigma check` clean and convert with pySigma:
```bash
pip install sigma-cli pysigma-backend-splunk
sigma check  detections/sigma/
sigma convert -t splunk detections/sigma/cli_cloud_instance_metadata_access.yml
# kusto (Sentinel/Defender), esql (Elastic), and CrowdStrike/Chronicle backends also exist.
```
If you keep detections as code, these Sigma rules drop straight into a
[peak-2-sigma](https://github.com/acseguin21)-style pipeline that emits each vendor format.

## Test

```bash
python detections/validate.py        # regression: 0 FP on ML-ops, all exfil caught, exit 0
```
`tests/benign_ml_ops.txt` and `tests/malicious_egress.txt` are the regression corpora — add
your own routine commands and keep false positives at zero. Edit `allowlist.json` to match
your tenancy and `jurisdictions.json` to your risk model. Reproduction and regression test
ideas (replaying a trace, firing a canary at a sink you own, jurisdiction checks) are in
**[TESTING.md](TESTING.md)**. Observed indicators from the event, tiered by confidence with
caveats, are in **[indicators/observed_indicators.json](indicators/observed_indicators.json)**
— reference, not a blocklist.

## Data sources (deploy without figuring out the plumbing)

See **[DATA_SOURCES.md](DATA_SOURCES.md)** for which telemetry each detection needs and
which common tool emits it (EDR, DNS logs, flow logs, SWG/proxy, Datadog CWS, Cloudflare
Gateway, GuardDuty…), plus the three gotchas that quietly break this use case — IMDS traffic
is invisible to flow logs, flow logs carry no hostname, and a WAF is the wrong (inbound) layer.

## Field mapping

Process-creation telemetry with a command line: Sigma `Image`/`CommandLine` (Sysmon-for-Linux
or your EDR schema), Splunk CIM `Endpoint.Processes`, Sentinel/Defender `DeviceProcessEvents`,
Elastic ECS `process.name`/`process.command_line`. Falco reads `proc.cmdline` and `fd.sip`.

## Honest scope

- These encode a **known primitive** (cloud-metadata SSRF / allowlist-relative exfil); the
  contribution is engineering it for **AI-agent command execution** and proving the FP rate.
- The egress rule is only as good as the allowlist — scope it to specific buckets, never a
  whole provider ("any GCS bucket" would allow exfil to an attacker's bucket).
- Network-layer coverage (Suricata/Zeek on the metadata IP + an egress proxy's deny log) is
  a useful complement and intentionally left to the environment's existing controls.
