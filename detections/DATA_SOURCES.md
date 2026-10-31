# Data sources — what to point these detections at

So you can deploy on Monday without reverse-engineering the plumbing. Each detection keys on
one of four telemetry classes; below is which common tool emits each, and the gotchas that
quietly break this use case.

## TL;DR — minimum viable telemetry

- **Pre-production (best):** your model/agent harness's own **tool-call logs**. The
  `agent_trace_detector.py` needs nothing but these — no security stack.
- **Production hosts / K8s:** **process-creation events with the full command line**
  (EDR or Falco). This single source powers both Sigma rules.
- **Cloud-only shops:** **DNS query logs** (catches the beacon resolving its hostname) +
  **flow logs** (catches the connection). See the IMDS caveat below.

## Per-detection → telemetry → tools

| Detection | Telemetry class it needs | Emitted by (use what you already have) |
|---|---|---|
| **Cloud metadata access** (`cli_cloud_instance_metadata_access`, T1552.005) | Process creation **with command line** | **EDR**: CrowdStrike `ProcessRollup2`, Defender `DeviceProcessEvents`, SentinelOne Deep Visibility, Carbon Black, Elastic Defend · **Linux**: auditd `execve`, Sysmon-for-Linux EID 1 · **K8s**: Falco. *Plus native:* **AWS GuardDuty** has built-in IMDS-exfil findings. |
| **Unsanctioned egress** (`sandbox_unsanctioned_egress`, T1567.002) | Process+cmdline (host) **or** HTTP egress w/ host **or** DNS **or** netflow | **EDR** (host + cmdline — gets the URL) · **Secure Web Gateway / forward proxy**: Zscaler, Netskope, Cloudflare Gateway, Palo Alto Prisma, Squid (host + method) · **DNS logs**: Route 53 Resolver, GCP Cloud DNS, CoreDNS (K8s), Cisco Umbrella, Cloudflare Gateway · **Flow logs**: AWS VPC / GCP VPC / Azure NSG / OCI VCN (dest IP only) |
| **Falco runtime rules** (`falco/ai_sandbox_egress.yaml`) | Syscall / eBPF runtime events + K8s metadata | Falco, **Datadog Cloud Workload Security**, Tetragon, Sysdig Secure, Aqua, Wiz runtime sensor |
| **Agent-trace detector** (`agent_trace_detector.py`) | The model harness's own tool-call / command log (application layer) | Eval-framework JSONL, LangSmith / Langfuse / Arize Phoenix, OpenTelemetry **GenAI** spans, or your custom agent logs — **no security tooling required** |

## "If you have X, here's where it fires"

- **EDR** (CrowdStrike / Defender / SentinelOne / Elastic) → your primary source. Process
  events carry the command line, so **both Sigma rules work directly** — convert the Sigma
  to your EDR's query language and go.
- **Datadog** → run the runtime rules via **Cloud Workload Security** (eBPF, the
  Falco-equivalent); send CloudTrail / flow / DNS / proxy logs to **Cloud SIEM** and port
  the Sigma logic there.
- **Cloudflare** → use **Cloudflare Gateway (Zero Trust SWG)**, not WAF — it gives you DNS
  and HTTP **egress** logs with hostnames. (WAF protects *inbound*; it won't see a model
  phoning out. See gotcha 3.)
- **AWS CloudTrail** → does **not** see the `curl` itself. It's your detection for the
  *aftermath* — stolen instance-metadata credentials being **used** (unusual `sts` / API
  calls from an unexpected source). Pair it with the metadata rule + GuardDuty.
- **VPC / VCN / NSG flow logs** → connection to an unexpected **external IP** from a
  workload subnet. IP-only (gotcha 2), and blind to IMDS (gotcha 1) — pair with DNS logs.
- **DNS query logs** → cheapest high-value source here: the beacon must resolve its
  hostname first, so a query for an off-allowlist / non-corporate domain from a workload is
  a clean signal. In K8s, log **CoreDNS**.
- **Nothing security-specific yet?** Start with the **agent-trace detector** on your eval
  pipeline — it's shift-left, needs only your harness logs, and catches this before prod.

## Three gotchas that break this if you don't know them

1. **Instance metadata traffic is invisible to flow logs.** `169.254.169.254` (and
   `100.100.100.200` on Alibaba) are link-local; **AWS VPC Flow Logs and GCP/Azure flow
   logs do not record it.** The metadata rule must run on **host/runtime** telemetry
   (EDR / auditd / Falco) or via a cloud-native detector (GuardDuty). Don't expect to catch
   IMDS abuse in flow logs.
2. **Flow logs are IP-only — no hostname.** They show "workload talked to 47.x.x.x:443,"
   not "…to `*.aliyuncs.com`." Great for "connection to an unexpected external IP from a
   namespace that should have none," but you need **DNS logs or a proxy** to get the name
   the egress rule matches on.
3. **A WAF is the wrong layer.** WAFs (Cloudflare WAF, AWS WAF, ModSecurity) inspect
   **inbound** requests to your services. This behaviour is **outbound**. You need an
   **egress** control — a forward proxy / secure web gateway, or host/runtime telemetry.

## Where it lands (SIEM / pipeline)

The Sigma source converts (pySigma) to **Splunk, Microsoft Sentinel/Defender, Elastic,
Chronicle / Google SecOps, QRadar, Panther, Sumo Logic**. The three vendor queries in this
folder (`splunk/`, `sentinel/`, `elastic/`) are pre-converted starting points; map the
process fields to your schema (see `README.md` → Field mapping).
