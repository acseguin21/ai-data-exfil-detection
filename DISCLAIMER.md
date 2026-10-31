# Responsible use

This repository is defensive detection content — rules, policy logic, and tests for spotting
unsolicited egress by model-driven processes. A few things to use it responsibly:

- **The indicators are model-generated and unverified.** The hostnames observed in the
  investigation are strings a model emitted, not confirmed attacker infrastructure. They
  vary per occurrence and some are legitimate public services. Do **not** import
  `indicators/` as a blocklist or threat-intel feed. Detect with the behavioural and
  jurisdiction rules; treat the observed hosts as reference only. See
  `detections/indicators/observed_indicators.json` for the per-tier caveats.

- **Jurisdiction markers are a signal, not attribution.** They identify where infrastructure
  is operated for data-residency purposes; they do not prove intent or origin, and are
  defeated by relaying through infrastructure elsewhere.

- **The rules are starting points to tune.** Deploy the zero-baseline rules (metadata,
  jurisdiction) first; scope the allowlist rule to your environment. Validate before you
  alert on production (`python detections/validate.py`).

- **If you reproduce the behaviour to test** (see `detections/TESTING.md`), keep it on
  infrastructure you control and never send data to a destination you do not own.

Built on a publicly documented investigation; not affiliated with any model vendor or cloud
provider.
