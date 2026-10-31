"""Allowlist-relative + jurisdiction-aware egress policy — the shared core of the detections.

Fidelity principle: in an AI lab, egress to cloud storage is routine. The signals are a
destination that is NOT on the sanctioned allowlist, a cloud instance-metadata endpoint, or
a destination under a watched legal jurisdiction (data-residency / exfiltration-surface
risk). This module encodes all three once; the trace detector and the regression validator
import it, and the Sigma/Falco rules mirror it.

No third-party dependencies (stdlib only).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

_URL_RE = re.compile(r"""https?://(?:[^/@\s"'<>|)\\]*@)?([^/\s"'<>|)\\]+)(/[^\s"'<>|)\\]*)?""",
                     re.IGNORECASE)

UPLOAD_INTENT = ("-X PUT", "-XPUT", "-X POST", "--data-binary", "--upload-file",
                 " -T ", "--post-file", "-d @", "--data @")

_HERE = Path(__file__).resolve().parent
DEFAULT_POLICY = _HERE / "allowlist.json"
DEFAULT_JURIS = _HERE / "jurisdictions.json"


def load_policy(path: str | Path | None = None) -> dict:
    return json.loads(Path(path or DEFAULT_POLICY).read_text(encoding="utf-8"))


def load_jurisdictions(path: str | Path | None = None) -> dict | None:
    p = Path(path or DEFAULT_JURIS)
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


_JURIS_UNSET = object()
_juris_cache: object = _JURIS_UNSET


def _default_juris():
    global _juris_cache
    if _juris_cache is _JURIS_UNSET:
        _juris_cache = load_jurisdictions()
    return _juris_cache


def _host_of(url_host: str) -> str:
    return url_host.split(":")[0].lower()


def _is_allowed(host: str, full: str, pol: dict) -> bool:
    if host in {h.lower() for h in pol.get("allow_hosts", [])}:
        return True
    for pat in pol.get("allow_url_patterns", []):
        if re.fullmatch(pat, host) or re.search(pat, full):
            return True
    return False


def _match_jurisdiction(host: str, juris: dict | None):
    """Return (code, label) if host is under a watched jurisdiction, else None."""
    if not juris:
        return None
    specs = juris.get("jurisdictions", {})
    for code in juris.get("enabled_watchlists", []):
        spec = specs.get(code)
        if not spec:
            continue
        if any(re.search(p, host) for p in spec.get("host_patterns", [])):
            return code, spec.get("label", code)
        if any(host.endswith(t) for t in spec.get("tlds", [])):
            return code, spec.get("label", code)
    cust = juris.get("custom", {})
    if any(re.search(p, host) for p in cust.get("host_patterns", [])) \
            or any(host.endswith(t) for t in cust.get("tlds", [])):
        return "CUSTOM", "custom watchlist"
    return None


def evaluate(command: str, pol: dict, juris: dict | None = None) -> list[dict]:
    """Egress-policy findings for a single command line / tool-call string."""
    if juris is None:
        juris = _default_juris()
    findings, seen = [], set()
    deny = pol.get("deny_always", [])
    upload = any(tok in command for tok in UPLOAD_INTENT)

    for d in deny:
        if d in command and ("deny", d) not in seen:
            seen.add(("deny", d))
            findings.append({
                "destination": d, "verdict": "deny_always", "severity": "critical",
                "reason": "cloud instance metadata / always-deny destination (SSRF, credential theft)",
                "attack": "T1552.005", "upload": upload})

    for m in _URL_RE.finditer(command):
        host = _host_of(m.group(1))
        full = host + (m.group(2) or "")
        if host in set(deny) or ("host", host) in seen:
            continue
        seen.add(("host", host))
        if _is_allowed(host, full, pol):
            continue
        j = _match_jurisdiction(host, juris)
        if j:
            code, label = j
            findings.append({
                "destination": host, "verdict": "jurisdiction", "jurisdiction": code,
                "severity": "high", "upload": upload, "attack": "T1567.002",
                "reason": f"egress to {label} ({code}) cloud infrastructure — "
                          f"data-residency / exfiltration-surface risk"})
        else:
            findings.append({
                "destination": host, "verdict": "unsanctioned", "upload": upload,
                "severity": "high" if upload else "medium",
                "reason": ("upload to a destination outside the sanctioned allowlist"
                           if upload else "egress to a destination outside the sanctioned allowlist"),
                "attack": "T1567.002" if upload else "T1071.001"})
    return findings
