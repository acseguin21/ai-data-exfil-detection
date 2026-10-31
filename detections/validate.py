#!/usr/bin/env python3
"""Regression test for the egress policy — prove it is signal, not noise.

Runs the allowlist-relative + jurisdiction-aware policy over two corpora:
  - tests/benign_ml_ops.txt    : routine AI-lab commands. MUST yield 0 findings (false pos).
  - tests/malicious_egress.txt : the behaviour + variants. MUST all yield findings (true pos).

Reports true positives, false positives and precision, with a jurisdiction breakdown. Exit 0
only if every benign command is clean AND every malicious command is caught — so a policy,
allowlist or jurisdiction change that starts alerting on normal ML ops, or stops catching
the exfil, fails the build. Use it as the CI gate and as a quick local regression check.
"""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import egress_policy as ep


def _lines(name: str) -> list[str]:
    p = HERE / "tests" / name
    if not p.exists():
        return []
    return [l.strip() for l in p.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.strip().startswith("#")]


def main() -> int:
    pol = ep.load_policy()
    benign = _lines("benign_ml_ops.txt")
    malicious = _lines("malicious_egress.txt")

    benign_hits = [(c, ep.evaluate(c, pol)) for c in benign]
    mal_hits = [(c, ep.evaluate(c, pol)) for c in malicious]

    false_pos = [(c, f) for c, f in benign_hits if f]
    true_pos = [(c, f) for c, f in mal_hits if f]
    false_neg = [c for c, f in mal_hits if not f]

    print(f"[validate] benign ML-ops commands : {len(benign)}")
    print(f"[validate]   false positives       : {len(false_pos)}  (target 0)")
    for c, f in false_pos:
        print(f"             x FP: {f[0]['destination']}  <-  {c[:80]}")
    print(f"[validate] malicious commands      : {len(malicious)}")
    print(f"[validate]   true positives        : {len(true_pos)}/{len(malicious)}")
    for c in false_neg:
        print(f"             x MISSED: {c[:90]}")

    detections = len(true_pos) + len(false_pos)
    precision = (len(true_pos) / detections * 100) if detections else 0.0
    print(f"[validate] precision on this corpus: {precision:.1f}%")

    juris = Counter(fi["jurisdiction"] for _, f in true_pos for fi in f
                    if fi.get("verdict") == "jurisdiction")
    if juris:
        print("[validate] jurisdiction watchlist hits: " +
              ", ".join(f"{k}={v}" for k, v in sorted(juris.items())))

    ok = not false_pos and not false_neg
    print("\n[validate] " + ("PASS — zero false positives, all exfil caught."
                             if ok else "FAIL — see FP/MISSED above."))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
