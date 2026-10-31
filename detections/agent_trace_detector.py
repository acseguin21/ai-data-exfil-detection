#!/usr/bin/env python3
"""Shift-left egress detector for AI agent / eval traces.

The earliest and highest-fidelity place to catch this behaviour is BEFORE a model ships:
in the eval/agent harness itself, where a sandboxed rollout should make no unsanctioned
egress at all. Point this at a rollout trace (the CohereLabs dataset's JSONL, your own eval
logs, or this repo's out/trials.jsonl / out/transcript.jsonl) and it flags every tool call
that reaches a destination off the sandbox allowlist, or a metadata endpoint.

Usage:
    python detections/agent_trace_detector.py <trace.jsonl> [--policy allowlist.json] [--json]

Reads common shapes: {"command": ...}, {"completion": ...}, or messages/tool-calls with a
bash/shell command. Exit 2 if any finding, else 0 — so it can gate an eval pipeline.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import egress_policy as ep


def _strings_from(obj) -> list[str]:
    """Pull candidate command/text strings out of a heterogeneous trace record."""
    out = []
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for k in ("command", "completion", "text", "content", "arguments", "cmd"):
            v = obj.get(k)
            if isinstance(v, str):
                out.append(v)
            elif isinstance(v, dict):
                out.extend(_strings_from(v))
        # tool-call shapes: {"message": {...}} / {"toolCall": {...}} / nested content lists
        for k in ("message", "toolCall", "tool_call"):
            if k in obj:
                out.extend(_strings_from(obj[k]))
        c = obj.get("content")
        if isinstance(c, list):
            for item in c:
                out.extend(_strings_from(item))
    elif isinstance(obj, list):
        for item in obj:
            out.extend(_strings_from(item))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("trace", help="JSONL trace file")
    ap.add_argument("--policy", default=None)
    ap.add_argument("--json", action="store_true", help="emit findings as JSON")
    args = ap.parse_args()

    pol = ep.load_policy(args.policy)
    findings = []
    for i, line in enumerate(Path(args.trace).read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            rec = line
        for s in _strings_from(rec):
            for f in ep.evaluate(s, pol):
                f["record"] = i
                findings.append(f)

    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        if not findings:
            print(f"[trace-detector] no unsanctioned egress in {args.trace}. ✔")
        for f in findings:
            print(f"[{f['severity'].upper():>8}] record {f['record']}: {f['verdict']} -> "
                  f"{f['destination']}  ({f['attack']}; {f['reason']})")
        print(f"\n[trace-detector] {len(findings)} finding(s) in {args.trace}")
    return 2 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
