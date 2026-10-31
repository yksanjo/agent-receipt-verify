#!/usr/bin/env python3
"""Demo: verify an intact receipt chain, then a tampered one (all synthetic)."""

import hashlib
import json
import os
import subprocess
import sys
import tempfile

from receipt_verify import canonical_hash

HERE = os.path.dirname(os.path.abspath(__file__))


def make_chain():
    receipts = []
    prev_hash = "genesis"
    steps = [
        ("planner", "decompose-task"),
        ("research-agent", "web-search"),
        ("research-agent", "read-page"),
        ("writer-agent", "draft-summary"),
        ("orchestrator", "file-result"),
    ]
    for i, (actor, action) in enumerate(steps):
        r = {
            "seq": i,
            "ts": f"2026-10-31T12:00:{10 + i:02d}Z",
            "actor": actor,
            "action": action,
            "payload_hash": hashlib.sha256(
                f"payload-{i}".encode()).hexdigest(),
            "prev_hash": prev_hash,
        }
        r["receipt_hash"] = canonical_hash(r)
        prev_hash = r["receipt_hash"]
        receipts.append(r)
    return receipts


def run(name, receipts):
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl",
                                     delete=False) as fh:
        fh.write("\n".join(json.dumps(r) for r in receipts) + "\n")
        path = fh.name
    try:
        print(f"=== {name} ===")
        result = subprocess.run(
            [sys.executable, os.path.join(HERE, "receipt_verify.py"), path],
            capture_output=True, text=True)
        print(result.stdout, end="")
        print(f"(exit {result.returncode})\n")
    finally:
        os.unlink(path)


if __name__ == "__main__":
    intact = make_chain()
    run("intact chain (5 receipts)", intact)

    tampered = make_chain()
    del tampered[2]                       # a receipt quietly removed
    tampered[1]["action"] = "exfiltrate"  # and another edited after the fact
    run("tampered chain (one receipt deleted, one edited)", tampered)
