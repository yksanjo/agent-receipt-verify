#!/usr/bin/env python3
"""agent-receipt-verify: verify a hash-chained agent action receipt log.

Agents that act on the world should leave receipts: one JSON object per
action, chained by hash so later edits and mid-log deletions or insertions
show up as breaks. This tool verifies such a log offline - chain continuity, receipt
hash correctness, sequence integrity, timestamp order - and reports exactly
where the evidence stops holding.

Severity is deliberate: anything consistent with a tampered or spliced log
(hash mismatch, chain break, sequence regression) is an error. Properties
that can be legitimate in a filtered export (sequence gaps, missing optional
fields, clock backsteps within skew tolerance) are warnings or info.

Exit codes: 0 no errors, 1 any error, 2 usage/input problems.
Standard library only; no network. It verifies the log; it does not prove
the actions themselves were authorized or correct.

Receipt convention (one JSON object per line):
  seq          integer, 0-based, increasing by 1 per emission
  ts           ISO-8601 UTC timestamp of the action
  actor        who acted (agent or tool name)
  action       what was done
  payload_hash sha256 hex of the action payload (whatever the emitter signed over)
  prev_hash    receipt_hash of the previous receipt ("genesis" for seq 0)
  receipt_hash sha256 hex of the canonical JSON of all fields above
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone

REQUIRED_FIELDS = ["seq", "ts", "actor", "action", "payload_hash", "prev_hash"]
ALL_FIELDS = REQUIRED_FIELDS + ["receipt_hash"]
GENESIS = "genesis"
DEFAULT_SKEW_SECONDS = 5


@dataclass
class Finding:
    severity: str  # "error" | "warning" | "info"
    rule: str
    detail: str

    def render(self) -> str:
        return f"[{self.severity:7s}] {self.rule:22s} {self.detail}"


def canonical_hash(receipt: dict) -> str:
    """sha256 over the canonical JSON of every field except receipt_hash."""
    body = {k: receipt[k] for k in receipt if k != "receipt_hash"}
    blob = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _parse_ts(value: str) -> datetime | None:
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts


def verify_lines(lines: list[str],
                 skew_seconds: int = DEFAULT_SKEW_SECONDS) -> list[Finding]:
    findings: list[Finding] = []
    prev_hash = GENESIS
    prev_seq: int | None = None
    prev_ts: datetime | None = None
    receipts = 0

    for lineno, raw in enumerate(lines, start=1):
        where = f"line {lineno}"
        if not raw.strip():
            continue
        try:
            receipt = json.loads(raw)
        except json.JSONDecodeError as exc:
            findings.append(Finding("error", "malformed-line",
                                    f"{where} is not valid JSON: {exc.msg}"))
            # keep verifying structure with what we can; chain position is lost
            prev_hash = GENESIS
            prev_seq = None
            prev_ts = None
            continue
        if not isinstance(receipt, dict):
            findings.append(Finding("error", "malformed-line",
                                    f"{where} is not a JSON object"))
            prev_hash = GENESIS
            prev_seq = None
            prev_ts = None
            continue

        receipts += 1
        seq = receipt.get("seq")

        missing = [f for f in REQUIRED_FIELDS if f not in receipt]
        if missing:
            findings.append(Finding("error", "missing-field",
                                    f"{where} (seq {seq!r}) missing: "
                                    + ", ".join(missing)))
            prev_hash = GENESIS
            prev_seq = None
            prev_ts = None
            continue

        unknown = sorted(set(receipt) - set(ALL_FIELDS))
        if unknown:
            findings.append(Finding("info", "unknown-field",
                                    f"{where} (seq {seq}) has unrecognized "
                                    "fields: " + ", ".join(unknown)))

        # sequence integrity
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
            findings.append(Finding("error", "invalid-seq",
                                    f"{where} seq {seq!r} is not a "
                                    "non-negative integer"))
        elif prev_seq is not None:
            if seq <= prev_seq:
                findings.append(Finding("error", "seq-regression",
                                        f"{where} seq {seq} follows seq "
                                        f"{prev_seq}; order or duplication "
                                        "breaks the trail"))
            elif seq > prev_seq + 1:
                findings.append(Finding("warning", "seq-gap",
                                        f"{where} seq jumps {prev_seq} -> "
                                        f"{seq}; consistent with a filtered "
                                        "export, or with dropped receipts"))

        # chain continuity
        if receipt["prev_hash"] != prev_hash:
            findings.append(Finding("error", "chain-break",
                                    f"{where} (seq {seq}) prev_hash does not "
                                    "match the previous receipt_hash; the log "
                                    "was spliced, had non-final receipts "
                                    "deleted, or was reordered"))

        # hash correctness (tamper evidence)
        if "receipt_hash" not in receipt:
            findings.append(Finding("error", "missing-field",
                                    f"{where} (seq {seq}) missing: "
                                    "receipt_hash"))
            prev_hash = GENESIS
        else:
            actual = canonical_hash(receipt)
            if receipt["receipt_hash"] != actual:
                findings.append(Finding("error", "hash-mismatch",
                                        f"{where} (seq {seq}) receipt_hash "
                                        "does not match its contents; the "
                                        "receipt was edited after emission"))
            prev_hash = receipt["receipt_hash"]

        # timestamp order
        ts = _parse_ts(receipt["ts"]) if isinstance(receipt["ts"], str) else None
        if ts is None:
            findings.append(Finding("error", "invalid-ts",
                                    f"{where} (seq {seq}) ts "
                                    f"{receipt['ts']!r} is not an ISO-8601 "
                                    "timestamp"))
        elif prev_ts is not None:
            backstep = (prev_ts - ts).total_seconds()
            if backstep > skew_seconds:
                findings.append(Finding("warning", "ts-backstep",
                                        f"{where} (seq {seq}) timestamp is "
                                        f"{backstep:.0f}s earlier than the "
                                        "previous receipt; clock skew or "
                                        "reordering"))
        prev_ts = ts
        if isinstance(seq, int) and not isinstance(seq, bool):
            prev_seq = seq

    if receipts == 0:
        findings.append(Finding("info", "empty-log",
                                "no receipts found in input"))

    order = {"error": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: order[f.severity])
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agent-receipt-verify",
        description="Verify a hash-chained agent action receipt log (JSONL).")
    parser.add_argument("log", help="path to the JSONL receipt log")
    parser.add_argument("--json", action="store_true",
                        help="emit findings as JSON")
    parser.add_argument("--skew-seconds", type=int,
                        default=DEFAULT_SKEW_SECONDS,
                        help="tolerated timestamp backstep (default 5)")
    args = parser.parse_args(argv)

    try:
        with open(args.log, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError as exc:
        print(f"agent-receipt-verify: cannot read log: {exc}",
              file=sys.stderr)
        return 2

    findings = verify_lines(lines, skew_seconds=args.skew_seconds)
    errors = sum(1 for f in findings if f.severity == "error")
    warnings = sum(1 for f in findings if f.severity == "warning")
    infos = sum(1 for f in findings if f.severity == "info")

    if args.json:
        print(json.dumps({
            "errors": errors,
            "warnings": warnings,
            "infos": infos,
            "ok": errors == 0,
            "findings": [f.__dict__ for f in findings],
        }, indent=2))
    else:
        print(f"agent-receipt-verify: {errors} error(s), {warnings} "
              f"warning(s), {infos} info")
        for f in findings:
            print("  " + f.render())
        if not findings:
            print("  no findings: chain intact, hashes correct, sequence "
                  "and timestamps in order")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
