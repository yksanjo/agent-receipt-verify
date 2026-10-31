# agent-receipt-verify

Verify a hash-chained agent action receipt log - find where the evidence
stops holding.

Agents that act on the world should leave receipts: one JSON object per
action, chained by hash so that later edits, deletions and insertions show
up as breaks. `agent-receipt-verify` checks such a log offline: chain
continuity, receipt-hash correctness, sequence integrity, timestamp order.
It answers one question precisely: **does this log still say what it said
when it was written?**

Severity is deliberate: anything consistent with a tampered or spliced log
(hash mismatch, chain break, sequence regression) is an error. Properties
that are legitimate in a filtered export (sequence gaps, small clock
backsteps) are warnings, so honest logs do not fail.

Exit codes: `0` no errors, `1` any error, `2` usage/input problems.

## Requirements

Python 3.10+. Standard library only - no dependencies, no network.

## Usage

```
python3 receipt_verify.py receipts.jsonl
python3 receipt_verify.py receipts.jsonl --json
python3 receipt_verify.py receipts.jsonl --skew-seconds 30
```

Run the demo and tests:

```
python3 demo.py
python3 -m unittest test_receipt_verify
```

## Receipt convention

One JSON object per line:

```json
{"seq": 0, "ts": "2026-10-31T12:00:10Z", "actor": "research-agent",
 "action": "web-search", "payload_hash": "<sha256 of the action payload>",
 "prev_hash": "genesis", "receipt_hash": "<sha256 of canonical JSON of the above>"}
```

`receipt_hash` is the sha256 of the canonical JSON (sorted keys, compact
separators) of every field except itself; `prev_hash` chains each receipt
to the previous one (`"genesis"` first). This is a documented convention
for this tool - any emitter that follows it can use the verifier, whatever
produced the log.

## Rules

| rule | severity | what it catches |
|------|----------|-----------------|
| `malformed-line` / `missing-field` / `invalid-seq` / `invalid-ts` | error | unreadable or incomplete receipts |
| `hash-mismatch` | error | receipt contents edited after emission |
| `chain-break` | error | `prev_hash` does not match the previous `receipt_hash` (splice, mid-log deletion, reorder) |
| `seq-regression` | error | sequence goes backwards or repeats |
| `seq-gap` | warning | sequence jumps - filtered export, or dropped receipts |
| `ts-backstep` | warning | timestamp earlier than the previous receipt beyond `--skew-seconds` |
| `unknown-field` / `empty-log` | info | housekeeping |

## Limits

- **Integrity, not authorization.** A verified chain proves the log was not
  edited after emission. It says nothing about whether the actions were
  permitted, correct, or worth doing - pair it with a preflight boundary or
  approval audit for that.
- **Hash-chaining is not signing.** Anyone who can write the log can forge a
  fresh chain from scratch. This detects *after-the-fact edits to an
  existing* chain, not a wholesale replacement with a newly minted one;
  anchoring (publishing a head hash elsewhere) is the emitter's job.
- **Tail truncation is invisible without anchoring.** Dropping the last N
  receipts leaves a perfectly valid shorter chain. Catching it requires an
  externally anchored expected head hash or receipt count, which this tool
  does not have.
- **Does not execute or replay actions.** Payload hashes are checked for
  presence and chain math, never recomputed from real payloads.
- **Heuristics, not proof.** A clean result means no detectable tampering
  under this convention, not that the log is trustworthy in every sense.
- All demo and test data is synthetic.

## License

MIT - see [LICENSE](LICENSE).
