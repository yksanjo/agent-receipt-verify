import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

from receipt_verify import canonical_hash, verify_lines

HERE = os.path.dirname(os.path.abspath(__file__))


def make_chain(n=4, base_ts="2026-10-31T12:00:00Z"):
    receipts = []
    prev_hash = "genesis"
    for i in range(n):
        r = {
            "seq": i,
            "ts": f"2026-10-31T12:00:{10 + i:02d}Z",
            "actor": "research-agent",
            "action": ["search", "read", "summarize", "file"][i % 4],
            "payload_hash": hashlib.sha256(f"payload-{i}".encode()).hexdigest(),
            "prev_hash": prev_hash,
        }
        r["receipt_hash"] = canonical_hash(r)
        prev_hash = r["receipt_hash"]
        receipts.append(r)
    return receipts


def to_lines(receipts):
    return [json.dumps(r) for r in receipts]


def rules(findings):
    return {f.rule for f in findings}


class TestIntactLog(unittest.TestCase):
    def test_clean_chain_has_no_findings(self):
        self.assertEqual(verify_lines(to_lines(make_chain())), [])

    def test_single_receipt_ok(self):
        self.assertEqual(verify_lines(to_lines(make_chain(1))), [])

    def test_blank_lines_skipped(self):
        lines = to_lines(make_chain(2))
        lines.insert(1, "   ")
        self.assertEqual(verify_lines(lines), [])

    def test_unknown_field_is_info(self):
        rs = make_chain(2)
        rs[0]["note"] = "synthetic"
        rs[0]["receipt_hash"] = canonical_hash(rs[0])
        rs[1]["prev_hash"] = rs[0]["receipt_hash"]
        rs[1]["receipt_hash"] = canonical_hash(rs[1])
        findings = verify_lines(to_lines(rs))
        self.assertEqual([f.rule for f in findings], ["unknown-field"])
        self.assertEqual(findings[0].severity, "info")

    def test_empty_input_is_info(self):
        findings = verify_lines(["", "  "])
        self.assertEqual([f.rule for f in findings], ["empty-log"])


class TestTampering(unittest.TestCase):
    def test_edited_receipt_fails_hash(self):
        rs = make_chain()
        rs[1]["action"] = "delete-everything"
        findings = verify_lines(to_lines(rs))
        self.assertIn("hash-mismatch", rules(findings))
        self.assertTrue(any(f.severity == "error" and f.rule == "hash-mismatch"
                            for f in findings))

    def test_deleted_receipt_breaks_chain(self):
        rs = make_chain()
        del rs[2]
        findings = verify_lines(to_lines(rs))
        self.assertIn("chain-break", rules(findings))
        self.assertIn("seq-gap", rules(findings))
        self.assertTrue(any(f.rule == "chain-break" and f.severity == "error"
                            for f in findings))
        self.assertTrue(any(f.rule == "seq-gap" and f.severity == "warning"
                            for f in findings))

    def test_reordered_receipts_flag(self):
        rs = make_chain()
        rs[1], rs[2] = rs[2], rs[1]
        findings = verify_lines(to_lines(rs))
        self.assertIn("chain-break", rules(findings))

    def test_seq_regression_is_error(self):
        rs = make_chain()
        rs.append(dict(rs[1]))  # duplicate seq 1 at the end
        findings = verify_lines(to_lines(rs))
        self.assertIn("seq-regression", rules(findings))
        self.assertTrue(any(f.rule == "seq-regression" and f.severity == "error"
                            for f in findings))

    def test_inserted_forged_receipt_fails(self):
        rs = make_chain()
        forged = {
            "seq": 4, "ts": "2026-10-31T12:00:50Z", "actor": "attacker",
            "action": "exfiltrate",
            "payload_hash": hashlib.sha256(b"stolen").hexdigest(),
            "prev_hash": rs[-1]["receipt_hash"],
        }
        forged["receipt_hash"] = hashlib.sha256(b"not-the-canon").hexdigest()
        rs.append(forged)
        findings = verify_lines(to_lines(rs))
        self.assertIn("hash-mismatch", rules(findings))


class TestMalformed(unittest.TestCase):
    def test_bad_json_line_is_error_and_chain_resets(self):
        lines = to_lines(make_chain(2)) + ["{not json"]
        findings = verify_lines(lines)
        self.assertIn("malformed-line", rules(findings))

    def test_missing_required_field_is_error(self):
        rs = make_chain(2)
        del rs[1]["actor"]
        findings = verify_lines(to_lines(rs))
        self.assertIn("missing-field", rules(findings))

    def test_missing_receipt_hash_is_error(self):
        rs = make_chain(2)
        del rs[1]["receipt_hash"]
        findings = verify_lines(to_lines(rs))
        self.assertIn("missing-field", rules(findings))

    def test_invalid_seq_type(self):
        rs = make_chain(2)
        rs[1]["seq"] = "1"
        rs[1]["receipt_hash"] = canonical_hash(rs[1])
        self.assertIn("invalid-seq", rules(verify_lines(to_lines(rs))))

    def test_invalid_timestamp(self):
        rs = make_chain(2)
        rs[1]["ts"] = "yesterday-ish"
        rs[1]["receipt_hash"] = canonical_hash(rs[1])
        self.assertIn("invalid-ts", rules(verify_lines(to_lines(rs))))


class TestTimestamps(unittest.TestCase):
    def test_small_backstep_within_skew_ok(self):
        rs = make_chain(2)
        rs[1]["ts"] = "2026-10-31T12:00:08Z"  # 2s before previous
        rs[1]["receipt_hash"] = canonical_hash(rs[1])
        self.assertEqual(verify_lines(to_lines(rs)), [])

    def test_large_backstep_warns(self):
        rs = make_chain(2)
        rs[1]["ts"] = "2026-10-31T11:59:00Z"  # 70s back
        rs[1]["receipt_hash"] = canonical_hash(rs[1])
        findings = verify_lines(to_lines(rs))
        self.assertEqual([f.rule for f in findings], ["ts-backstep"])
        self.assertEqual(findings[0].severity, "warning")

    def test_naive_timestamp_treated_as_utc(self):
        rs = make_chain(2)
        rs[1]["ts"] = "2026-10-31T12:00:11"
        rs[1]["receipt_hash"] = canonical_hash(rs[1])
        self.assertEqual(verify_lines(to_lines(rs)), [])


class TestCli(unittest.TestCase):
    def run_cli(self, lines, *extra):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl",
                                         delete=False) as fh:
            fh.write("\n".join(lines) + "\n")
            path = fh.name
        try:
            return subprocess.run(
                [sys.executable, os.path.join(HERE, "receipt_verify.py"),
                 path, "--json", *extra],
                capture_output=True, text=True)
        finally:
            os.unlink(path)

    def test_clean_log_exit_zero(self):
        result = self.run_cli(to_lines(make_chain()))
        self.assertEqual(result.returncode, 0)
        self.assertTrue(json.loads(result.stdout)["ok"])

    def test_tampered_log_exit_one(self):
        rs = make_chain()
        rs[2]["actor"] = "someone-else"
        result = self.run_cli(to_lines(rs))
        self.assertEqual(result.returncode, 1)
        self.assertFalse(json.loads(result.stdout)["ok"])

    def test_missing_file_exit_two(self):
        result = subprocess.run(
            [sys.executable, os.path.join(HERE, "receipt_verify.py"),
             "/nonexistent/receipts.jsonl"],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)

    def test_skew_flag_respected(self):
        rs = make_chain(2)
        rs[1]["ts"] = "2026-10-31T11:59:00Z"
        rs[1]["receipt_hash"] = canonical_hash(rs[1])
        result = self.run_cli(to_lines(rs), "--skew-seconds", "120")
        self.assertEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
