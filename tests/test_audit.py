import json
import tempfile
import unittest
from pathlib import Path

from ghostmcp.audit import AuditChain, verify_audit_log


class AuditChainTests(unittest.TestCase):
    def test_signed_chain_persists_across_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            key = b"k" * 32
            first = AuditChain(str(path), hmac_key=key, fsync=True)
            event_one = first.append({"tool": "dns", "target": "example.test"})
            second = AuditChain(str(path), hmac_key=key)
            event_two = second.append({"tool": "tls", "target": "example.test"})
            self.assertEqual(event_two["prev_hash"], event_one["event_hash"])
            result = verify_audit_log(str(path), key)
            self.assertEqual(result["status"], "success")
            self.assertEqual(result["events_processed"], 2)
            self.assertTrue(result["signed"])

    def test_tampering_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            key = b"s" * 32
            chain = AuditChain(str(path), hmac_key=key)
            chain.append({"tool": "dns", "target": "10.0.0.1"})
            event = json.loads(path.read_text(encoding="utf-8"))
            event["target"] = "8.8.8.8"
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")
            result = verify_audit_log(str(path), key)
            self.assertEqual(result["status"], "failed")
            self.assertIn("event hash mismatch", " ".join(result["errors"]))
            with self.assertRaises(RuntimeError):
                AuditChain(str(path), hmac_key=key)


if __name__ == "__main__":
    unittest.main()
