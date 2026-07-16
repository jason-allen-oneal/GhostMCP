import tempfile
import unittest
from pathlib import Path

from ghostmcp.database import Database


class DatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db = Database(str(Path(self.tempdir.name) / "ghostmcp.db"))

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_read_cursor_is_not_used_after_connection_close(self) -> None:
        created = self.db.create_engagement(
            "eng-1",
            "Internal review",
            scope_cidrs=["10.0.0.0/24"],
            max_tool_level="active",
        )
        loaded = self.db.get_engagement(created.id)
        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded.name, "Internal review")
        self.assertEqual(self.db.list_engagements(), [loaded])

    def test_scan_and_finding_lifecycle(self) -> None:
        self.db.create_engagement("eng-1", "Review")
        self.db.create_scan("scan-1", "eng-1", "nmap_service_scan_tool", "10.0.0.2")
        running = self.db.start_scan("scan-1")
        self.assertIsNotNone(running)
        assert running is not None
        self.assertEqual(running.status, "running")
        completed = self.db.complete_scan("scan-1", {"ports": [443]})
        self.assertIsNotNone(completed)
        assert completed is not None
        self.assertEqual(completed.status, "completed")
        self.db.add_finding(
            "finding-1",
            "scan-1",
            "open-port",
            "info",
            "HTTPS exposed",
            "Port 443 is reachable",
            target="10.0.0.2",
        )
        stats = self.db.get_engagement_stats("eng-1")
        self.assertEqual(stats["total_scans"], 1)
        self.assertEqual(stats["total_findings"], 1)

    def test_delete_engagement_cascades(self) -> None:
        self.db.create_engagement("eng-1", "Review")
        self.db.create_scan("scan-1", "eng-1", "nmap_service_scan_tool", "10.0.0.2")
        self.db.add_finding(
            "finding-1", "scan-1", "open-port", "info", "HTTPS exposed", ""
        )
        self.assertTrue(self.db.delete_engagement("eng-1"))
        self.assertIsNone(self.db.get_scan("scan-1"))
        self.assertEqual(self.db.get_findings("scan-1"), [])


if __name__ == "__main__":
    unittest.main()
