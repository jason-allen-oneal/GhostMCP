import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

from ghostmcp.database import Database
from ghostmcp.execution import (
    EXECUTORS,
    ExecutorDefinition,
    ScanExecutor,
    ScanScheduler,
    ScanWorker,
)


class ExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.database = Database(str(Path(self.tempdir.name) / "ghostmcp.db"))
        self.database.create_engagement(
            "eng-1",
            "Internal assessment",
            scope_cidrs=["10.0.0.0/24"],
            max_tool_level="active",
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_executor_completes_registered_scan(self) -> None:
        self.database.create_scan("scan-1", "eng-1", "fake_tool", "10.0.0.2")
        definition = ExecutorDefinition(
            level="active",
            binary=None,
            run=lambda _policy, target, _params: {"target": target, "ok": True},
        )
        with patch.dict(EXECUTORS, {"fake_tool": definition}, clear=False):
            completed = ScanExecutor(self.database).execute("scan-1")
        self.assertEqual(completed.status, "completed")
        self.assertEqual(completed.result, {"target": "10.0.0.2", "ok": True})

    def test_executor_enforces_engagement_tool_ceiling(self) -> None:
        self.database.create_scan("scan-1", "eng-1", "fake_intrusive", "10.0.0.2")
        definition = ExecutorDefinition(
            level="intrusive",
            binary=None,
            run=lambda _policy, _target, _params: {},
        )
        with patch.dict(EXECUTORS, {"fake_intrusive": definition}, clear=False):
            completed = ScanExecutor(self.database).execute("scan-1")
        self.assertEqual(completed.status, "failed")
        self.assertIn("exceeds engagement max", completed.error or "")

    def test_worker_processes_queued_scan(self) -> None:
        worker = ScanWorker(self.database)
        worker.executor.execute = Mock()
        worker.start()
        try:
            worker.submit("scan-1")
            worker._queue.join()
        finally:
            worker.stop()
        worker.executor.execute.assert_called_once_with("scan-1")

    def test_worker_survives_unhandled_executor_error(self) -> None:
        worker = ScanWorker(self.database)
        worker.executor.execute = Mock(side_effect=[RuntimeError("boom"), None])
        worker.start()
        try:
            worker.submit("scan-1")
            worker.submit("scan-2")
            worker._queue.join()
        finally:
            worker.stop()
        self.assertEqual(worker.executor.execute.call_count, 2)

    def test_scheduler_creates_and_submits_due_scan(self) -> None:
        now = datetime(2026, 7, 15, 20, 0, tzinfo=UTC)
        self.database.create_schedule(
            "schedule-1",
            "eng-1",
            "whatweb_tool",
            "https://10.0.0.2",
            {},
            "*/5 * * * *",
            (now - timedelta(minutes=1)).isoformat(),
        )
        fake_worker = Mock()
        scheduler = ScanScheduler(self.database, fake_worker, poll_seconds=60)
        self.assertEqual(scheduler.run_due_once(now), 1)
        fake_worker.submit.assert_called_once()
        schedules = self.database.list_schedules("eng-1")
        self.assertEqual(len(schedules), 1)
        self.assertGreater(datetime.fromisoformat(schedules[0].next_run_at), now)
        scans = self.database.list_scans("eng-1")
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0].status, "queued")
        self.assertIsNone(schedules[0].claimed_until)


if __name__ == "__main__":
    unittest.main()
