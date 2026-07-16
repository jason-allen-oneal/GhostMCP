import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from ghostmcp.workflows import (
    host_exposure_assessment,
    tls_posture_assessment,
    web_surface_assessment,
)


class WorkflowTests(unittest.TestCase):
    def test_web_surface_normalizes_steps(self) -> None:
        policy = Mock()
        with (
            patch("ghostmcp.workflows.http_probe", return_value={"status": 200}),
            patch("ghostmcp.workflows.shutil.which", return_value=None),
        ):
            result = web_surface_assessment(policy, "https://example.test", "GhostMCP")
        policy.validate_url.assert_called_once_with("https://example.test")
        self.assertEqual(result["summary"], {"ok": 1, "failed": 0, "skipped": 0})

    def test_tls_workflow_includes_certificate_and_expiry(self) -> None:
        policy = Mock()
        policy.validate_target.return_value = SimpleNamespace(host="10.0.0.2")
        policy.parse_ports.return_value = [443]
        with (
            patch("ghostmcp.workflows.tls_certificate", return_value={"subject": []}),
            patch(
                "ghostmcp.workflows.tls_certificate_expiry",
                return_value={"days_remaining": 30},
            ),
            patch("ghostmcp.workflows.shutil.which", return_value=None),
        ):
            result = tls_posture_assessment(policy, "internal.test", 443)
        self.assertEqual(result["summary"]["ok"], 2)

    def test_host_exposure_returns_open_port_count(self) -> None:
        policy = Mock()
        policy.validate_target.return_value = SimpleNamespace(host="10.0.0.2")
        policy.parse_ports.return_value = [80, 443]
        policy.config.max_concurrent_connects = 8
        with patch(
            "ghostmcp.workflows.port_scan",
            return_value={
                "results": [
                    {"port": 80, "state": "closed"},
                    {"port": 443, "state": "open"},
                ]
            },
        ):
            result = host_exposure_assessment(policy, "internal.test", [80, 443], 500)
        self.assertEqual(result["summary"], {"ports_checked": 2, "open_ports": 1})


if __name__ == "__main__":
    unittest.main()
