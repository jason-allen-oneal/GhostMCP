import os
import sys
import types
import unittest
from typing import get_args, get_type_hints
from unittest.mock import patch

os.environ.setdefault("GHOSTMCP_REQUIRE_ENGAGEMENT_CONTEXT", "false")

if "mcp.server.fastmcp" not in sys.modules:
    mcp_module = types.ModuleType("mcp")
    mcp_server_module = types.ModuleType("mcp.server")
    fastmcp_module = types.ModuleType("mcp.server.fastmcp")

    class _FakeFastMCP:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def tool(self):
            def decorator(fn):
                return fn

            return decorator

        def run(self) -> None:
            return None

    fastmcp_module.FastMCP = _FakeFastMCP
    sys.modules["mcp"] = mcp_module
    sys.modules["mcp.server"] = mcp_server_module
    sys.modules["mcp.server.fastmcp"] = fastmcp_module

import ghostmcp.server as server


class ServerControlTests(unittest.TestCase):
    def test_validate_raw_args_blocks_shell_tokens(self) -> None:
        with self.assertRaises(ValueError):
            server._validate_raw_tool_args("nmap", ["-sV", "$(id)"])

    def test_validate_raw_args_accepts_safe_flags(self) -> None:
        args = server._validate_raw_tool_args("nmap", ["-sV", "-Pn"])
        self.assertEqual(args, ["-sV", "-Pn"])

    def test_raw_tool_registration_is_disabled_by_default(self) -> None:
        with patch("ghostmcp.server.ENABLE_RAW_TOOLS", False):
            with patch.object(server.mcp, "tool") as register:
                server._register_dynamic_kali_raw_tools()
        register.assert_not_called()

    def test_remote_authorization_requires_transport_principal(self) -> None:
        with patch("ghostmcp.server.TRANSPORT_MODE", "remote_gateway"):
            with patch("ghostmcp.server.AUTH_MODE", "token"):
                with patch("ghostmcp.server.AUTH_TOKEN", "secret"):
                    with self.assertRaises(PermissionError):
                        server._authorize(
                            "x",
                            "passive",
                            engagement_id="eng-1",
                            engagement_mode="passive",
                            auth_token="wrong",
                        )

    def test_authorize_accepts_default_engagement_mode_alias(self) -> None:
        with patch("ghostmcp.server.rate_limiter.allow", return_value=True):
            context = server._authorize(
                "runtime_probe_tool",
                "passive",
                engagement_id=None,
                engagement_mode="default",
            )
        self.assertEqual(context["engagement_mode"], "passive")
        self.assertEqual(context["tool_level"], "passive")

    def test_runtime_probe_accepts_default_engagement_mode_alias(self) -> None:
        with patch("ghostmcp.server.rate_limiter.allow", return_value=True):
            payload = server.runtime_probe_tool(engagement_mode="default")
        self.assertIn(payload["status"], {"ready", "stopping"})

    def test_runtime_probe_type_hints_advertise_default_engagement_mode_alias(self) -> None:
        engagement_mode_hint = get_type_hints(server.runtime_probe_tool)["engagement_mode"]
        self.assertEqual(
            get_args(engagement_mode_hint),
            ("default", "passive", "active", "intrusive"),
        )


if __name__ == "__main__":
    unittest.main()
