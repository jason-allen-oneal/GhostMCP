import unittest
from unittest.mock import patch

from ghostmcp.plugins import Plugin, PluginManager


class AllowedPlugin(Plugin):
    @property
    def name(self) -> str:
        return "allowed"

    @property
    def version(self) -> str:
        return "1.0.0"

    def register_tools(self, mcp):
        return ["allowed_tool"]

    def register_parsers(self):
        return {"allowed_parser": lambda value: value}


class FakeEntryPoint:
    name = "allowed"

    @staticmethod
    def load():
        return AllowedPlugin


class PluginHardeningTests(unittest.TestCase):
    def test_plugin_loading_requires_allowlist(self) -> None:
        manager = PluginManager()
        with self.assertRaises(RuntimeError):
            manager.load_plugins(allowlist=[])

    @patch("ghostmcp.plugins.importlib.metadata.entry_points")
    def test_only_allowlisted_plugin_is_loaded(self, entry_points) -> None:
        entry_points.return_value = [FakeEntryPoint()]
        manager = PluginManager()
        self.assertEqual(manager.load_plugins(allowlist=["allowed"]), ["allowed"])
        self.assertEqual(
            manager.register_plugin_tools(object()),
            {"allowed": ["allowed_tool"]},
        )

    @patch("ghostmcp.plugins.importlib.metadata.entry_points")
    def test_missing_allowlisted_plugin_fails_closed(self, entry_points) -> None:
        entry_points.return_value = []
        manager = PluginManager()
        with self.assertRaises(RuntimeError):
            manager.load_plugins(allowlist=["missing"])


if __name__ == "__main__":
    unittest.main()
