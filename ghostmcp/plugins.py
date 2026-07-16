"""Explicitly allowlisted plugin loading for GhostMCP."""

from __future__ import annotations

import importlib.metadata
import logging
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable
from typing import Any

logger = logging.getLogger(__name__)


class Plugin(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError

    @property
    @abstractmethod
    def version(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def register_tools(self, mcp: Any) -> list[str]:
        raise NotImplementedError

    @abstractmethod
    def register_parsers(self) -> dict[str, Callable[..., Any]]:
        raise NotImplementedError

    def get_config_schema(self) -> dict[str, Any]:
        return {}

    def validate_config(self, config: dict[str, Any]) -> bool:
        return True


class PluginManager:
    def __init__(self) -> None:
        self._plugins: dict[str, Plugin] = {}
        self._tool_to_plugin: dict[str, str] = {}

    def load_plugins(
        self,
        entry_point_group: str = "ghostmcp.plugins",
        *,
        allowlist: Iterable[str],
    ) -> list[str]:
        allowed = {name.strip() for name in allowlist if name.strip()}
        if not allowed:
            raise RuntimeError("Plugin loading requires a non-empty allowlist")

        loaded: list[str] = []
        for entry_point in importlib.metadata.entry_points(group=entry_point_group):
            if entry_point.name not in allowed:
                continue
            try:
                plugin_class = entry_point.load()
                plugin = plugin_class()
                if not isinstance(plugin, Plugin):
                    raise TypeError("Plugin entry point must instantiate Plugin")
                if plugin.name not in allowed:
                    raise RuntimeError(
                        f"Plugin name {plugin.name!r} is not explicitly allowlisted"
                    )
                self.register_plugin(plugin)
                loaded.append(plugin.name)
                logger.info("Loaded plugin: %s v%s", plugin.name, plugin.version)
            except Exception:
                logger.exception("Failed to load plugin entry point: %s", entry_point.name)
                raise
        missing = allowed - set(loaded)
        if missing:
            raise RuntimeError(f"Allowlisted plugins were not found: {sorted(missing)}")
        return loaded

    def register_plugin(self, plugin: Plugin) -> None:
        if not plugin.name or plugin.name in self._plugins:
            raise RuntimeError(f"Duplicate or invalid plugin name: {plugin.name!r}")
        self._plugins[plugin.name] = plugin

    def register_plugin_tools(self, mcp: Any) -> dict[str, list[str]]:
        results: dict[str, list[str]] = {}
        for name, plugin in self._plugins.items():
            tool_names = plugin.register_tools(mcp)
            if len(tool_names) != len(set(tool_names)):
                raise RuntimeError(f"Plugin {name!r} returned duplicate tool names")
            for tool_name in tool_names:
                owner = self._tool_to_plugin.get(tool_name)
                if owner is not None:
                    raise RuntimeError(
                        f"Plugin tool collision: {tool_name!r} from {name!r} and {owner!r}"
                    )
                self._tool_to_plugin[tool_name] = name
            results[name] = tool_names
        return results

    def list_plugins(self) -> list[dict[str, Any]]:
        return [
            {
                "name": plugin.name,
                "version": plugin.version,
                "tools": sorted(
                    tool
                    for tool, plugin_name in self._tool_to_plugin.items()
                    if plugin_name == plugin.name
                ),
            }
            for plugin in self._plugins.values()
        ]

    def get_parsers(self) -> dict[str, Callable[..., Any]]:
        parsers: dict[str, Callable[..., Any]] = {}
        for plugin in self._plugins.values():
            for parser_name, parser in plugin.register_parsers().items():
                if parser_name in parsers:
                    raise RuntimeError(f"Plugin parser collision: {parser_name!r}")
                parsers[parser_name] = parser
        return parsers


_plugin_manager: PluginManager | None = None


def get_plugin_manager() -> PluginManager:
    global _plugin_manager
    if _plugin_manager is None:
        _plugin_manager = PluginManager()
    return _plugin_manager


def load_all_plugins(
    entry_point_group: str = "ghostmcp.plugins",
    *,
    allowlist: Iterable[str],
) -> list[str]:
    return get_plugin_manager().load_plugins(
        entry_point_group, allowlist=allowlist
    )


def register_plugin_tools(mcp: Any) -> dict[str, list[str]]:
    return get_plugin_manager().register_plugin_tools(mcp)
