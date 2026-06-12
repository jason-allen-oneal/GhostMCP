"""Proxy/Tor support for GhostMCP."""

import os
import shutil
from typing import Literal

ProxyMode = Literal["none", "tor", "proxychains", "torsocks"]


def get_proxy_mode() -> ProxyMode:
    """Get the configured proxy mode from environment."""
    mode = os.getenv("GHOSTMCP_PROXY_MODE", "none").strip().lower()
    valid_modes: tuple[ProxyMode, ...] = ("none", "tor", "proxychains", "torsocks")
    if mode not in valid_modes:
        return "none"
    return mode


def get_tor_proxy() -> dict[str, str] | None:
    """Get Tor proxy configuration."""
    host = os.getenv("GHOSTMCP_TOR_HOST", "127.0.0.1")
    port = int(os.getenv("GHOSTMCP_TOR_PORT", "9050"))
    return {
        "http": f"socks5h://{host}:{port}",
        "https": f"socks5h://{host}:{port}",
    }


def build_proxychains_command(command: list[str]) -> list[str]:
    """Wrap a command with proxychains4."""
    if shutil.which("proxychains4"):
        return ["proxychains4", "-q"] + command
    if shutil.which("proxychains"):
        return ["proxychains", "-q"] + command
    # Fall back to running without proxy if proxychains not available
    return command


def build_torsocks_command(command: list[str]) -> list[str]:
    """Wrap a command with torsocks."""
    if shutil.which("torsocks"):
        return ["torsocks"] + command
    return command


def apply_proxy_mode(command: list[str]) -> list[str]:
    """Apply the configured proxy mode to a command."""
    mode = get_proxy_mode()

    if mode == "tor":
        # For tor mode, we use environment variables for tools that support it
        # The actual proxy env vars will be set in _run_external_tool
        return command
    elif mode == "proxychains":
        return build_proxychains_command(command)
    elif mode == "torsocks":
        return build_torsocks_command(command)
    return command


def get_proxy_env() -> dict[str, str] | None:
    """Get proxy environment variables for subprocess."""
    mode = get_proxy_mode()

    if mode == "tor":
        proxy = get_tor_proxy()
        if proxy:
            return {
                "http_proxy": proxy["http"],
                "https_proxy": proxy["https"],
                "HTTP_PROXY": proxy["http"],
                "HTTPS_PROXY": proxy["https"],
                "ALL_PROXY": proxy["http"],
                "all_proxy": proxy["http"],
            }
    return None
