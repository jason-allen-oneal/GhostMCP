from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field

TOOL_LEVELS = {"passive", "active", "intrusive"}


@dataclass(frozen=True)
class ServerConfig:
    max_ports_per_scan: int = 256
    connect_timeout_ms: int = 1500
    max_concurrent_connects: int = 64
    allow_private_only: bool = True
    allowed_cidrs: tuple[ipaddress._BaseNetwork, ...] = field(default_factory=tuple)
    blocked_ports: tuple[int, ...] = (22, 2375, 2376, 3389)
    user_agent: str = "GhostMCP/0.2"
    require_engagement_context: bool = False
    allowed_domains: tuple[str, ...] = field(default_factory=tuple)
    max_tool_level: str = "active"


def _parse_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"Invalid boolean value: {value}")


def _parse_int(
    value: str | None,
    default: int,
    *,
    minimum: int = 1,
    maximum: int | None = None,
) -> int:
    parsed = default if value is None else int(value)
    if parsed < minimum or (maximum is not None and parsed > maximum):
        upper = f" and <= {maximum}" if maximum is not None else ""
        raise ValueError(f"Integer must be >= {minimum}{upper}: {parsed}")
    return parsed


def _parse_cidrs(value: str | None) -> tuple[ipaddress._BaseNetwork, ...]:
    if not value:
        return tuple()
    cidrs: list[ipaddress._BaseNetwork] = []
    for raw in value.split(","):
        raw = raw.strip()
        if raw:
            cidrs.append(ipaddress.ip_network(raw, strict=False))
    return tuple(cidrs)


def _parse_ports(value: str | None, default: tuple[int, ...]) -> tuple[int, ...]:
    if not value:
        return default
    ports: list[int] = []
    for raw in value.split(","):
        raw = raw.strip()
        if not raw:
            continue
        port = int(raw)
        if port < 1 or port > 65535:
            raise ValueError(f"Invalid blocked port value: {port}")
        ports.append(port)
    return tuple(sorted(set(ports)))


def _parse_csv(value: str | None) -> tuple[str, ...]:
    if not value:
        return tuple()
    return tuple(item.strip().lower().rstrip(".") for item in value.split(",") if item.strip())


def _parse_tool_level(value: str | None, default: str = "active") -> str:
    level = (value or default).strip().lower()
    if level not in TOOL_LEVELS:
        raise ValueError(f"Invalid tool level: {level}")
    return level


def _env(name: str, default: str | None = None) -> str | None:
    return os.getenv(f"GHOSTMCP_{name}", default)


def load_config() -> ServerConfig:
    return ServerConfig(
        max_ports_per_scan=_parse_int(
            _env("MAX_PORTS_PER_SCAN"), 256, maximum=65535
        ),
        connect_timeout_ms=_parse_int(
            _env("CONNECT_TIMEOUT_MS"), 1500, maximum=120_000
        ),
        max_concurrent_connects=_parse_int(
            _env("MAX_CONCURRENT_CONNECTS"), 64, maximum=4096
        ),
        allow_private_only=_parse_bool(_env("ALLOW_PRIVATE_ONLY"), True),
        allowed_cidrs=_parse_cidrs(_env("ALLOWED_CIDRS")),
        blocked_ports=_parse_ports(
            _env("BLOCKED_PORTS"),
            (22, 2375, 2376, 3389),
        ),
        user_agent=_env("USER_AGENT", "GhostMCP/0.2") or "GhostMCP/0.2",
        require_engagement_context=_parse_bool(
            _env("REQUIRE_ENGAGEMENT_CONTEXT"),
            False,
        ),
        allowed_domains=_parse_csv(_env("ALLOWED_DOMAINS")),
        max_tool_level=_parse_tool_level(_env("MAX_TOOL_LEVEL"), "active"),
    )
