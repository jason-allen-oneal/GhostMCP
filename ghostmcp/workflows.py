"""Normalized assessment workflows built from guarded primitives."""

from __future__ import annotations

import shutil
from collections.abc import Callable
from typing import Any

from .scanners import (
    http_probe,
    port_scan,
    sslscan_target,
    tls_certificate,
    tls_certificate_expiry,
    wafw00f_scan,
    whatweb_scan,
)
from .security import SecurityPolicy


def _step(
    name: str, function: Callable[[], Any], *, optional: bool = False
) -> dict[str, Any]:
    try:
        return {"name": name, "status": "ok", "result": function()}
    except Exception as exc:
        return {
            "name": name,
            "status": "skipped" if optional else "failed",
            "error": str(exc),
        }


def _summary(steps: list[dict[str, Any]]) -> dict[str, int]:
    return {
        status: sum(step["status"] == status for step in steps)
        for status in ("ok", "failed", "skipped")
    }


def web_surface_assessment(
    policy: SecurityPolicy, url: str, user_agent: str
) -> dict[str, Any]:
    policy.validate_url(url)
    steps = [
        _step("http_probe", lambda: http_probe(url, user_agent=user_agent)),
    ]
    if shutil.which("whatweb"):
        steps.append(_step("whatweb", lambda: whatweb_scan(url), optional=True))
    if shutil.which("wafw00f"):
        steps.append(_step("waf_detection", lambda: wafw00f_scan(url), optional=True))
    return {
        "workflow": "web_surface_assessment",
        "target": url,
        "summary": _summary(steps),
        "steps": steps,
    }


def tls_posture_assessment(
    policy: SecurityPolicy, host: str, port: int = 443
) -> dict[str, Any]:
    validated = policy.validate_target(host)
    validated_port = policy.parse_ports([port])[0]
    steps = [
        _step(
            "certificate",
            lambda: tls_certificate(validated.host, validated_port),
        ),
        _step(
            "certificate_expiry",
            lambda: tls_certificate_expiry(validated.host, validated_port),
        ),
    ]
    if shutil.which("sslscan"):
        steps.append(
            _step(
                "sslscan",
                lambda: sslscan_target(validated.host, validated_port),
                optional=True,
            )
        )
    return {
        "workflow": "tls_posture_assessment",
        "target": f"{validated.host}:{validated_port}",
        "summary": _summary(steps),
        "steps": steps,
    }


def host_exposure_assessment(
    policy: SecurityPolicy, host: str, ports: list[int], timeout_ms: int
) -> dict[str, Any]:
    validated = policy.validate_target(host)
    validated_ports = policy.parse_ports(ports)
    result = port_scan(
        host=validated.host,
        ports=validated_ports,
        connect_timeout_ms=timeout_ms,
        max_workers=policy.config.max_concurrent_connects,
    )
    open_ports = [
        entry for entry in result["results"] if entry.get("state") == "open"
    ]
    return {
        "workflow": "host_exposure_assessment",
        "target": validated.host,
        "summary": {
            "ports_checked": len(validated_ports),
            "open_ports": len(open_ports),
        },
        "results": result,
    }
