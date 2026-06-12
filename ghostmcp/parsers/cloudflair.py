"""Parse cloudflair JSON output into a structured dictionary."""

import json
from typing import Any


def parse_cloudflair_json(json_content: str) -> dict[str, Any]:
    """Parse cloudflair JSON output into a structured dictionary."""
    if not json_content.strip():
        return {"origins": [], "summary": {"total": 0}}

    try:
        data = json.loads(json_content)
        origins = data.get("origins", []) if isinstance(data, dict) else []
    except json.JSONDecodeError:
        return {"error": "Invalid JSON output from cloudflair"}

    parsed_origins = []
    for origin in origins:
        if not isinstance(origin, dict):
            continue
        parsed_origins.append({
            "ip": origin.get("ip", ""),
            "hostname": origin.get("hostname", ""),
            "port": origin.get("port", 0),
            "protocol": origin.get("protocol", ""),
            "source": origin.get("source", ""),
        })

    return {"origins": parsed_origins, "summary": {"total": len(parsed_origins)}}
