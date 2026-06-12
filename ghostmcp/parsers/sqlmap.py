"""Parse SQLMap JSON output into a structured dictionary."""

import json
from typing import Any


def parse_sqlmap_json(json_content: str) -> dict[str, Any]:
    """Parse SQLMap JSON output into a structured dictionary."""
    if not json_content.strip():
        return {"injections": [], "summary": {"total": 0}}

    injections = []

    try:
        data = json.loads(json_content)
        # SQLMap JSON output is an array of results
        if isinstance(data, list):
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                parsed = {
                    "place": entry.get("place", ""),
                    "parameter": entry.get("parameter", ""),
                    "type": entry.get("type", ""),
                    "title": entry.get("title", ""),
                    "payload": entry.get("payload", ""),
                    "vector": entry.get("vector", ""),
                    "dbms": entry.get("dbms", ""),
                    "dbms_version": entry.get("dbms_version", ""),
                    "technique": entry.get("technique", ""),
                    "confirmed": entry.get("confirmed", False),
                }
                injections.append(parsed)
    except json.JSONDecodeError:
        pass

    return {"injections": injections, "summary": {"total": len(injections)}}
