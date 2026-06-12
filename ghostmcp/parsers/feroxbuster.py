"""Parse Feroxbuster JSON output into a structured dictionary."""

import json
from typing import Any


def parse_feroxbuster_json(jsonl_content: str) -> dict[str, Any]:
    """Parse Feroxbuster JSON Lines output into a structured dictionary."""
    if not jsonl_content.strip():
        return {"results": [], "summary": {"total": 0, "by_status": {}}}

    results = []
    by_status: dict[int, int] = {}

    for line in jsonl_content.strip().split("\n"):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            if entry.get("type") != "response":
                continue
            status = entry.get("status", 0)
            parsed = {
                "url": entry.get("url", ""),
                "status": status,
                "method": entry.get("method", ""),
                "content_length": entry.get("content_length", 0),
                "paths": entry.get("paths", []),
                "wildcard": entry.get("wildcard", False),
            }
            results.append(parsed)
            by_status[status] = by_status.get(status, 0) + 1
        except json.JSONDecodeError:
            continue

    return {"results": results, "summary": {"total": len(results), "by_status": by_status}}
