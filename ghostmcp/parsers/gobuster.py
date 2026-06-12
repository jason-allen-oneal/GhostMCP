"""Parse Gobuster JSON output into a structured dictionary."""

import json
from typing import Any


def parse_gobuster_json(json_content: str) -> dict[str, Any]:
    """Parse Gobuster JSON output into a structured dictionary."""
    if not json_content.strip():
        return {"paths": [], "summary": {"total": 0}}

    paths = []
    try:
        data = json.loads(json_content)
        if isinstance(data, dict) and "results" in data:
            results = data["results"]
        elif isinstance(data, list):
            results = data
        else:
            results = []

        for entry in results:
            if not isinstance(entry, dict):
                continue
            parsed = {
                "path": entry.get("path", ""),
                "status": entry.get("status", 0),
                "status_text": entry.get("status_text", ""),
                "content_length": entry.get("content_length", 0),
                "content_type": entry.get("content_type", ""),
                "redirect_to": entry.get("redirect_to", ""),
            }
            paths.append(parsed)
    except json.JSONDecodeError:
        pass

    return {"paths": paths, "summary": {"total": len(paths)}}
