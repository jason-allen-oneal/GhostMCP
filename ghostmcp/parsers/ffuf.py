"""Parse FFUF JSON output into a structured dictionary."""

import json
from typing import Any


def parse_ffuf_json(json_content: str) -> dict[str, Any]:
    """Parse FFUF JSON output into a structured dictionary."""
    if not json_content.strip():
        return {"results": [], "summary": {"total": 0, "by_status": {}}}

    results = []
    by_status: dict[int, int] = {}

    try:
        data = json.loads(json_content)
        if isinstance(data, dict) and "results" in data:
            raw_results = data["results"]
        elif isinstance(data, list):
            raw_results = data
        else:
            raw_results = []

        for entry in raw_results:
            if not isinstance(entry, dict):
                continue
            status = entry.get("status", 0)
            parsed = {
                "url": entry.get("url", ""),
                "status": status,
                "status_text": entry.get("status_text", ""),
                "content_length": entry.get("length", 0),
                "content_words": entry.get("words", 0),
                "content_lines": entry.get("lines", 0),
                "redirect_location": entry.get("redirectlocation", ""),
                "resultfile": entry.get("resultfile", ""),
                "input": entry.get("input", {}),
            }
            results.append(parsed)
            by_status[status] = by_status.get(status, 0) + 1
    except json.JSONDecodeError:
        pass

    return {"results": results, "summary": {"total": len(results), "by_status": by_status}}
