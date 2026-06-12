"""Parse gowitness JSON output into a structured dictionary."""

import json
from typing import Any


def parse_gowitness_json(json_content: str) -> dict[str, Any]:
    """Parse gowitness JSON output into a structured dictionary."""
    if not json_content.strip():
        return {"screenshots": [], "summary": {"total": 0}}

    screenshots = []

    try:
        data = json.loads(json_content)
        if isinstance(data, list):
            entries = data
        elif isinstance(data, dict) and "results" in data:
            entries = data["results"]
        else:
            entries = []

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            parsed = {
                "url": entry.get("url", ""),
                "status_code": entry.get("status_code", 0),
                "content_length": entry.get("content_length", 0),
                "content_type": entry.get("content_type", ""),
                "title": entry.get("title", ""),
                "server": entry.get("server", ""),
                "screenshot_path": entry.get("screenshot_path", ""),
                "technologies": entry.get("technologies", []),
                "headers": entry.get("headers", {}),
            }
            screenshots.append(parsed)
    except json.JSONDecodeError:
        pass

    return {"screenshots": screenshots, "summary": {"total": len(screenshots)}}
