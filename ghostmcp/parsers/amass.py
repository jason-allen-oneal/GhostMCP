"""Parse Amass JSON output into a structured dictionary."""

import json
from typing import Any


def parse_amass_json(json_content: str) -> dict[str, Any]:
    """Parse Amass JSON output into a structured dictionary."""
    if not json_content.strip():
        return {"subdomains": [], "summary": {"total": 0}}

    subdomains = []
    seen = set()

    for line in json_content.strip().split("\n"):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            # Amass outputs one JSON object per line
            name = entry.get("name", "")
            if not name or name in seen:
                continue
            seen.add(name)

            parsed = {
                "name": name,
                "domain": entry.get("domain", ""),
                "addresses": entry.get("addresses", []),
                "tag": entry.get("tag", ""),
                "sources": entry.get("sources", []),
                "timestamp": entry.get("timestamp"),
            }
            subdomains.append(parsed)
        except json.JSONDecodeError:
            continue

    return {"subdomains": subdomains, "summary": {"total": len(subdomains)}}
