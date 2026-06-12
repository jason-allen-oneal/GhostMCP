"""Parse Subfinder JSON output into a structured dictionary."""

import json
from typing import Any


def parse_subfinder_json(jsonl_content: str) -> dict[str, Any]:
    """Parse Subfinder JSON Lines output into a structured dictionary."""
    if not jsonl_content.strip():
        return {"subdomains": [], "summary": {"total": 0}}

    subdomains = []
    seen = set()

    for line in jsonl_content.strip().split("\n"):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            # Subfinder outputs one JSON object per line with "host" field
            host = entry.get("host", "")
            if not host or host in seen:
                continue
            seen.add(host)

            parsed = {
                "host": host,
                "source": entry.get("source", ""),
                "ip": entry.get("ip", ""),
                "cdn": entry.get("cdn", False),
            }
            subdomains.append(parsed)
        except json.JSONDecodeError:
            continue

    return {"subdomains": subdomains, "summary": {"total": len(subdomains)}}
