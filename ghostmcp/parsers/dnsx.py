"""Parse dnsx JSON output into a structured dictionary."""

import json
from typing import Any


def parse_dnsx_json(jsonl_content: str) -> dict[str, Any]:
    """Parse dnsx JSON Lines output into a structured dictionary."""
    if not jsonl_content.strip():
        return {"records": [], "summary": {"total": 0}}

    records = []

    for line in jsonl_content.strip().split("\n"):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            # dnsx outputs one JSON object per line
            parsed = {
                "host": entry.get("host", ""),
                "a": entry.get("a", []),
                "aaaa": entry.get("aaaa", []),
                "cname": entry.get("cname", []),
                "ns": entry.get("ns", []),
                "mx": entry.get("mx", []),
                "txt": entry.get("txt", []),
                "ptr": entry.get("ptr", []),
            }
            records.append(parsed)
        except json.JSONDecodeError:
            continue

    return {"records": records, "summary": {"total": len(records)}}
