"""Parse s3scanner JSON output into a structured dictionary."""

import json
from typing import Any


def parse_s3scanner_json(jsonl_content: str) -> dict[str, Any]:
    """Parse s3scanner JSON Lines output into a structured dictionary."""
    if not jsonl_content.strip():
        return {"buckets": [], "summary": {"total": 0, "by_status": {}}}

    buckets = []
    by_status: dict[str, int] = {}

    for line in jsonl_content.strip().split("\n"):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            status = entry.get("Status", "Unknown")
            parsed = {
                "bucket": entry.get("Bucket", ""),
                "status": status,
                "region": entry.get("Region", ""),
                "creation_date": entry.get("CreationDate", ""),
                "permissions": entry.get("Permissions", []),
                "acl": entry.get("ACL", []),
                "policy": entry.get("Policy", ""),
            }
            buckets.append(parsed)
            by_status[status] = by_status.get(status, 0) + 1
        except json.JSONDecodeError:
            continue

    return {"buckets": buckets, "summary": {"total": len(buckets), "by_status": by_status}}
