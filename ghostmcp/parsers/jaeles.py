"""Parse Jaeles JSON output into a structured dictionary."""

import json
from typing import Any


def parse_jaeles_json(jsonl_content: str) -> dict[str, Any]:
    """Parse Jaeles JSON Lines output into a structured dictionary."""
    if not jsonl_content.strip():
        return {"findings": [], "summary": {"total": 0, "by_severity": {}}}

    findings = []
    by_severity: dict[str, int] = {}

    for line in jsonl_content.strip().split("\n"):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            parsed = {
                "signature_id": entry.get("signature", {}).get("id", ""),
                "name": entry.get("signature", {}).get("info", {}).get("name", ""),
                "severity": entry.get("signature", {}).get("info", {}).get("severity", "unknown").lower(),
                "description": entry.get("signature", {}).get("info", {}).get("description", ""),
                "target": entry.get("target", ""),
                "match": entry.get("match", ""),
                "tags": entry.get("signature", {}).get("info", {}).get("tags", []),
                "references": entry.get("signature", {}).get("info", {}).get("reference", []),
            }
            findings.append(parsed)
            sev = parsed["severity"]
            by_severity[sev] = by_severity.get(sev, 0) + 1
        except json.JSONDecodeError:
            continue

    return {"findings": findings, "summary": {"total": len(findings), "by_severity": by_severity}}
