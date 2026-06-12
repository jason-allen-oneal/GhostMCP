"""Parse Nuclei JSONL output into a structured dictionary."""

import json
from typing import Any


def parse_nuclei_jsonl(jsonl_content: str) -> dict[str, Any]:
    """Parse Nuclei JSON Lines output into a structured dictionary."""
    if not jsonl_content.strip():
        return {"findings": [], "summary": {"total": 0, "by_severity": {}}}

    findings = []
    by_severity: dict[str, int] = {}

    for line in jsonl_content.strip().split("\n"):
        if not line.strip():
            continue
        try:
            finding = json.loads(line)
            results = finding.get("results", [])
            for result in results:
                severity = result.get("info", {}).get("severity", "unknown").lower()
                parsed = {
                    "template_id": result.get("template-id"),
                    "template_name": result.get("template", "").split("/")[-1] if result.get("template") else "",
                    "severity": severity,
                    "type": result.get("type"),
                    "host": result.get("host"),
                    "matched_at": result.get("matched-at"),
                    "extracted_results": result.get("extracted-results", []),
                    "matcher_name": result.get("matcher-name"),
                    "description": result.get("info", {}).get("description", ""),
                    "reference": result.get("info", {}).get("reference", []),
                    "tags": result.get("info", {}).get("tags", []),
                    "timestamp": result.get("timestamp"),
                }
                findings.append(parsed)
                by_severity[severity] = by_severity.get(severity, 0) + 1
        except json.JSONDecodeError:
            continue

    return {
        "findings": findings,
        "summary": {"total": len(findings), "by_severity": by_severity},
    }


def parse_nuclei_json(json_content: str) -> dict[str, Any]:
    """Parse Nuclei single JSON output (from -json-export)."""
    try:
        data = json.loads(json_content)
        if isinstance(data, list):
            # Handle array of results
            return parse_nuclei_jsonl("\n".join(json.dumps(item) for item in data))
        return parse_nuclei_jsonl(json_content)
    except json.JSONDecodeError:
        return {"error": "Invalid JSON output from nuclei"}
