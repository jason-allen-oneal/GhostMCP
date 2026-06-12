"""Parse Gitleaks JSON output into a structured dictionary."""

import json
from typing import Any


def parse_gitleaks_json(json_content: str) -> dict[str, Any]:
    """Parse Gitleaks JSON output into a structured dictionary."""
    if not json_content.strip():
        return {"findings": [], "summary": {"total": 0, "by_rule": {}}}

    findings = []
    by_rule: dict[str, int] = {}

    try:
        data = json.loads(json_content)
        if not isinstance(data, list):
            # Gitleaks can output a single object or array
            data = [data] if isinstance(data, dict) else []

        for entry in data:
            if not isinstance(entry, dict):
                continue
            rule = entry.get("RuleID") or entry.get("rule_id") or "unknown"
            parsed = {
                "rule_id": rule,
                "description": entry.get("Description", entry.get("description", "")),
                "file": entry.get("File", entry.get("file", "")),
                "line": entry.get("StartLine", entry.get("start_line", 0)),
                "end_line": entry.get("EndLine", entry.get("end_line", 0)),
                "commit": entry.get("Commit", entry.get("commit", "")),
                "entropy": entry.get("Entropy", entry.get("entropy", 0.0)),
                "secret": entry.get("Secret", entry.get("secret", "")),
                "match": entry.get("Match", entry.get("match", "")),
                "author": entry.get("Author", entry.get("author", "")),
                "email": entry.get("Email", entry.get("email", "")),
                "date": entry.get("Date", entry.get("date", "")),
                "tags": entry.get("Tags", entry.get("tags", [])),
            }
            findings.append(parsed)
            by_rule[rule] = by_rule.get(rule, 0) + 1
    except json.JSONDecodeError:
        pass

    return {"findings": findings, "summary": {"total": len(findings), "by_rule": by_rule}}
