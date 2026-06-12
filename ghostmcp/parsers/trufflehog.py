"""Parse TruffleHog JSON output into a structured dictionary."""

import json
from typing import Any


def parse_trufflehog_json(jsonl_content: str) -> dict[str, Any]:
    """Parse TruffleHog JSON Lines output into a structured dictionary."""
    if not jsonl_content.strip():
        return {"findings": [], "summary": {"total": 0, "by_detector": {}}}

    findings = []
    by_detector: dict[str, int] = {}

    for line in jsonl_content.strip().split("\n"):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            detector = entry.get("DetectorName", entry.get("detector", "unknown"))
            parsed = {
                "detector": detector,
                "detector_type": entry.get("DetectorType", ""),
                "decoded": entry.get("Decoded", entry.get("decoded", "")),
                "file": entry.get("File", entry.get("file", "")),
                "line": entry.get("Line", entry.get("line", 0)),
                "commit": entry.get("Commit", entry.get("commit", "")),
                "branch": entry.get("Branch", entry.get("branch", "")),
                "repository": entry.get("Repository", entry.get("repository", "")),
                "author": entry.get("Author", entry.get("author", "")),
                "email": entry.get("Email", entry.get("email", "")),
                "date": entry.get("Date", entry.get("date", "")),
                "verified": entry.get("Verified", entry.get("verified", False)),
                "raw": entry.get("Raw", entry.get("raw", "")),
                "extra_data": entry.get("ExtraData", entry.get("extra_data", {})),
            }
            findings.append(parsed)
            by_detector[detector] = by_detector.get(detector, 0) + 1
        except json.JSONDecodeError:
            continue

    return {"findings": findings, "summary": {"total": len(findings), "by_detector": by_detector}}
