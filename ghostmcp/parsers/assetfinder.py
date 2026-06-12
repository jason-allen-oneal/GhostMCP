"""Parse assetfinder output into a structured dictionary."""

from typing import Any


def parse_assetfinder_output(text_content: str) -> dict[str, Any]:
    """Parse assetfinder plain text output into a structured dictionary."""
    if not text_content.strip():
        return {"subdomains": [], "summary": {"total": 0}}

    subdomains = []
    seen = set()

    for line in text_content.strip().split("\n"):
        line = line.strip()
        if not line or line in seen:
            continue
        seen.add(line)
        subdomains.append({"host": line})

    return {"subdomains": subdomains, "summary": {"total": len(subdomains)}}
