"""Parse WPScan JSON output into a structured dictionary."""

import json
from typing import Any


def parse_wpscan_json(json_content: str) -> dict[str, Any]:
    """Parse WPScan JSON output into a structured dictionary."""
    if not json_content.strip():
        return {
            "version": None,
            "vulnerabilities": [],
            "themes": [],
            "plugins": [],
            "users": [],
            "summary": {"vulnerabilities": 0, "themes": 0, "plugins": 0, "users": 0},
        }

    result: dict[str, Any] = {
        "version": None,
        "vulnerabilities": [],
        "themes": [],
        "plugins": [],
        "users": [],
    }

    try:
        data = json.loads(json_content)

        # Version info
        if "version" in data:
            v = data["version"]
            result["version"] = {
                "number": v.get("number", ""),
                "status": v.get("status", ""),
            }

        # Vulnerabilities
        if "vulnerabilities" in data:
            for vuln in data["vulnerabilities"]:
                result["vulnerabilities"].append({
                    "title": vuln.get("title", ""),
                    "references": vuln.get("references", {}),
                    "fixed_in": vuln.get("fixed_in", ""),
                })

        # Themes
        if "themes" in data:
            for theme_name, theme_data in data["themes"].items():
                theme_info = {"name": theme_name}
                if isinstance(theme_data, dict):
                    theme_info.update({
                        "version": theme_data.get("version", ""),
                        "location": theme_data.get("location", ""),
                        "vulnerabilities": theme_data.get("vulnerabilities", []),
                    })
                result["themes"].append(theme_info)

        # Plugins
        if "plugins" in data:
            for plugin_name, plugin_data in data["plugins"].items():
                plugin_info = {"name": plugin_name}
                if isinstance(plugin_data, dict):
                    plugin_info.update({
                        "version": plugin_data.get("version", ""),
                        "location": plugin_data.get("location", ""),
                        "vulnerabilities": plugin_data.get("vulnerabilities", []),
                    })
                result["plugins"].append(plugin_info)

        # Users
        if "users" in data:
            for user_name, user_data in data["users"].items():
                user_info = {"username": user_name}
                if isinstance(user_data, dict):
                    user_info.update({
                        "id": user_data.get("id", ""),
                        "location": user_data.get("location", ""),
                    })
                result["users"].append(user_info)

        result["summary"] = {
            "vulnerabilities": len(result["vulnerabilities"]),
            "themes": len(result["themes"]),
            "plugins": len(result["plugins"]),
            "users": len(result["users"]),
        }

    except json.JSONDecodeError:
        pass

    return result
