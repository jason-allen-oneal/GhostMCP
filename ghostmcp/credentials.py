import json
import os
from typing import Any


class CredentialStore:
    def __init__(self, store_path: str):
        self.store_path = store_path
        self._cache: dict[str, Any] = {}
        self._load()

    def _load(self):
        if os.path.exists(self.store_path):
            try:
                with open(self.store_path) as f:
                    self._cache = json.load(f)
            except Exception:
                self._cache = {}

    def get_credentials(self, tool_id: str, target: str | None = None) -> dict[str, Any] | None:
        """Retrieve credentials for a tool, optionally scoped to a target."""
        tool_creds = self._cache.get(tool_id, {})
        if not tool_creds:
            return None

        if target:
            # Check for exact target match
            if target in tool_creds:
                return tool_creds[target]

        return tool_creds.get("default")

    def set_credentials(self, tool_id: str, creds: dict[str, Any], scope: str = "default"):
        if tool_id not in self._cache:
            self._cache[tool_id] = {}
        self._cache[tool_id][scope] = creds
        self._save()

    def _save(self):
        with open(self.store_path, "w") as f:
            json.dump(self._cache, f, indent=2)
