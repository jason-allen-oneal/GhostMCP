"""Canonical, persistent, optionally signed audit chains."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from pathlib import Path
from typing import Any

ZERO_HASH = "0" * 64


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _event_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _signature(event_hash: str, key: bytes) -> str:
    return hmac.new(key, event_hash.encode("ascii"), hashlib.sha256).hexdigest()


def load_hmac_key(*, key_value: str = "", key_file: str = "") -> bytes | None:
    if key_value and key_file:
        raise RuntimeError("Configure only one audit HMAC key source")
    if key_file:
        path = Path(key_file).expanduser()
        key = path.read_bytes().strip()
        if len(key) < 32:
            raise RuntimeError("Audit HMAC key file must contain at least 32 bytes")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return key
    if key_value:
        key = key_value.encode("utf-8")
        if len(key) < 32:
            raise RuntimeError("Audit HMAC key must contain at least 32 bytes")
        return key
    return None


def verify_audit_log(log_path: str, hmac_key: bytes | None = None) -> dict[str, Any]:
    path = Path(log_path).expanduser()
    if not path.exists():
        return {"status": "error", "message": "Log file not found", "events_processed": 0}

    expected_previous = ZERO_HASH
    errors: list[str] = []
    events_processed = 0
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append(f"Line {line_number}: invalid JSON: {exc.msg}")
                continue
            if not isinstance(event, dict):
                errors.append(f"Line {line_number}: event must be an object")
                continue
            events_processed += 1
            event_hash = event.get("event_hash")
            signature = event.get("signature")
            base_event = {
                key: value
                for key, value in event.items()
                if key not in {"event_hash", "signature"}
            }
            if base_event.get("prev_hash") != expected_previous:
                errors.append(f"Line {line_number}: hash chain break")
            calculated = _event_hash(base_event)
            if not isinstance(event_hash, str) or not hmac.compare_digest(
                event_hash, calculated
            ):
                errors.append(f"Line {line_number}: event hash mismatch")
            if hmac_key is not None:
                expected_signature = _signature(calculated, hmac_key)
                if not isinstance(signature, str) or not hmac.compare_digest(
                    signature, expected_signature
                ):
                    errors.append(f"Line {line_number}: signature mismatch")
            expected_previous = calculated

    return {
        "status": "success" if not errors else "failed",
        "events_processed": events_processed,
        "last_hash": expected_previous,
        "signed": hmac_key is not None,
        "errors": errors,
    }


class AuditChain:
    def __init__(
        self,
        sink_path: str = "",
        *,
        hmac_key: bytes | None = None,
        fsync: bool = False,
    ) -> None:
        self.sink_path = Path(sink_path).expanduser() if sink_path else None
        self.hmac_key = hmac_key
        self.fsync = fsync
        self._lock = threading.Lock()
        self._last_hash = ZERO_HASH
        if self.sink_path is not None:
            self.sink_path.parent.mkdir(parents=True, exist_ok=True)
            if self.sink_path.exists() and self.sink_path.stat().st_size:
                result = verify_audit_log(str(self.sink_path), self.hmac_key)
                if result["status"] != "success":
                    raise RuntimeError(
                        "Audit sink integrity check failed: "
                        + "; ".join(result.get("errors", []))
                    )
                self._last_hash = str(result["last_hash"])
            else:
                self.sink_path.touch(mode=0o600, exist_ok=True)
            try:
                os.chmod(self.sink_path, 0o600)
            except OSError:
                pass

    @property
    def last_hash(self) -> str:
        return self._last_hash

    @property
    def signed(self) -> bool:
        return self.hmac_key is not None

    def append(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            base_event = dict(payload)
            base_event["prev_hash"] = self._last_hash
            event_hash = _event_hash(base_event)
            event = dict(base_event)
            event["event_hash"] = event_hash
            if self.hmac_key is not None:
                event["signature"] = _signature(event_hash, self.hmac_key)
            serialized = canonical_json(event) + "\n"
            if self.sink_path is not None:
                descriptor = os.open(
                    self.sink_path,
                    os.O_WRONLY | os.O_APPEND | os.O_CREAT,
                    0o600,
                )
                try:
                    os.write(descriptor, serialized.encode("utf-8"))
                    if self.fsync:
                        os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            self._last_hash = event_hash
            return event
