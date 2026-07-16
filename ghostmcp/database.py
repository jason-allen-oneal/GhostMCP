"""SQLite persistence for engagements, scans, and normalized findings."""

from __future__ import annotations

import ipaddress
import json
import os
import sqlite3
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ENGAGEMENT_STATUSES = {"active", "completed", "archived"}
SCAN_STATUSES = {"pending", "running", "completed", "failed"}
TOOL_LEVELS = {"passive", "active", "intrusive"}
SEVERITIES = {"critical", "high", "medium", "low", "info"}


@dataclass(frozen=True)
class Engagement:
    id: str
    name: str
    description: str | None
    scope_cidrs: list[str]
    scope_domains: list[str]
    max_tool_level: str
    created_at: str
    updated_at: str
    status: str


@dataclass(frozen=True)
class Scan:
    id: str
    engagement_id: str
    tool_name: str
    target: str
    parameters: dict[str, Any]
    status: str
    result: dict[str, Any] | None
    started_at: str | None
    completed_at: str | None
    error: str | None


@dataclass(frozen=True)
class ScanFinding:
    id: str
    scan_id: str
    finding_type: str
    severity: str
    title: str
    description: str
    target: str
    raw_data: dict[str, Any]
    created_at: str


class Database:
    def __init__(self, db_path: str = "ghostmcp.db"):
        self.db_path = str(Path(db_path).expanduser())
        self._lock = threading.RLock()
        self._init_db()

    @contextmanager
    def _get_conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=5.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 5000")
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        db_parent = Path(self.db_path).parent
        db_parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self._get_conn() as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS engagements (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    scope_cidrs TEXT NOT NULL DEFAULT '[]',
                    scope_domains TEXT NOT NULL DEFAULT '[]',
                    max_tool_level TEXT NOT NULL DEFAULT 'active',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active'
                );

                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    target TEXT NOT NULL,
                    parameters TEXT NOT NULL DEFAULT '{}',
                    status TEXT NOT NULL DEFAULT 'pending',
                    result TEXT,
                    started_at TEXT,
                    completed_at TEXT,
                    error TEXT,
                    FOREIGN KEY (engagement_id) REFERENCES engagements (id)
                        ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS scan_findings (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    finding_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    target TEXT NOT NULL DEFAULT '',
                    raw_data TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans (id)
                        ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_scans_engagement
                    ON scans (engagement_id);
                CREATE INDEX IF NOT EXISTS idx_scans_status
                    ON scans (status);
                CREATE INDEX IF NOT EXISTS idx_findings_scan
                    ON scan_findings (scan_id);
                CREATE INDEX IF NOT EXISTS idx_findings_severity
                    ON scan_findings (severity);
                """
            )
            conn.commit()

    def _execute_write(self, query: str, params: Sequence[Any] = ()) -> int:
        with self._lock, self._get_conn() as conn:
            cursor = conn.execute(query, tuple(params))
            conn.commit()
            return cursor.rowcount

    def _fetchone(
        self, query: str, params: Sequence[Any] = ()
    ) -> sqlite3.Row | None:
        with self._lock, self._get_conn() as conn:
            return conn.execute(query, tuple(params)).fetchone()

    def _fetchall(
        self, query: str, params: Sequence[Any] = ()
    ) -> list[sqlite3.Row]:
        with self._lock, self._get_conn() as conn:
            return list(conn.execute(query, tuple(params)).fetchall())

    @staticmethod
    def _validate_scope_cidrs(values: list[str] | None) -> list[str]:
        normalized: list[str] = []
        for value in values or []:
            normalized.append(str(ipaddress.ip_network(value.strip(), strict=False)))
        return sorted(set(normalized))

    @staticmethod
    def _validate_scope_domains(values: list[str] | None) -> list[str]:
        normalized: list[str] = []
        for value in values or []:
            domain = value.strip().lower().rstrip(".")
            if not domain or any(ch.isspace() for ch in domain):
                raise ValueError(f"Invalid scope domain: {value}")
            normalized.append(domain)
        return sorted(set(normalized))

    def create_engagement(
        self,
        engagement_id: str,
        name: str,
        description: str | None = None,
        scope_cidrs: list[str] | None = None,
        scope_domains: list[str] | None = None,
        max_tool_level: str = "active",
    ) -> Engagement:
        if not engagement_id.strip() or not name.strip():
            raise ValueError("Engagement id and name are required")
        max_tool_level = max_tool_level.strip().lower()
        if max_tool_level not in TOOL_LEVELS:
            raise ValueError(f"Invalid max tool level: {max_tool_level}")
        now = datetime.now(UTC).isoformat()
        engagement = Engagement(
            id=engagement_id.strip(),
            name=name.strip(),
            description=description,
            scope_cidrs=self._validate_scope_cidrs(scope_cidrs),
            scope_domains=self._validate_scope_domains(scope_domains),
            max_tool_level=max_tool_level,
            created_at=now,
            updated_at=now,
            status="active",
        )
        self._execute_write(
            """INSERT INTO engagements (
                   id, name, description, scope_cidrs, scope_domains,
                   max_tool_level, created_at, updated_at, status
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                engagement.id,
                engagement.name,
                engagement.description,
                json.dumps(engagement.scope_cidrs),
                json.dumps(engagement.scope_domains),
                engagement.max_tool_level,
                engagement.created_at,
                engagement.updated_at,
                engagement.status,
            ),
        )
        return engagement

    def get_engagement(self, engagement_id: str) -> Engagement | None:
        row = self._fetchone(
            "SELECT * FROM engagements WHERE id = ?", (engagement_id,)
        )
        return self._row_to_engagement(row) if row else None

    def list_engagements(self, status: str | None = None) -> list[Engagement]:
        if status is not None:
            status = status.strip().lower()
            if status not in ENGAGEMENT_STATUSES:
                raise ValueError(f"Invalid engagement status: {status}")
            rows = self._fetchall(
                "SELECT * FROM engagements WHERE status = ? ORDER BY created_at DESC",
                (status,),
            )
        else:
            rows = self._fetchall(
                "SELECT * FROM engagements ORDER BY created_at DESC"
            )
        return [self._row_to_engagement(row) for row in rows]

    def update_engagement(self, engagement_id: str, **kwargs: Any) -> Engagement | None:
        if self.get_engagement(engagement_id) is None:
            return None
        allowed = {
            "name",
            "description",
            "scope_cidrs",
            "scope_domains",
            "max_tool_level",
            "status",
        }
        unknown = set(kwargs) - allowed
        if unknown:
            raise ValueError(f"Unsupported engagement fields: {sorted(unknown)}")

        updates: list[str] = []
        params: list[Any] = []
        for key, value in kwargs.items():
            if key == "scope_cidrs":
                value = json.dumps(self._validate_scope_cidrs(value))
            elif key == "scope_domains":
                value = json.dumps(self._validate_scope_domains(value))
            elif key == "max_tool_level":
                value = str(value).strip().lower()
                if value not in TOOL_LEVELS:
                    raise ValueError(f"Invalid max tool level: {value}")
            elif key == "status":
                value = str(value).strip().lower()
                if value not in ENGAGEMENT_STATUSES:
                    raise ValueError(f"Invalid engagement status: {value}")
            elif key == "name":
                value = str(value).strip()
                if not value:
                    raise ValueError("Engagement name cannot be empty")
            updates.append(f"{key} = ?")
            params.append(value)

        if not updates:
            return self.get_engagement(engagement_id)
        updates.append("updated_at = ?")
        params.extend([datetime.now(UTC).isoformat(), engagement_id])
        self._execute_write(
            f"UPDATE engagements SET {', '.join(updates)} WHERE id = ?",  # nosec B608
            params,
        )
        return self.get_engagement(engagement_id)

    def delete_engagement(self, engagement_id: str) -> bool:
        # Delete children explicitly for databases created before ON DELETE CASCADE
        # was added to the schema.
        with self._lock, self._get_conn() as conn:
            conn.execute(
                "DELETE FROM scan_findings WHERE scan_id IN "
                "(SELECT id FROM scans WHERE engagement_id = ?)",
                (engagement_id,),
            )
            conn.execute("DELETE FROM scans WHERE engagement_id = ?", (engagement_id,))
            cursor = conn.execute(
                "DELETE FROM engagements WHERE id = ?", (engagement_id,)
            )
            conn.commit()
            return cursor.rowcount > 0

    @staticmethod
    def _row_to_engagement(row: sqlite3.Row) -> Engagement:
        return Engagement(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            scope_cidrs=json.loads(row["scope_cidrs"]),
            scope_domains=json.loads(row["scope_domains"]),
            max_tool_level=row["max_tool_level"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            status=row["status"],
        )

    def create_scan(
        self,
        scan_id: str,
        engagement_id: str,
        tool_name: str,
        target: str,
        parameters: dict[str, Any] | None = None,
    ) -> Scan:
        if self.get_engagement(engagement_id) is None:
            raise ValueError(f"Unknown engagement: {engagement_id}")
        if not scan_id.strip() or not tool_name.strip() or not target.strip():
            raise ValueError("Scan id, tool name, and target are required")
        scan = Scan(
            id=scan_id.strip(),
            engagement_id=engagement_id,
            tool_name=tool_name.strip(),
            target=target.strip(),
            parameters=dict(parameters or {}),
            status="pending",
            result=None,
            started_at=None,
            completed_at=None,
            error=None,
        )
        self._execute_write(
            """INSERT INTO scans (
                   id, engagement_id, tool_name, target, parameters, status,
                   result, started_at, completed_at, error
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan.id,
                scan.engagement_id,
                scan.tool_name,
                scan.target,
                json.dumps(scan.parameters),
                scan.status,
                None,
                None,
                None,
                None,
            ),
        )
        return scan

    def start_scan(self, scan_id: str) -> Scan | None:
        if self.get_scan(scan_id) is None:
            return None
        self._execute_write(
            "UPDATE scans SET status = ?, started_at = ?, completed_at = NULL, error = NULL WHERE id = ?",
            ("running", datetime.now(UTC).isoformat(), scan_id),
        )
        return self.get_scan(scan_id)

    def complete_scan(
        self,
        scan_id: str,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> Scan | None:
        if self.get_scan(scan_id) is None:
            return None
        status = "failed" if error else "completed"
        self._execute_write(
            "UPDATE scans SET status = ?, completed_at = ?, result = ?, error = ? WHERE id = ?",
            (
                status,
                datetime.now(UTC).isoformat(),
                json.dumps(result) if result is not None else None,
                error,
                scan_id,
            ),
        )
        return self.get_scan(scan_id)

    def get_scan(self, scan_id: str) -> Scan | None:
        row = self._fetchone("SELECT * FROM scans WHERE id = ?", (scan_id,))
        return self._row_to_scan(row) if row else None

    def list_scans(
        self, engagement_id: str | None = None, status: str | None = None
    ) -> list[Scan]:
        conditions: list[str] = []
        params: list[Any] = []
        if engagement_id:
            conditions.append("engagement_id = ?")
            params.append(engagement_id)
        if status:
            status = status.strip().lower()
            if status not in SCAN_STATUSES:
                raise ValueError(f"Invalid scan status: {status}")
            conditions.append("status = ?")
            params.append(status)
        query = "SELECT * FROM scans"
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY COALESCE(started_at, '') DESC, id DESC"
        return [self._row_to_scan(row) for row in self._fetchall(query, params)]

    @staticmethod
    def _row_to_scan(row: sqlite3.Row) -> Scan:
        return Scan(
            id=row["id"],
            engagement_id=row["engagement_id"],
            tool_name=row["tool_name"],
            target=row["target"],
            parameters=json.loads(row["parameters"]),
            status=row["status"],
            result=json.loads(row["result"]) if row["result"] else None,
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            error=row["error"],
        )

    def add_finding(
        self,
        finding_id: str,
        scan_id: str,
        finding_type: str,
        severity: str,
        title: str,
        description: str,
        target: str = "",
        raw_data: dict[str, Any] | None = None,
    ) -> ScanFinding:
        if self.get_scan(scan_id) is None:
            raise ValueError(f"Unknown scan: {scan_id}")
        severity = severity.strip().lower()
        if severity not in SEVERITIES:
            raise ValueError(f"Invalid finding severity: {severity}")
        finding = ScanFinding(
            id=finding_id.strip(),
            scan_id=scan_id,
            finding_type=finding_type.strip(),
            severity=severity,
            title=title.strip(),
            description=description,
            target=target,
            raw_data=dict(raw_data or {}),
            created_at=datetime.now(UTC).isoformat(),
        )
        if not finding.id or not finding.finding_type or not finding.title:
            raise ValueError("Finding id, type, and title are required")
        self._execute_write(
            """INSERT INTO scan_findings (
                   id, scan_id, finding_type, severity, title, description,
                   target, raw_data, created_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding.id,
                finding.scan_id,
                finding.finding_type,
                finding.severity,
                finding.title,
                finding.description,
                finding.target,
                json.dumps(finding.raw_data),
                finding.created_at,
            ),
        )
        return finding

    def get_findings(self, scan_id: str) -> list[ScanFinding]:
        rows = self._fetchall(
            "SELECT * FROM scan_findings WHERE scan_id = ? ORDER BY created_at DESC",
            (scan_id,),
        )
        return [self._row_to_finding(row) for row in rows]

    def get_findings_by_severity(
        self, engagement_id: str, severity: str | None = None
    ) -> list[ScanFinding]:
        query = (
            "SELECT f.* FROM scan_findings f "
            "JOIN scans s ON f.scan_id = s.id "
            "WHERE s.engagement_id = ?"
        )
        params: list[Any] = [engagement_id]
        if severity:
            severity = severity.strip().lower()
            if severity not in SEVERITIES:
                raise ValueError(f"Invalid finding severity: {severity}")
            query += " AND f.severity = ?"
            params.append(severity)
        query += " ORDER BY f.created_at DESC"
        return [
            self._row_to_finding(row) for row in self._fetchall(query, params)
        ]

    @staticmethod
    def _row_to_finding(row: sqlite3.Row) -> ScanFinding:
        return ScanFinding(
            id=row["id"],
            scan_id=row["scan_id"],
            finding_type=row["finding_type"],
            severity=row["severity"],
            title=row["title"],
            description=row["description"],
            target=row["target"],
            raw_data=json.loads(row["raw_data"]),
            created_at=row["created_at"],
        )

    def get_engagement_stats(self, engagement_id: str) -> dict[str, Any]:
        scans = self.list_scans(engagement_id=engagement_id)
        findings = self.get_findings_by_severity(engagement_id)
        return {
            "engagement_id": engagement_id,
            "total_scans": len(scans),
            "scans_by_status": {
                status: sum(scan.status == status for scan in scans)
                for status in sorted(SCAN_STATUSES)
            },
            "total_findings": len(findings),
            "findings_by_severity": {
                severity: sum(finding.severity == severity for finding in findings)
                for severity in ("critical", "high", "medium", "low", "info")
            },
        }


def get_database() -> Database:
    db_type = os.getenv("GHOSTMCP_DB_TYPE", "sqlite").strip().lower()
    if db_type == "postgres":
        if not os.getenv("GHOSTMCP_DB_DSN"):
            raise RuntimeError("GHOSTMCP_DB_DSN required for PostgreSQL")
        raise NotImplementedError("PostgreSQL backend is not implemented")
    if db_type != "sqlite":
        raise RuntimeError(f"Unsupported database type: {db_type}")
    return Database(os.getenv("GHOSTMCP_DB_PATH", "ghostmcp.db"))
