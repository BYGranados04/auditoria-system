from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.core.events import SecurityEvent


class EventRepository:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path

    @contextmanager
    def _connection(
        self,
    ) -> Iterator[sqlite3.Connection]:
        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        connection = sqlite3.connect(
            self.database_path,
            timeout=5,
        )
        connection.row_factory = sqlite3.Row

        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            yield connection
            connection.commit()
        finally:
            connection.close()

    def initialize(self) -> None:
        with self._connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    source TEXT NOT NULL,
                    category TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                        DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

            indexes = (
                ("idx_events_timestamp", "timestamp"),
                ("idx_events_hostname", "hostname"),
                ("idx_events_severity", "severity"),
                ("idx_events_type", "event_type"),
                ("idx_events_category", "category"),
            )

            for name, column in indexes:
                connection.execute(
                    f"""
                    CREATE INDEX IF NOT EXISTS {name}
                    ON events ({column})
                    """
                )

    def add(self, event: SecurityEvent) -> None:
        data = event.model_dump(mode="json")

        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO events (
                    event_id,
                    timestamp,
                    hostname,
                    source,
                    category,
                    event_type,
                    severity,
                    description,
                    evidence_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["event_id"],
                    data["timestamp"],
                    data["hostname"],
                    data["source"],
                    data["category"],
                    data["event_type"],
                    data["severity"],
                    data["description"],
                    json.dumps(
                        data["evidence"],
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                ),
            )

    def statistics(self) -> dict[str, Any]:
        with self._connection() as connection:
            total = connection.execute(
                "SELECT COUNT(*) AS total FROM events"
            ).fetchone()["total"]

            severity_rows = connection.execute(
                """
                SELECT severity, COUNT(*) AS total
                FROM events
                GROUP BY severity
                ORDER BY severity
                """
            ).fetchall()

            type_rows = connection.execute(
                """
                SELECT event_type, COUNT(*) AS total
                FROM events
                GROUP BY event_type
                ORDER BY total DESC, event_type
                """
            ).fetchall()

        return {
            "total": int(total),
            "by_severity": {
                row["severity"]: int(row["total"]) for row in severity_rows
            },
            "by_event_type": {
                row["event_type"]: int(row["total"]) for row in type_rows
            },
        }

    def count(self) -> int:
        with self._connection() as connection:
            row = connection.execute("SELECT COUNT(*) AS total FROM events").fetchone()

        return int(row["total"])

    def list_events(
        self,
        *,
        severity: str | None = None,
        event_type: str | None = None,
        hostname: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        parameters: list[Any] = []

        if severity is not None:
            clauses.append("severity = ?")
            parameters.append(severity)

        if event_type is not None:
            clauses.append("event_type = ?")
            parameters.append(event_type)

        if hostname is not None:
            clauses.append("hostname = ?")
            parameters.append(hostname)

        if since is not None:
            clauses.append("julianday(timestamp) >= julianday(?)")
            parameters.append(since.astimezone(UTC).isoformat())

        if until is not None:
            clauses.append("julianday(timestamp) <= julianday(?)")
            parameters.append(until.astimezone(UTC).isoformat())

        where = " WHERE " + " AND ".join(clauses) if clauses else ""

        safe_limit = max(1, min(limit, 1000))

        query = f"SELECT * FROM events{where} ORDER BY timestamp DESC LIMIT ?"
        parameters.append(safe_limit)

        with self._connection() as connection:
            rows = connection.execute(
                query,
                parameters,
            ).fetchall()

        return [
            {
                **dict(row),
                "evidence": json.loads(row["evidence_json"]),
            }
            for row in rows
        ]
