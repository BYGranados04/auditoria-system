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
    SCHEMA_VERSION = 2

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
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self._connection() as connection:
            current_version = self._schema_version(connection)

            if current_version > self.SCHEMA_VERSION:
                raise RuntimeError(
                    "La base de datos usa un esquema "
                    f"más nuevo ({current_version}) "
                    f"que esta aplicación ({self.SCHEMA_VERSION})."
                )

            migrations = {
                1: self._migrate_to_v1,
                2: self._migrate_to_v2,
            }

            while current_version < self.SCHEMA_VERSION:
                next_version = current_version + 1
                migration = migrations[next_version]

                migration(connection)

                connection.execute(f"PRAGMA user_version = {next_version}")
                current_version = next_version

    @staticmethod
    def _schema_version(
        connection: sqlite3.Connection,
    ) -> int:
        row = connection.execute("PRAGMA user_version").fetchone()

        return int(row[0])

    def schema_version(self) -> int:
        with self._connection() as connection:
            return self._schema_version(connection)

    @staticmethod
    def _migrate_to_v1(
        connection: sqlite3.Connection,
    ) -> None:
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

    @staticmethod
    def _migrate_to_v2(
        connection: sqlite3.Connection,
    ) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS response_blocks (
                block_id TEXT PRIMARY KEY,
                detection_event_id TEXT NOT NULL,
                response_event_id TEXT NOT NULL,
                execution_event_id TEXT,
                hostname TEXT NOT NULL,
                target_ip TEXT NOT NULL,
                family TEXT NOT NULL
                    CHECK (family IN ('ip', 'ip6')),
                duration_seconds INTEGER NOT NULL
                    CHECK (
                        duration_seconds >= 60
                        AND duration_seconds <= 86400
                    ),
                requested_at TEXT NOT NULL,
                applied_at TEXT,
                expires_at TEXT NOT NULL,
                status TEXT NOT NULL
                    CHECK (
                        status IN (
                            'PENDING',
                            'ACTIVE',
                            'EXPIRED',
                            'REMOVED',
                            'FAILED'
                        )
                    ),
                last_error TEXT,
                created_at TEXT NOT NULL
                    DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL
                    DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
                idx_response_blocks_status
            ON response_blocks (status)
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
                idx_response_blocks_expires_at
            ON response_blocks (expires_at)
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
                idx_response_blocks_target
            ON response_blocks (target_ip)
            """
        )

        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS
                idx_response_blocks_live_target
            ON response_blocks (
                hostname,
                target_ip
            )
            WHERE status IN ('PENDING', 'ACTIVE')
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

    def create_response_block(
        self,
        *,
        block_id: str,
        detection_event_id: str,
        response_event_id: str,
        hostname: str,
        target_ip: str,
        family: str,
        duration_seconds: int,
        requested_at: datetime,
        expires_at: datetime,
    ) -> None:
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO response_blocks (
                    block_id,
                    detection_event_id,
                    response_event_id,
                    hostname,
                    target_ip,
                    family,
                    duration_seconds,
                    requested_at,
                    expires_at,
                    status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING')
                """,
                (
                    block_id,
                    detection_event_id,
                    response_event_id,
                    hostname,
                    target_ip,
                    family,
                    duration_seconds,
                    requested_at.astimezone(UTC).isoformat(),
                    expires_at.astimezone(UTC).isoformat(),
                ),
            )

    def mark_response_block_active(
        self,
        block_id: str,
        *,
        execution_event_id: str,
        applied_at: datetime,
    ) -> None:
        with self._connection() as connection:
            cursor = connection.execute(
                """
                UPDATE response_blocks
                SET execution_event_id = ?,
                    applied_at = ?,
                    status = 'ACTIVE',
                    last_error = NULL,
                    updated_at = CURRENT_TIMESTAMP
                WHERE block_id = ?
                  AND status = 'PENDING'
                """,
                (
                    execution_event_id,
                    applied_at.astimezone(UTC).isoformat(),
                    block_id,
                ),
            )

            if cursor.rowcount != 1:
                raise RuntimeError(
                    f"No se pudo activar el bloqueo {block_id} desde estado PENDING."
                )

    def mark_response_block_failed(
        self,
        block_id: str,
        *,
        error: str,
    ) -> None:
        with self._connection() as connection:
            cursor = connection.execute(
                """
                UPDATE response_blocks
                SET status = 'FAILED',
                    last_error = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE block_id = ?
                  AND status = 'PENDING'
                """,
                (
                    error,
                    block_id,
                ),
            )

            if cursor.rowcount != 1:
                raise RuntimeError(
                    f"No se pudo marcar como FAILED el bloqueo {block_id}."
                )

    def mark_response_block_removed(
        self,
        block_id: str,
    ) -> None:
        with self._connection() as connection:
            cursor = connection.execute(
                """
                UPDATE response_blocks
                SET status = 'REMOVED',
                    updated_at = CURRENT_TIMESTAMP
                WHERE block_id = ?
                  AND status IN ('PENDING', 'ACTIVE')
                """,
                (block_id,),
            )

            if cursor.rowcount != 1:
                raise RuntimeError(
                    f"No se pudo marcar como REMOVED el bloqueo {block_id}."
                )

    def expire_response_blocks(
        self,
        *,
        now: datetime,
    ) -> int:
        with self._connection() as connection:
            cursor = connection.execute(
                """
                UPDATE response_blocks
                SET status = 'EXPIRED',
                    updated_at = CURRENT_TIMESTAMP
                WHERE status IN ('PENDING', 'ACTIVE')
                  AND julianday(expires_at) <= julianday(?)
                """,
                (now.astimezone(UTC).isoformat(),),
            )

            return cursor.rowcount

    def fail_pending_response_blocks(
        self,
        *,
        reason: str,
    ) -> int:
        with self._connection() as connection:
            cursor = connection.execute(
                """
                UPDATE response_blocks
                SET status = 'FAILED',
                    last_error = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE status = 'PENDING'
                """,
                (reason,),
            )

            return cursor.rowcount

    def list_active_response_blocks(
        self,
        *,
        now: datetime,
    ) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM response_blocks
                WHERE status = 'ACTIVE'
                  AND julianday(expires_at) > julianday(?)
                ORDER BY expires_at ASC
                """,
                (now.astimezone(UTC).isoformat(),),
            ).fetchall()

        return [dict(row) for row in rows]

    def list_live_response_blocks(
        self,
        *,
        now: datetime,
    ) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM response_blocks
                WHERE status IN ('PENDING', 'ACTIVE')
                  AND julianday(expires_at) > julianday(?)
                ORDER BY expires_at ASC
                """,
                (now.astimezone(UTC).isoformat(),),
            ).fetchall()

        return [dict(row) for row in rows]

    def get_response_block(
        self,
        block_id: str,
    ) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM response_blocks
                WHERE block_id = ?
                """,
                (block_id,),
            ).fetchone()

        if row is None:
            return None

        return dict(row)

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

    def count_before(
        self,
        before: datetime,
    ) -> int:
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS total
                FROM events
                WHERE julianday(timestamp) < julianday(?)
                """,
                (before.astimezone(UTC).isoformat(),),
            ).fetchone()

        return int(row["total"])

    def delete_before(
        self,
        before: datetime,
    ) -> int:
        with self._connection() as connection:
            cursor = connection.execute(
                """
                DELETE FROM events
                WHERE julianday(timestamp) < julianday(?)
                """,
                (before.astimezone(UTC).isoformat(),),
            )

            return cursor.rowcount

    def list_events(
        self,
        *,
        severity: str | None = None,
        event_type: str | None = None,
        hostname: str | None = None,
        category: str | None = None,
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

        if category is not None:
            clauses.append("category = ?")
            parameters.append(category)

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
