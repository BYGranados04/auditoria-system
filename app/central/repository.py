from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.core.events import SecurityEvent


class CentralEventConflictError(RuntimeError):
    pass


@dataclass(frozen=True)
class CentralBatchResult:
    accepted: int
    inserted: int
    duplicates: int


def _utc_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("La fecha debe incluir zona horaria.")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def canonical_event_payload(event: SecurityEvent) -> bytes:
    data = event.model_dump(mode="json")
    payload = {
        "event_id": data["event_id"],
        "occurred_at": _utc_timestamp(event.timestamp),
        "hostname": data["hostname"],
        "source": data["source"],
        "category": data["category"],
        "event_type": data["event_type"],
        "severity": data["severity"],
        "description": data["description"],
        "evidence": data["evidence"],
    }
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def event_payload_hash(event: SecurityEvent) -> str:
    return hashlib.sha256(canonical_event_payload(event)).hexdigest()


class CentralEventRepository:
    SCHEMA_VERSION = 1

    def __init__(
        self,
        database_path: Path,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.database_path = database_path
        self.clock = clock or (lambda: datetime.now(UTC))

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.database_path, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA busy_timeout = 5000")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @contextmanager
    def _read_connection(self) -> Iterator[sqlite3.Connection]:
        uri = f"{self.database_path.resolve().as_uri()}?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            yield connection
        finally:
            connection.close()

    def initialize(self) -> None:
        with self._connection() as connection:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version > self.SCHEMA_VERSION:
                raise RuntimeError("central.db usa un esquema más nuevo.")
            connection.execute("PRAGMA journal_mode = WAL")
            if version < 1:
                self._migrate_to_v1(connection)
                connection.execute("PRAGMA user_version = 1")

    @staticmethod
    def _migrate_to_v1(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                received_at TEXT NOT NULL,
                hostname TEXT NOT NULL,
                source TEXT NOT NULL,
                category TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                payload_hash TEXT NOT NULL,
                UNIQUE (agent_id, event_id)
            );

            CREATE INDEX IF NOT EXISTS idx_central_events_agent_occurred
                ON events (agent_id, occurred_at);
            CREATE INDEX IF NOT EXISTS idx_central_events_agent_category_occurred
                ON events (agent_id, category, occurred_at);
            CREATE INDEX IF NOT EXISTS idx_central_events_agent_severity_occurred
                ON events (agent_id, severity, occurred_at);
            CREATE INDEX IF NOT EXISTS idx_central_events_received
                ON events (received_at);
            """
        )

    @staticmethod
    def _record(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": int(row["id"]),
            "agent_id": str(row["agent_id"]),
            "event_id": str(row["event_id"]),
            "occurred_at": str(row["occurred_at"]),
            "received_at": str(row["received_at"]),
            "hostname": str(row["hostname"]),
            "source": str(row["source"]),
            "category": str(row["category"]),
            "event_type": str(row["event_type"]),
            "severity": str(row["severity"]),
            "description": str(row["description"]),
            "evidence": json.loads(str(row["evidence_json"])),
            "payload_hash": str(row["payload_hash"]),
        }

    def add_event(
        self,
        *,
        agent_id: str,
        event: SecurityEvent,
    ) -> tuple[dict[str, Any], bool]:
        result, records = self._add_events(
            agent_id=agent_id,
            events=(event,),
        )
        return records[0], result.inserted == 1

    def add_events(
        self,
        *,
        agent_id: str,
        events: tuple[SecurityEvent, ...],
    ) -> CentralBatchResult:
        result, _ = self._add_events(agent_id=agent_id, events=events)
        return result

    def _add_events(
        self,
        *,
        agent_id: str,
        events: tuple[SecurityEvent, ...],
    ) -> tuple[CentralBatchResult, list[dict[str, Any]]]:
        normalized_agent_id = agent_id.strip()
        if not normalized_agent_id:
            raise ValueError("agent_id es obligatorio.")
        if not events:
            raise ValueError("El batch no puede estar vacío.")

        self.initialize()
        received_at = _utc_timestamp(self.clock())
        prepared: list[tuple[dict[str, Any], str, str, str]] = []
        for event in events:
            data = event.model_dump(mode="json")
            prepared.append(
                (
                    data,
                    _utc_timestamp(event.timestamp),
                    json.dumps(
                        data["evidence"],
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    ),
                    event_payload_hash(event),
                )
            )

        inserted = 0
        records: list[dict[str, Any]] = []
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for data, occurred_at, evidence_json, payload_hash in prepared:
                cursor = connection.execute(
                    """
                    INSERT OR IGNORE INTO events (
                        agent_id,
                        event_id,
                        occurred_at,
                        received_at,
                        hostname,
                        source,
                        category,
                        event_type,
                        severity,
                        description,
                        evidence_json,
                        payload_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        normalized_agent_id,
                        data["event_id"],
                        occurred_at,
                        received_at,
                        data["hostname"],
                        data["source"],
                        data["category"],
                        data["event_type"],
                        data["severity"],
                        data["description"],
                        evidence_json,
                        payload_hash,
                    ),
                )
                row = connection.execute(
                    """
                    SELECT *
                    FROM events
                    WHERE agent_id = ? AND event_id = ?
                    """,
                    (normalized_agent_id, data["event_id"]),
                ).fetchone()
                if row is None:
                    raise RuntimeError("No se pudo persistir el evento central.")
                if cursor.rowcount == 0 and str(row["payload_hash"]) != payload_hash:
                    raise CentralEventConflictError(
                        "El event_id ya existe para el agente con otro payload."
                    )
                inserted += cursor.rowcount
                records.append(self._record(row))

        accepted = len(events)
        return (
            CentralBatchResult(
                accepted=accepted,
                inserted=inserted,
                duplicates=accepted - inserted,
            ),
            records,
        )

    def list_events(
        self,
        *,
        agent_ids: tuple[str, ...] | None = None,
        agent_id: str | None = None,
        category: str | None = None,
        severity: str | None = None,
        event_type: str | None = None,
        event_types: tuple[str, ...] | None = None,
        hostname: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if (
            limit < 1
            or agent_ids == ()
            or event_types == ()
            or not self.database_path.is_file()
        ):
            return []
        clauses: list[str] = []
        parameters: list[object] = []
        if agent_ids is not None:
            placeholders = ", ".join("?" for _ in agent_ids)
            clauses.append(f"agent_id IN ({placeholders})")
            parameters.extend(agent_ids)
        if agent_id is not None:
            clauses.append("agent_id = ?")
            parameters.append(agent_id)
        if event_types is not None:
            placeholders = ", ".join("?" for _ in event_types)
            clauses.append(f"event_type IN ({placeholders})")
            parameters.extend(event_types)
        for column, value in (
            ("category", category),
            ("severity", severity),
            ("event_type", event_type),
            ("hostname", hostname),
        ):
            if value is not None:
                clauses.append(f"{column} = ?")
                parameters.append(value)
        if since is not None:
            clauses.append("occurred_at >= ?")
            parameters.append(_utc_timestamp(since))
        if until is not None:
            clauses.append("occurred_at <= ?")
            parameters.append(_utc_timestamp(until))
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        parameters.append(limit)
        with self._read_connection() as connection:
            rows = connection.execute(
                f"""
                SELECT *
                FROM events
                {where}
                ORDER BY occurred_at DESC, id DESC
                LIMIT ?
                """,
                parameters,
            ).fetchall()
        return [self._record(row) for row in rows]

    def statistics(
        self,
        *,
        agent_ids: tuple[str, ...] | None = None,
    ) -> dict[str, Any]:
        empty = {
            "total": 0,
            "by_severity": {
                "low": 0,
                "medium": 0,
                "high": 0,
                "critical": 0,
            },
        }
        if agent_ids == () or not self.database_path.is_file():
            return empty
        parameters: list[object] = []
        where = ""
        if agent_ids is not None:
            placeholders = ", ".join("?" for _ in agent_ids)
            where = f" WHERE agent_id IN ({placeholders})"
            parameters.extend(agent_ids)
        with self._read_connection() as connection:
            rows = connection.execute(
                "SELECT severity, COUNT(*) AS count FROM events"
                f"{where} GROUP BY severity",
                parameters,
            ).fetchall()
        by_severity = dict(empty["by_severity"])
        for row in rows:
            severity = str(row["severity"])
            if severity in by_severity:
                by_severity[severity] = int(row["count"])
        return {
            "total": sum(by_severity.values()),
            "by_severity": by_severity,
        }
