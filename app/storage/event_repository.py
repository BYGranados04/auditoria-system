from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.core.events import SecurityEvent


@dataclass(frozen=True)
class PendingOutboxEvent:
    event: SecurityEvent
    attempt_count: int
    next_attempt_at: datetime | None


class EventRepository:
    SCHEMA_VERSION = 5

    def __init__(
        self,
        database_path: Path,
        *,
        read_only: bool = False,
    ) -> None:
        self.database_path = database_path
        self.read_only = read_only

    @contextmanager
    def _connection(
        self,
    ) -> Iterator[sqlite3.Connection]:
        if self.read_only:
            database_uri = self.database_path.absolute().as_uri() + "?mode=ro"

            connection = sqlite3.connect(
                database_uri,
                uri=True,
                timeout=5,
            )
        else:
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

            if self.read_only:
                connection.execute("PRAGMA query_only = ON")

            yield connection

            if not self.read_only:
                connection.commit()

        except Exception:
            if not self.read_only:
                connection.rollback()

            raise

        finally:
            connection.close()

    @staticmethod
    def _hostname_scope(
        hostnames: Iterable[str] | None,
        *,
        column: str = "hostname",
    ) -> tuple[str | None, list[str]]:
        if hostnames is None:
            return None, []
        normalized = tuple(dict.fromkeys(hostnames))
        if not normalized:
            return "1 = 0", []
        placeholders = ", ".join("?" for _ in normalized)
        return f"{column} IN ({placeholders})", list(normalized)

    def initialize(self) -> None:
        if self.read_only:
            raise RuntimeError(
                "No se puede inicializar un repositorio de solo lectura."
            )
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
                3: self._migrate_to_v3,
                4: self._migrate_to_v4,
                5: self._migrate_to_v5,
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

    @staticmethod
    def _migrate_to_v3(
        connection: sqlite3.Connection,
    ) -> None:
        columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(events)").fetchall()
        }
        if "agent_id" not in columns:
            connection.execute("ALTER TABLE events ADD COLUMN agent_id TEXT")
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_agent_timestamp "
            "ON events (agent_id, timestamp)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS event_outbox (
                event_id TEXT PRIMARY KEY
                    REFERENCES events(event_id) ON DELETE CASCADE,
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK (
                        status IN (
                            'pending',
                            'acknowledged',
                            'permanently_failed'
                        )
                    ),
                attempt_count INTEGER NOT NULL DEFAULT 0
                    CHECK (attempt_count >= 0),
                next_attempt_at TEXT,
                last_error TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                acknowledged_at TEXT
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_event_outbox_pending "
            "ON event_outbox (status, next_attempt_at, created_at)"
        )

    @staticmethod
    def _migrate_to_v4(
        connection: sqlite3.Connection,
    ) -> None:
        """Bloqueo IP+puerto, incidentes locales y reincidencia persistente.

        Migración aditiva: no elimina datos. Los bloqueos existentes quedan
        como ``TEMPORARY_BLOCK_IP`` sin protocolo ni puerto.
        """

        columns = {
            str(row["name"])
            for row in connection.execute(
                "PRAGMA table_info(response_blocks)"
            ).fetchall()
        }

        if "action" not in columns:
            connection.execute(
                """
                ALTER TABLE response_blocks
                ADD COLUMN action TEXT NOT NULL
                    DEFAULT 'TEMPORARY_BLOCK_IP'
                    CHECK (
                        action IN (
                            'TEMPORARY_BLOCK_IP',
                            'TEMPORARY_BLOCK_IP_PORT'
                        )
                    )
                """
            )

        if "protocol" not in columns:
            connection.execute(
                """
                ALTER TABLE response_blocks
                ADD COLUMN protocol TEXT
                    CHECK (protocol IS NULL OR protocol IN ('tcp', 'udp'))
                """
            )

        if "port" not in columns:
            connection.execute(
                """
                ALTER TABLE response_blocks
                ADD COLUMN port INTEGER
                    CHECK (port IS NULL OR (port >= 1 AND port <= 65535))
                """
            )

        # El índice único de bloqueos vivos se amplía para distinguir el
        # alcance. Para TEMPORARY_BLOCK_IP la unicidad (hostname, target_ip)
        # se conserva exactamente igual que antes.
        connection.execute("DROP INDEX IF EXISTS idx_response_blocks_live_target")
        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS
                idx_response_blocks_live_target
            ON response_blocks (
                hostname,
                target_ip,
                action,
                COALESCE(protocol, ''),
                COALESCE(port, 0)
            )
            WHERE status IN ('PENDING', 'ACTIVE')
            """
        )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                incident_type TEXT NOT NULL,
                severity TEXT NOT NULL
                    CHECK (severity IN ('low', 'medium', 'high', 'critical')),
                source_ip TEXT,
                status TEXT NOT NULL
                    CHECK (
                        status IN ('OPEN', 'OBSERVED', 'CONTAINED', 'CLOSED')
                    ),
                opened_at TEXT NOT NULL,
                last_activity_at TEXT NOT NULL,
                closed_at TEXT,
                detection_count INTEGER NOT NULL DEFAULT 0
                    CHECK (detection_count >= 0),
                recurrence_level INTEGER,
                last_action TEXT,
                last_execution_status TEXT,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_incidents_lookup "
            "ON incidents (hostname, source_ip, status, last_activity_at)"
        )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS response_offenses (
                offense_id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                detection_event_id TEXT NOT NULL UNIQUE,
                detection_type TEXT NOT NULL,
                incident_id TEXT,
                occurred_at TEXT NOT NULL,
                recurrence_level INTEGER NOT NULL
                    CHECK (recurrence_level >= 1),
                selected_duration_seconds INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_response_offenses_lookup "
            "ON response_offenses (hostname, source_ip, occurred_at)"
        )

    @staticmethod
    def _migrate_to_v5(
        connection: sqlite3.Connection,
    ) -> None:
        """Aprobaciones del modo assisted y cola forense diferida.

        Migración aditiva posterior a v4: solo crea tablas e índices nuevos.
        """

        # Acciones del modo assisted pendientes de aprobación humana. El
        # agente solo ejecuta lo que él mismo propuso y almacenó aquí.
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS response_approvals (
                action_id TEXT PRIMARY KEY,
                incident_id TEXT,
                detection_event_id TEXT NOT NULL UNIQUE,
                decision_event_id TEXT NOT NULL,
                hostname TEXT NOT NULL,
                action TEXT NOT NULL
                    CHECK (
                        action IN (
                            'TEMPORARY_BLOCK_IP',
                            'TEMPORARY_BLOCK_IP_PORT'
                        )
                    ),
                target_ip TEXT NOT NULL,
                protocol TEXT
                    CHECK (protocol IS NULL OR protocol IN ('tcp', 'udp')),
                port INTEGER
                    CHECK (port IS NULL OR (port >= 1 AND port <= 65535)),
                duration_seconds INTEGER NOT NULL
                    CHECK (
                        duration_seconds >= 60
                        AND duration_seconds <= 86400
                    ),
                requested_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                status TEXT NOT NULL
                    CHECK (
                        status IN (
                            'PENDING_APPROVAL',
                            'EXECUTING',
                            'EXECUTED',
                            'SKIPPED',
                            'FAILED',
                            'REJECTED',
                            'EXPIRED'
                        )
                    ),
                decided_by TEXT,
                decided_at TEXT,
                decision_reason TEXT,
                execution_event_id TEXT,
                result_reason TEXT,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_response_approvals_status "
            "ON response_approvals (status, expires_at)"
        )

        # Captura forense ampliada diferida: se procesa después de la
        # contención, en el mismo hilo del agente, y sobrevive reinicios.
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS forensic_capture_queue (
                detection_event_id TEXT PRIMARY KEY,
                incident_id TEXT,
                detection_json TEXT NOT NULL,
                quick_snapshot_json TEXT,
                status TEXT NOT NULL DEFAULT 'PENDING'
                    CHECK (status IN ('PENDING', 'DONE', 'FAILED')),
                attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
                last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_forensic_capture_queue_pending "
            "ON forensic_capture_queue (status, created_at)"
        )

    def add(
        self,
        event: SecurityEvent,
        *,
        enqueue_for_sync: bool = False,
    ) -> None:
        data = event.model_dump(mode="json")

        if enqueue_for_sync and event.agent_id is None:
            raise ValueError("Un evento sin agent_id no puede agregarse al outbox.")

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
                    evidence_json,
                    agent_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    data["agent_id"],
                ),
            )
            if enqueue_for_sync:
                connection.execute(
                    "INSERT INTO event_outbox (event_id) VALUES (?)",
                    (data["event_id"],),
                )

    def list_pending_outbox(
        self,
        *,
        now: datetime,
        limit: int,
    ) -> list[PendingOutboxEvent]:
        if limit < 1:
            return []
        timestamp = now.astimezone(UTC).isoformat()
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT
                    events.*,
                    event_outbox.attempt_count AS outbox_attempt_count,
                    event_outbox.next_attempt_at AS outbox_next_attempt_at
                FROM event_outbox
                JOIN events
                  ON events.event_id = event_outbox.event_id
                WHERE event_outbox.status = 'pending'
                  AND (
                      event_outbox.next_attempt_at IS NULL
                      OR julianday(event_outbox.next_attempt_at) <= julianday(?)
                  )
                ORDER BY event_outbox.created_at, event_outbox.event_id
                LIMIT ?
                """,
                (timestamp, min(limit, 100)),
            ).fetchall()

        pending: list[PendingOutboxEvent] = []
        for row in rows:
            next_attempt_at = (
                datetime.fromisoformat(str(row["outbox_next_attempt_at"]))
                if row["outbox_next_attempt_at"] is not None
                else None
            )
            pending.append(
                PendingOutboxEvent(
                    event=SecurityEvent(
                        event_id=row["event_id"],
                        timestamp=row["timestamp"],
                        agent_id=row["agent_id"],
                        hostname=row["hostname"],
                        source=row["source"],
                        category=row["category"],
                        event_type=row["event_type"],
                        severity=row["severity"],
                        description=row["description"],
                        evidence=json.loads(row["evidence_json"]),
                    ),
                    attempt_count=int(row["outbox_attempt_count"]),
                    next_attempt_at=next_attempt_at,
                )
            )
        return pending

    def mark_outbox_acknowledged(
        self,
        event_ids: Iterable[str],
        *,
        acknowledged_at: datetime,
    ) -> int:
        normalized = tuple(dict.fromkeys(event_ids))
        if not normalized:
            return 0
        placeholders = ", ".join("?" for _ in normalized)
        timestamp = acknowledged_at.astimezone(UTC).isoformat()
        with self._connection() as connection:
            cursor = connection.execute(
                f"""
                UPDATE event_outbox
                SET status = 'acknowledged',
                    next_attempt_at = NULL,
                    last_error = NULL,
                    acknowledged_at = ?
                WHERE status = 'pending'
                  AND event_id IN ({placeholders})
                """,
                (timestamp, *normalized),
            )
        return cursor.rowcount

    def record_outbox_failure(
        self,
        event_id: str,
        *,
        error: str,
        next_attempt_at: datetime | None,
        permanently_failed: bool = False,
    ) -> bool:
        sanitized_error = " ".join(error.split())[:512]
        next_timestamp = (
            next_attempt_at.astimezone(UTC).isoformat()
            if next_attempt_at is not None and not permanently_failed
            else None
        )
        status = "permanently_failed" if permanently_failed else "pending"
        with self._connection() as connection:
            cursor = connection.execute(
                """
                UPDATE event_outbox
                SET status = ?,
                    attempt_count = attempt_count + 1,
                    next_attempt_at = ?,
                    last_error = ?,
                    acknowledged_at = NULL
                WHERE event_id = ?
                  AND status = 'pending'
                """,
                (status, next_timestamp, sanitized_error, event_id),
            )
        return cursor.rowcount == 1

    def defer_pending_outbox(
        self,
        *,
        next_attempt_at: datetime,
        error: str,
    ) -> int:
        sanitized_error = " ".join(error.split())[:512]
        next_timestamp = next_attempt_at.astimezone(UTC).isoformat()
        with self._connection() as connection:
            cursor = connection.execute(
                """
                UPDATE event_outbox
                SET next_attempt_at = CASE
                        WHEN next_attempt_at IS NULL
                          OR julianday(next_attempt_at) < julianday(?)
                        THEN ?
                        ELSE next_attempt_at
                    END,
                    last_error = ?
                WHERE status = 'pending'
                """,
                (next_timestamp, next_timestamp, sanitized_error),
            )
        return cursor.rowcount

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
        action: str = "TEMPORARY_BLOCK_IP",
        protocol: str | None = None,
        port: int | None = None,
    ) -> None:
        if action == "TEMPORARY_BLOCK_IP":
            if protocol is not None or port is not None:
                raise ValueError(
                    "TEMPORARY_BLOCK_IP no admite protocolo ni puerto."
                )
        elif action == "TEMPORARY_BLOCK_IP_PORT":
            if protocol is None or port is None:
                raise ValueError(
                    "TEMPORARY_BLOCK_IP_PORT requiere protocolo y puerto."
                )
        else:
            raise ValueError("Acción de bloqueo no soportada.")

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
                    status,
                    action,
                    protocol,
                    port
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?, ?)
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
                    action,
                    protocol,
                    port,
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

    def mark_active_response_block_failed(
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
                  AND status = 'ACTIVE'
                """,
                (
                    error,
                    block_id,
                ),
            )

            if cursor.rowcount != 1:
                raise RuntimeError(
                    f"No se pudo marcar como FAILED el bloqueo activo {block_id}."
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
        hostnames: Iterable[str] | None = None,
    ) -> list[dict[str, Any]]:
        hostname_clause, hostname_parameters = self._hostname_scope(hostnames)
        scope = f" AND {hostname_clause}" if hostname_clause else ""
        with self._connection() as connection:
            rows = connection.execute(
                f"""
                SELECT *
                FROM response_blocks
                WHERE status IN ('PENDING', 'ACTIVE')
                  AND julianday(expires_at) > julianday(?)
                  {scope}
                ORDER BY expires_at ASC
                """,
                [now.astimezone(UTC).isoformat(), *hostname_parameters],
            ).fetchall()

        return [dict(row) for row in rows]

    def find_live_response_block(
        self,
        *,
        hostname: str,
        target_ip: str,
        action: str,
        protocol: str | None,
        port: int | None,
        now: datetime,
    ) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM response_blocks
                WHERE hostname = ?
                  AND target_ip = ?
                  AND action = ?
                  AND COALESCE(protocol, '') = ?
                  AND COALESCE(port, 0) = ?
                  AND status IN ('PENDING', 'ACTIVE')
                  AND julianday(expires_at) > julianday(?)
                LIMIT 1
                """,
                (
                    hostname,
                    target_ip,
                    action,
                    protocol or "",
                    port or 0,
                    now.astimezone(UTC).isoformat(),
                ),
            ).fetchone()

        return dict(row) if row is not None else None

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

    # ------------------------------------------------------------------
    # Reincidencia persistente
    # ------------------------------------------------------------------

    def count_response_offenses(
        self,
        *,
        hostname: str,
        source_ip: str,
        since: datetime,
        until: datetime,
        exclude_detection_event_id: str | None = None,
    ) -> int:
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS total
                FROM response_offenses
                WHERE hostname = ?
                  AND source_ip = ?
                  AND julianday(occurred_at) > julianday(?)
                  AND julianday(occurred_at) <= julianday(?)
                  AND detection_event_id != ?
                """,
                (
                    hostname,
                    source_ip,
                    since.astimezone(UTC).isoformat(),
                    until.astimezone(UTC).isoformat(),
                    exclude_detection_event_id or "",
                ),
            ).fetchone()

        return int(row["total"])

    def record_response_offense(
        self,
        *,
        offense_id: str,
        hostname: str,
        source_ip: str,
        detection_event_id: str,
        detection_type: str,
        incident_id: str | None,
        occurred_at: datetime,
        recurrence_level: int,
        selected_duration_seconds: int | None,
    ) -> bool:
        with self._connection() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO response_offenses (
                    offense_id,
                    hostname,
                    source_ip,
                    detection_event_id,
                    detection_type,
                    incident_id,
                    occurred_at,
                    recurrence_level,
                    selected_duration_seconds
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    offense_id,
                    hostname,
                    source_ip,
                    detection_event_id,
                    detection_type,
                    incident_id,
                    occurred_at.astimezone(UTC).isoformat(),
                    recurrence_level,
                    selected_duration_seconds,
                ),
            )

        return cursor.rowcount == 1

    # ------------------------------------------------------------------
    # Aprobaciones del modo assisted
    # ------------------------------------------------------------------

    def create_response_approval(
        self,
        *,
        action_id: str,
        incident_id: str | None,
        detection_event_id: str,
        decision_event_id: str,
        hostname: str,
        action: str,
        target_ip: str,
        protocol: str | None,
        port: int | None,
        duration_seconds: int,
        requested_at: datetime,
        expires_at: datetime,
    ) -> None:
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO response_approvals (
                    action_id, incident_id, detection_event_id,
                    decision_event_id, hostname, action, target_ip,
                    protocol, port, duration_seconds, requested_at,
                    expires_at, status, updated_at
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    'PENDING_APPROVAL', ?
                )
                """,
                (
                    action_id,
                    incident_id,
                    detection_event_id,
                    decision_event_id,
                    hostname,
                    action,
                    target_ip,
                    protocol,
                    port,
                    duration_seconds,
                    requested_at.astimezone(UTC).isoformat(),
                    expires_at.astimezone(UTC).isoformat(),
                    requested_at.astimezone(UTC).isoformat(),
                ),
            )

    def get_response_approval(self, action_id: str) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM response_approvals WHERE action_id = ?",
                (action_id,),
            ).fetchone()

        return dict(row) if row is not None else None

    def count_pending_response_approvals(self) -> int:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS total FROM response_approvals "
                "WHERE status = 'PENDING_APPROVAL'"
            ).fetchone()

        return int(row["total"])

    def claim_response_approval(
        self,
        action_id: str,
        *,
        decided_by: str,
        decided_at: datetime,
        now: datetime,
    ) -> dict[str, Any] | None:
        """Transición atómica PENDING_APPROVAL -> EXECUTING.

        Devuelve la fila solo a quien gana la transición; impide la doble
        ejecución y la ejecución de acciones vencidas.
        """

        with self._connection() as connection:
            cursor = connection.execute(
                """
                UPDATE response_approvals
                SET status = 'EXECUTING',
                    decided_by = ?,
                    decided_at = ?,
                    updated_at = ?
                WHERE action_id = ?
                  AND status = 'PENDING_APPROVAL'
                  AND julianday(expires_at) > julianday(?)
                """,
                (
                    decided_by,
                    decided_at.astimezone(UTC).isoformat(),
                    now.astimezone(UTC).isoformat(),
                    action_id,
                    now.astimezone(UTC).isoformat(),
                ),
            )
            if cursor.rowcount != 1:
                return None
            row = connection.execute(
                "SELECT * FROM response_approvals WHERE action_id = ?",
                (action_id,),
            ).fetchone()

        return dict(row)

    def finish_response_approval(
        self,
        action_id: str,
        *,
        status: str,
        result_reason: str,
        execution_event_id: str | None,
        now: datetime,
    ) -> None:
        if status not in {"EXECUTED", "SKIPPED", "FAILED"}:
            raise ValueError("Estado final de aprobación no válido.")

        with self._connection() as connection:
            cursor = connection.execute(
                """
                UPDATE response_approvals
                SET status = ?,
                    result_reason = ?,
                    execution_event_id = ?,
                    updated_at = ?
                WHERE action_id = ?
                  AND status = 'EXECUTING'
                """,
                (
                    status,
                    result_reason[:500],
                    execution_event_id,
                    now.astimezone(UTC).isoformat(),
                    action_id,
                ),
            )
            if cursor.rowcount != 1:
                raise RuntimeError(
                    f"La aprobación {action_id} no estaba en ejecución."
                )

    def reject_response_approval(
        self,
        action_id: str,
        *,
        decided_by: str,
        decided_at: datetime,
        reason: str | None,
        now: datetime,
    ) -> dict[str, Any] | None:
        with self._connection() as connection:
            cursor = connection.execute(
                """
                UPDATE response_approvals
                SET status = 'REJECTED',
                    decided_by = ?,
                    decided_at = ?,
                    decision_reason = ?,
                    updated_at = ?
                WHERE action_id = ?
                  AND status = 'PENDING_APPROVAL'
                """,
                (
                    decided_by,
                    decided_at.astimezone(UTC).isoformat(),
                    reason,
                    now.astimezone(UTC).isoformat(),
                    action_id,
                ),
            )
            if cursor.rowcount != 1:
                return None
            row = connection.execute(
                "SELECT * FROM response_approvals WHERE action_id = ?",
                (action_id,),
            ).fetchone()

        return dict(row)

    def expire_response_approvals(self, *, now: datetime) -> list[dict[str, Any]]:
        timestamp = now.astimezone(UTC).isoformat()
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM response_approvals
                WHERE status = 'PENDING_APPROVAL'
                  AND julianday(expires_at) <= julianday(?)
                """,
                (timestamp,),
            ).fetchall()
            expired: list[dict[str, Any]] = []
            for row in rows:
                cursor = connection.execute(
                    """
                    UPDATE response_approvals
                    SET status = 'EXPIRED', updated_at = ?
                    WHERE action_id = ? AND status = 'PENDING_APPROVAL'
                    """,
                    (timestamp, row["action_id"]),
                )
                if cursor.rowcount == 1:
                    expired.append({**dict(row), "status": "EXPIRED"})

        return expired

    def fail_interrupted_response_approvals(self, *, reason: str) -> int:
        """EXECUTING tras un reinicio no puede confirmarse: queda FAILED."""

        with self._connection() as connection:
            cursor = connection.execute(
                """
                UPDATE response_approvals
                SET status = 'FAILED', result_reason = ?, updated_at = ?
                WHERE status = 'EXECUTING'
                """,
                (reason, datetime.now(UTC).isoformat()),
            )

        return cursor.rowcount

    # ------------------------------------------------------------------
    # Cola de captura forense ampliada
    # ------------------------------------------------------------------

    def enqueue_forensic_capture(
        self,
        *,
        detection_event_id: str,
        incident_id: str | None,
        detection_json: str,
        quick_snapshot_json: str | None,
        created_at: datetime,
    ) -> bool:
        timestamp = created_at.astimezone(UTC).isoformat()
        with self._connection() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO forensic_capture_queue (
                    detection_event_id, incident_id, detection_json,
                    quick_snapshot_json, status, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, 'PENDING', ?, ?)
                """,
                (
                    detection_event_id,
                    incident_id,
                    detection_json,
                    quick_snapshot_json,
                    timestamp,
                    timestamp,
                ),
            )

        return cursor.rowcount == 1

    def list_pending_forensic_captures(self, *, limit: int) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM forensic_capture_queue
                WHERE status = 'PENDING'
                ORDER BY created_at ASC
                LIMIT ?
                """,
                (max(1, min(limit, 100)),),
            ).fetchall()

        return [dict(row) for row in rows]

    def update_forensic_capture(
        self,
        detection_event_id: str,
        *,
        status: str,
        error: str | None,
        now: datetime,
    ) -> None:
        if status not in {"PENDING", "DONE", "FAILED"}:
            raise ValueError("Estado de captura no válido.")

        with self._connection() as connection:
            connection.execute(
                """
                UPDATE forensic_capture_queue
                SET status = ?,
                    attempts = attempts + 1,
                    last_error = ?,
                    updated_at = ?
                WHERE detection_event_id = ?
                """,
                (
                    status,
                    error[:300] if error else None,
                    now.astimezone(UTC).isoformat(),
                    detection_event_id,
                ),
            )

    # ------------------------------------------------------------------
    # Incidentes locales del agente
    # ------------------------------------------------------------------

    def find_active_incident(
        self,
        *,
        hostname: str,
        source_ip: str,
        active_since: datetime,
    ) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM incidents
                WHERE hostname = ?
                  AND source_ip = ?
                  AND status != 'CLOSED'
                  AND julianday(last_activity_at) >= julianday(?)
                ORDER BY last_activity_at DESC
                LIMIT 1
                """,
                (
                    hostname,
                    source_ip,
                    active_since.astimezone(UTC).isoformat(),
                ),
            ).fetchone()

        return dict(row) if row is not None else None

    def create_incident(
        self,
        *,
        incident_id: str,
        hostname: str,
        incident_type: str,
        severity: str,
        source_ip: str | None,
        status: str,
        opened_at: datetime,
    ) -> dict[str, Any]:
        timestamp = opened_at.astimezone(UTC).isoformat()
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO incidents (
                    incident_id,
                    hostname,
                    incident_type,
                    severity,
                    source_ip,
                    status,
                    opened_at,
                    last_activity_at,
                    detection_count,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                """,
                (
                    incident_id,
                    hostname,
                    incident_type,
                    severity,
                    source_ip,
                    status,
                    timestamp,
                    timestamp,
                    timestamp,
                ),
            )
            row = connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()

        return dict(row)

    def update_incident(
        self,
        incident_id: str,
        *,
        updated_at: datetime,
        severity: str | None = None,
        status: str | None = None,
        last_activity_at: datetime | None = None,
        closed_at: datetime | None = None,
        increment_detections: int = 0,
        recurrence_level: int | None = None,
        last_action: str | None = None,
        last_execution_status: str | None = None,
    ) -> dict[str, Any]:
        assignments = [
            "updated_at = ?",
            "detection_count = detection_count + ?",
        ]
        parameters: list[Any] = [
            updated_at.astimezone(UTC).isoformat(),
            max(increment_detections, 0),
        ]

        optional: tuple[tuple[str, Any], ...] = (
            ("severity", severity),
            ("status", status),
            (
                "last_activity_at",
                last_activity_at.astimezone(UTC).isoformat()
                if last_activity_at is not None
                else None,
            ),
            (
                "closed_at",
                closed_at.astimezone(UTC).isoformat()
                if closed_at is not None
                else None,
            ),
            ("recurrence_level", recurrence_level),
            ("last_action", last_action),
            ("last_execution_status", last_execution_status),
        )

        for column, value in optional:
            if value is not None:
                assignments.append(f"{column} = ?")
                parameters.append(value)

        parameters.append(incident_id)

        with self._connection() as connection:
            cursor = connection.execute(
                f"UPDATE incidents SET {', '.join(assignments)} "
                "WHERE incident_id = ?",
                parameters,
            )
            if cursor.rowcount != 1:
                raise RuntimeError(f"No existe el incidente {incident_id}.")
            row = connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()

        return dict(row)

    def get_incident(
        self,
        incident_id: str,
    ) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()

        return dict(row) if row is not None else None

    def list_stale_incidents(
        self,
        *,
        inactive_before: datetime,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM incidents
                WHERE status != 'CLOSED'
                  AND julianday(last_activity_at) < julianday(?)
                ORDER BY last_activity_at ASC
                LIMIT ?
                """,
                (
                    inactive_before.astimezone(UTC).isoformat(),
                    max(1, min(limit, 1000)),
                ),
            ).fetchall()

        return [dict(row) for row in rows]

    def statistics(
        self,
        *,
        hostnames: Iterable[str] | None = None,
    ) -> dict[str, Any]:
        hostname_clause, parameters = self._hostname_scope(hostnames)
        where = f" WHERE {hostname_clause}" if hostname_clause else ""
        with self._connection() as connection:
            total = connection.execute(
                f"SELECT COUNT(*) AS total FROM events{where}",
                parameters,
            ).fetchone()["total"]

            severity_rows = connection.execute(
                f"""
                SELECT severity, COUNT(*) AS total
                FROM events
                {where}
                GROUP BY severity
                ORDER BY severity
                """,
                parameters,
            ).fetchall()

            type_rows = connection.execute(
                f"""
                SELECT event_type, COUNT(*) AS total
                FROM events
                {where}
                GROUP BY event_type
                ORDER BY total DESC, event_type
                """,
                parameters,
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

    def list_known_hostnames(self) -> list[str]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT DISTINCT hostname
                FROM events
                WHERE hostname != ''
                ORDER BY hostname
                """
            ).fetchall()
        return [str(row["hostname"]) for row in rows]

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
        event_types: tuple[str, ...] | None = None,
        hostname: str | None = None,
        hostnames: Iterable[str] | None = None,
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

        if event_type is not None and event_types is not None:
            raise ValueError(
                "event_type y event_types no pueden usarse al mismo tiempo."
            )

        if event_type is not None:
            clauses.append("event_type = ?")
            parameters.append(event_type)
        elif event_types:
            placeholders = ", ".join("?" for _ in event_types)
            clauses.append(f"event_type IN ({placeholders})")
            parameters.extend(event_types)

        if hostname is not None:
            clauses.append("hostname = ?")
            parameters.append(hostname)

        hostname_clause, hostname_parameters = self._hostname_scope(hostnames)
        if hostname_clause is not None:
            clauses.append(hostname_clause)
            parameters.extend(hostname_parameters)

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
