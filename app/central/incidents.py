"""Proyección y consulta central de incidentes.

El agente es la fuente de verdad: emite eventos ``INCIDENT_OPENED`` e
``INCIDENT_UPDATED`` (categoría ``incident``) por el outbox existente. Al
ingresar un evento nuevo, el central actualiza dos tablas derivadas en la
misma transacción:

- ``incidents``: último estado conocido de cada incidente por agente.
- ``incident_links``: referencias (agent_id, event_id) a eventos ya
  almacenados en ``events``. La timeline se arma por JOIN; no se duplican los
  datos de los eventos.

Los payloads inválidos no rechazan el batch (el evento se conserva tal como
llegó); simplemente no se proyectan.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from uuid import UUID

INCIDENT_EVENT_TYPES = frozenset({"INCIDENT_OPENED", "INCIDENT_UPDATED"})
INCIDENT_ID_PATTERN = re.compile(r"^INC-[0-9A-F]{16}$")
INCIDENT_STATUSES = frozenset({"OPEN", "OBSERVED", "CONTAINED", "CLOSED"})
SEVERITIES = frozenset({"low", "medium", "high", "critical"})
LINK_KINDS = ("event", "detection", "evidence", "decision", "approval", "execution")
KIND_ORDER = {
    "event": 0,
    "detection": 1,
    "decision": 2,
    "approval": 3,
    "execution": 4,
    "evidence": 5,
}
ACTION_STATUSES = frozenset(
    {
        "PENDING_APPROVAL",
        "APPROVED",
        "REJECTED",
        "EXECUTED",
        "SKIPPED",
        "FAILED",
        "EXPIRED",
    }
)
EXECUTABLE_ACTIONS = frozenset({"TEMPORARY_BLOCK_IP", "TEMPORARY_BLOCK_IP_PORT"})
TYPE_PATTERN = re.compile(r"^[A-Z0-9_]{1,128}$")
MAXIMUM_LINKS_PER_EVENT = 200


def migrate_incidents_v2(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            agent_id TEXT NOT NULL,
            incident_id TEXT NOT NULL,
            hostname TEXT NOT NULL,
            incident_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT,
            status TEXT NOT NULL,
            opened_at TEXT NOT NULL,
            last_activity_at TEXT NOT NULL,
            closed_at TEXT,
            detection_count INTEGER NOT NULL DEFAULT 0,
            recurrence_level INTEGER,
            last_action TEXT,
            last_execution_status TEXT,
            last_event_at TEXT NOT NULL,
            last_event_id TEXT NOT NULL,
            PRIMARY KEY (agent_id, incident_id)
        );

        CREATE INDEX IF NOT EXISTS idx_central_incidents_agent_opened
            ON incidents (agent_id, opened_at);
        CREATE INDEX IF NOT EXISTS idx_central_incidents_status
            ON incidents (status, opened_at);
        CREATE INDEX IF NOT EXISTS idx_central_incidents_severity
            ON incidents (severity, opened_at);
        CREATE INDEX IF NOT EXISTS idx_central_incidents_type
            ON incidents (incident_type, opened_at);
        CREATE INDEX IF NOT EXISTS idx_central_incidents_source
            ON incidents (source_ip);

        CREATE TABLE IF NOT EXISTS incident_links (
            agent_id TEXT NOT NULL,
            incident_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            PRIMARY KEY (agent_id, incident_id, event_id)
        );

        CREATE INDEX IF NOT EXISTS idx_central_incident_links_timeline
            ON incident_links (agent_id, incident_id, occurred_at);
        """
    )


def migrate_response_actions_v3(connection: sqlite3.Connection) -> None:
    """Acciones del modo assisted (aprobación humana). Aditiva sobre v2."""

    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS response_actions (
            agent_id TEXT NOT NULL,
            action_id TEXT NOT NULL,
            incident_id TEXT,
            detection_event_id TEXT,
            decision_event_id TEXT,
            request_event_id TEXT NOT NULL,
            hostname TEXT NOT NULL,
            action TEXT NOT NULL,
            target_ip TEXT NOT NULL,
            protocol TEXT,
            port INTEGER,
            duration_seconds INTEGER NOT NULL,
            requested_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            status TEXT NOT NULL,
            decided_by_user_id INTEGER,
            decided_by TEXT,
            decided_at TEXT,
            decision_reason TEXT,
            result_status TEXT,
            result_reason TEXT,
            result_at TEXT,
            result_event_id TEXT,
            PRIMARY KEY (agent_id, action_id)
        );

        CREATE INDEX IF NOT EXISTS idx_central_response_actions_incident
            ON response_actions (agent_id, incident_id);
        CREATE INDEX IF NOT EXISTS idx_central_response_actions_delivery
            ON response_actions (agent_id, status, result_status);
        """
    )


def _utc(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return (
        parsed.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    )


def _optional_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _optional_type(value: object) -> str | None:
    if isinstance(value, str) and TYPE_PATTERN.fullmatch(value):
        return value
    return None


def _valid_ip(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ip_address(value))
    except ValueError:
        return None


def _valid_uuid(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(UUID(value))
    except ValueError:
        return None


def parse_incident_payload(evidence: dict[str, Any]) -> dict[str, Any] | None:
    incident_id = evidence.get("incident_id")
    status = evidence.get("status")
    severity = evidence.get("severity")
    incident_type = _optional_type(evidence.get("incident_type"))
    opened_at = _utc(evidence.get("opened_at"))
    last_activity_at = _utc(evidence.get("last_activity_at"))

    if (
        not isinstance(incident_id, str)
        or INCIDENT_ID_PATTERN.fullmatch(incident_id) is None
        or status not in INCIDENT_STATUSES
        or severity not in SEVERITIES
        or incident_type is None
        or opened_at is None
        or last_activity_at is None
    ):
        return None

    links: list[dict[str, str]] = []
    raw_links = evidence.get("links", [])

    if not isinstance(raw_links, list):
        return None

    for item in raw_links[:MAXIMUM_LINKS_PER_EVENT]:
        if not isinstance(item, dict):
            continue
        event_id = _valid_uuid(item.get("event_id"))
        kind = item.get("kind")
        occurred_at = _utc(item.get("occurred_at"))
        if event_id is None or kind not in LINK_KINDS or occurred_at is None:
            continue
        links.append(
            {
                "event_id": event_id,
                "kind": str(kind),
                "occurred_at": occurred_at,
            }
        )

    detection_count = _optional_int(evidence.get("detection_count")) or 0

    return {
        "incident_id": incident_id,
        "incident_type": incident_type,
        "severity": severity,
        "source_ip": _valid_ip(evidence.get("source_ip")),
        "status": status,
        "opened_at": opened_at,
        "last_activity_at": last_activity_at,
        "closed_at": _utc(evidence.get("closed_at")),
        "detection_count": max(detection_count, 0),
        "recurrence_level": _optional_int(evidence.get("recurrence_level")),
        "last_action": _optional_type(evidence.get("last_action")),
        "last_execution_status": _optional_type(evidence.get("last_execution_status")),
        "links": links,
    }


def project_incident_event(
    connection: sqlite3.Connection,
    *,
    agent_id: str,
    event_id: str,
    hostname: str,
    occurred_at: str,
    event_type: str,
    category: str,
    evidence: dict[str, Any],
) -> bool:
    if category != "incident" or event_type not in INCIDENT_EVENT_TYPES:
        return False

    payload = parse_incident_payload(evidence)

    if payload is None:
        return False

    connection.execute(
        """
        INSERT INTO incidents (
            agent_id,
            incident_id,
            hostname,
            incident_type,
            severity,
            source_ip,
            status,
            opened_at,
            last_activity_at,
            closed_at,
            detection_count,
            recurrence_level,
            last_action,
            last_execution_status,
            last_event_at,
            last_event_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (agent_id, incident_id) DO UPDATE SET
            hostname = excluded.hostname,
            severity = excluded.severity,
            source_ip = excluded.source_ip,
            status = excluded.status,
            last_activity_at = excluded.last_activity_at,
            closed_at = excluded.closed_at,
            detection_count = excluded.detection_count,
            recurrence_level = COALESCE(
                excluded.recurrence_level,
                incidents.recurrence_level
            ),
            last_action = COALESCE(excluded.last_action, incidents.last_action),
            last_execution_status = COALESCE(
                excluded.last_execution_status,
                incidents.last_execution_status
            ),
            last_event_at = excluded.last_event_at,
            last_event_id = excluded.last_event_id
        WHERE excluded.last_event_at >= incidents.last_event_at
        """,
        (
            agent_id,
            payload["incident_id"],
            hostname,
            payload["incident_type"],
            payload["severity"],
            payload["source_ip"],
            payload["status"],
            payload["opened_at"],
            payload["last_activity_at"],
            payload["closed_at"],
            payload["detection_count"],
            payload["recurrence_level"],
            payload["last_action"],
            payload["last_execution_status"],
            occurred_at,
            event_id,
        ),
    )

    for item in payload["links"]:
        connection.execute(
            """
            INSERT OR IGNORE INTO incident_links (
                agent_id,
                incident_id,
                event_id,
                kind,
                occurred_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                agent_id,
                payload["incident_id"],
                item["event_id"],
                item["kind"],
                item["occurred_at"],
            ),
        )

    return True


_KIND_ORDER_SQL = (
    "CASE l.kind WHEN 'event' THEN 0 WHEN 'detection' THEN 1 "
    "WHEN 'decision' THEN 2 WHEN 'approval' THEN 3 "
    "WHEN 'execution' THEN 4 ELSE 5 END"
)


def project_event(
    connection: sqlite3.Connection,
    *,
    agent_id: str,
    event_id: str,
    hostname: str,
    occurred_at: str,
    event_type: str,
    category: str,
    evidence: dict[str, Any],
) -> None:
    """Proyecciones derivadas para un evento recién insertado."""

    project_incident_event(
        connection,
        agent_id=agent_id,
        event_id=event_id,
        hostname=hostname,
        occurred_at=occurred_at,
        event_type=event_type,
        category=category,
        evidence=evidence,
    )
    if category == "response":
        project_response_action_event(
            connection,
            agent_id=agent_id,
            event_id=event_id,
            hostname=hostname,
            occurred_at=occurred_at,
            event_type=event_type,
            evidence=evidence,
        )


def project_response_action_event(
    connection: sqlite3.Connection,
    *,
    agent_id: str,
    event_id: str,
    hostname: str,
    occurred_at: str,
    event_type: str,
    evidence: dict[str, Any],
) -> bool:
    """Registra solicitudes de aprobación y resultados informados por el agente.

    El agente solo puede crear solicitudes PENDING_APPROVAL e informar el
    resultado de acciones que un humano ya aprobó o rechazó en el central;
    nunca puede aprobar ni rechazar por sí mismo.
    """

    action_id = _valid_uuid(evidence.get("approval_id"))

    if action_id is None:
        return False

    if event_type == "RESPONSE_APPROVAL_REQUESTED":
        action = evidence.get("action")
        target_ip = _valid_ip(evidence.get("target_ip"))
        duration = _optional_int(evidence.get("duration_seconds"))
        requested_at = _utc(evidence.get("requested_at"))
        expires_at = _utc(evidence.get("expires_at"))
        incident_id = evidence.get("incident_id")
        protocol = evidence.get("protocol")
        port = _optional_int(evidence.get("port"))

        if (
            action not in EXECUTABLE_ACTIONS
            or target_ip is None
            or duration is None
            or not 60 <= duration <= 86400
            or requested_at is None
            or expires_at is None
            or protocol not in (None, "tcp", "udp")
            or (port is not None and not 1 <= port <= 65535)
            or (
                incident_id is not None
                and (
                    not isinstance(incident_id, str)
                    or INCIDENT_ID_PATTERN.fullmatch(incident_id) is None
                )
            )
        ):
            return False

        connection.execute(
            """
            INSERT OR IGNORE INTO response_actions (
                agent_id, action_id, incident_id, detection_event_id,
                decision_event_id, request_event_id, hostname, action,
                target_ip, protocol, port, duration_seconds, requested_at,
                expires_at, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING_APPROVAL')
            """,
            (
                agent_id,
                action_id,
                incident_id,
                _valid_uuid(evidence.get("detection_event_id")),
                _valid_uuid(evidence.get("decision_event_id")),
                event_id,
                hostname,
                action,
                target_ip,
                protocol,
                port,
                duration,
                requested_at,
                expires_at,
            ),
        )
        return True

    if event_type == "RESPONSE_EXECUTION":
        status = evidence.get("status")
        if (
            status not in {"EXECUTED", "SKIPPED", "FAILED", "DRY_RUN"}
            or not isinstance(evidence.get("approved_by"), str)
        ):
            # Solo resultados de ejecuciones aprobadas (no la evaluación
            # inicial de la decisión pendiente).
            return False
        final = "SKIPPED" if status == "DRY_RUN" else str(status)
        cursor = connection.execute(
            """
            UPDATE response_actions
            SET status = ?,
                result_status = ?,
                result_reason = ?,
                result_at = ?,
                result_event_id = ?
            WHERE agent_id = ? AND action_id = ? AND status = 'APPROVED'
            """,
            (
                final,
                final,
                _short_text(evidence.get("reason")),
                occurred_at,
                event_id,
                agent_id,
                action_id,
            ),
        )
        return cursor.rowcount == 1

    if event_type == "RESPONSE_REJECTION_APPLIED":
        cursor = connection.execute(
            """
            UPDATE response_actions
            SET result_status = 'REJECTED',
                result_reason = 'Rechazo aplicado por el agente.',
                result_at = ?,
                result_event_id = ?
            WHERE agent_id = ? AND action_id = ? AND status = 'REJECTED'
            """,
            (occurred_at, event_id, agent_id, action_id),
        )
        return cursor.rowcount == 1

    if event_type == "RESPONSE_APPROVAL_EXPIRED":
        cursor = connection.execute(
            """
            UPDATE response_actions
            SET status = 'EXPIRED',
                result_status = 'EXPIRED',
                result_reason = 'La acción venció en el agente.',
                result_at = ?,
                result_event_id = ?
            WHERE agent_id = ? AND action_id = ?
              AND status IN ('PENDING_APPROVAL', 'APPROVED')
            """,
            (occurred_at, event_id, agent_id, action_id),
        )
        return cursor.rowcount == 1

    return False


def _short_text(value: object, limit: int = 500) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = "".join(
        character if character.isprintable() else " " for character in value
    )
    return " ".join(cleaned.split())[:limit] or None


def action_record(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "agent_id": str(row["agent_id"]),
        "action_id": str(row["action_id"]),
        "incident_id": row["incident_id"],
        "hostname": str(row["hostname"]),
        "action": str(row["action"]),
        "target_ip": str(row["target_ip"]),
        "protocol": row["protocol"],
        "port": row["port"],
        "duration_seconds": int(row["duration_seconds"]),
        "requested_at": str(row["requested_at"]),
        "expires_at": str(row["expires_at"]),
        "status": str(row["status"]),
        "decided_by": row["decided_by"],
        "decided_at": row["decided_at"],
        "decision_reason": row["decision_reason"],
        "result_status": row["result_status"],
        "result_reason": row["result_reason"],
        "result_at": row["result_at"],
    }


class ResponseActionConflictError(RuntimeError):
    def __init__(self, message: str, *, status: str) -> None:
        super().__init__(message)
        self.status = status


class CentralResponseActionStore:
    """Escrituras de decisiones humanas sobre ``response_actions``."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
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

    def decide(
        self,
        *,
        agent_id: str,
        incident_id: str,
        action_id: str,
        approve: bool,
        user_id: int,
        username: str,
        reason: str | None,
        now: str,
    ) -> dict[str, Any] | None:
        """Transición atómica PENDING_APPROVAL -> APPROVED/REJECTED.

        Devuelve None si la acción no existe para ese incidente/agente.
        Lanza ResponseActionConflictError si ya fue decidida o venció.
        """

        if not self.database_path.is_file():
            return None

        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            exists = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' "
                "AND name = 'response_actions'"
            ).fetchone()
            if exists is None:
                return None
            row = connection.execute(
                """
                SELECT * FROM response_actions
                WHERE agent_id = ? AND action_id = ? AND incident_id = ?
                """,
                (agent_id, action_id, incident_id),
            ).fetchone()
            if row is None:
                return None
            if row["status"] != "PENDING_APPROVAL":
                raise ResponseActionConflictError(
                    "La acción ya no está pendiente de aprobación.",
                    status=str(row["status"]),
                )
            expired = str(row["expires_at"]) <= now
            if expired:
                # Se confirma el vencimiento (commit) antes de informar el
                # conflicto, para que el estado quede persistido.
                connection.execute(
                    """
                    UPDATE response_actions
                    SET status = 'EXPIRED', result_reason = ?
                    WHERE agent_id = ? AND action_id = ?
                      AND status = 'PENDING_APPROVAL'
                    """,
                    ("La acción venció antes de ser decidida.", agent_id, action_id),
                )
                updated = None
            else:
                updated = self._apply_decision(
                    connection,
                    agent_id=agent_id,
                    action_id=action_id,
                    approve=approve,
                    user_id=user_id,
                    username=username,
                    reason=reason,
                    now=now,
                )

        if expired:
            raise ResponseActionConflictError(
                "La acción pendiente ya venció.",
                status="EXPIRED",
            )

        return updated

    @staticmethod
    def _apply_decision(
        connection: sqlite3.Connection,
        *,
        agent_id: str,
        action_id: str,
        approve: bool,
        user_id: int,
        username: str,
        reason: str | None,
        now: str,
    ) -> dict[str, Any]:
        cursor = connection.execute(
            """
            UPDATE response_actions
            SET status = ?,
                decided_by_user_id = ?,
                decided_by = ?,
                decided_at = ?,
                decision_reason = ?
            WHERE agent_id = ? AND action_id = ?
              AND status = 'PENDING_APPROVAL'
            """,
            (
                "APPROVED" if approve else "REJECTED",
                user_id,
                username,
                now,
                _short_text(reason),
                agent_id,
                action_id,
            ),
        )
        if cursor.rowcount != 1:
            raise ResponseActionConflictError(
                "La acción ya no está pendiente de aprobación.",
                status="UNKNOWN",
            )
        updated = connection.execute(
            "SELECT * FROM response_actions WHERE agent_id = ? AND action_id = ?",
            (agent_id, action_id),
        ).fetchone()

        return action_record(updated)


class CentralIncidentReader:
    """Consultas de solo lectura sobre ``central.db``."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path

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

    def _available(self, connection: sqlite3.Connection) -> bool:
        row = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'incidents'"
        ).fetchone()
        return row is not None

    @staticmethod
    def _record(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "agent_id": str(row["agent_id"]),
            "incident_id": str(row["incident_id"]),
            "hostname": str(row["hostname"]),
            "incident_type": str(row["incident_type"]),
            "severity": str(row["severity"]),
            "source_ip": row["source_ip"],
            "status": str(row["status"]),
            "opened_at": str(row["opened_at"]),
            "last_activity_at": str(row["last_activity_at"]),
            "closed_at": row["closed_at"],
            "detection_count": int(row["detection_count"]),
            "recurrence_level": row["recurrence_level"],
            "last_action": row["last_action"],
            "last_execution_status": row["last_execution_status"],
            "updated_at": str(row["last_event_at"]),
        }

    def list_incidents(
        self,
        *,
        agent_ids: tuple[str, ...] | None,
        severity: str | None = None,
        status: str | None = None,
        incident_type: str | None = None,
        source_ip: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        if agent_ids == () or not self.database_path.is_file():
            return [], 0

        clauses: list[str] = []
        parameters: list[object] = []

        if agent_ids is not None:
            placeholders = ", ".join("?" for _ in agent_ids)
            clauses.append(f"agent_id IN ({placeholders})")
            parameters.extend(agent_ids)

        for column, value in (
            ("severity", severity),
            ("status", status),
            ("incident_type", incident_type),
            ("source_ip", source_ip),
        ):
            if value is not None:
                clauses.append(f"{column} = ?")
                parameters.append(value)

        if since is not None:
            clauses.append("opened_at >= ?")
            parameters.append(since)

        if until is not None:
            clauses.append("opened_at <= ?")
            parameters.append(until)

        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""

        with self._read_connection() as connection:
            if not self._available(connection):
                return [], 0

            total = int(
                connection.execute(
                    f"SELECT COUNT(*) FROM incidents{where}",
                    parameters,
                ).fetchone()[0]
            )
            rows = connection.execute(
                f"""
                SELECT *
                FROM incidents
                {where}
                ORDER BY opened_at DESC, incident_id DESC
                LIMIT ? OFFSET ?
                """,
                [*parameters, limit, offset],
            ).fetchall()

        return [self._record(row) for row in rows], total

    def find_incidents(
        self,
        *,
        incident_id: str,
        agent_ids: tuple[str, ...] | None,
    ) -> list[dict[str, Any]]:
        if agent_ids == () or not self.database_path.is_file():
            return []

        parameters: list[object] = [incident_id]
        scope = ""

        if agent_ids is not None:
            placeholders = ", ".join("?" for _ in agent_ids)
            scope = f" AND agent_id IN ({placeholders})"
            parameters.extend(agent_ids)

        with self._read_connection() as connection:
            if not self._available(connection):
                return []

            rows = connection.execute(
                f"SELECT * FROM incidents WHERE incident_id = ?{scope}",
                parameters,
            ).fetchall()

        return [self._record(row) for row in rows]

    def timeline(
        self,
        *,
        agent_id: str,
        incident_id: str,
    ) -> list[dict[str, Any]]:
        with self._read_connection() as connection:
            if not self._available(connection):
                return []

            rows = connection.execute(
                f"""
                SELECT
                    l.kind AS kind,
                    l.event_id AS event_id,
                    l.occurred_at AS linked_at,
                    e.occurred_at AS occurred_at,
                    e.event_type AS event_type,
                    e.category AS category,
                    e.severity AS severity,
                    e.source AS source,
                    e.description AS description,
                    e.evidence_json AS evidence_json
                FROM incident_links AS l
                LEFT JOIN events AS e
                  ON e.agent_id = l.agent_id
                 AND e.event_id = l.event_id
                WHERE l.agent_id = ?
                  AND l.incident_id = ?
                ORDER BY l.occurred_at ASC, {_KIND_ORDER_SQL} ASC, l.event_id ASC
                """,
                (agent_id, incident_id),
            ).fetchall()

        entries: list[dict[str, Any]] = []

        for action in self.actions(agent_id=agent_id, incident_id=incident_id):
            if action["decided_at"] is None or action["decided_by"] is None:
                continue
            # Solo decisiones humanas registradas (decided_by): aprobada salvo
            # que el estado sea REJECTED.
            approved = action["status"] != "REJECTED"
            entries.append(
                {
                    "kind": "approval",
                    "event_id": f"{action['action_id']}:decision",
                    "timestamp": str(action["decided_at"]),
                    "available": True,
                    "event_type": (
                        "RESPONSE_APPROVAL_GRANTED"
                        if approved
                        else "RESPONSE_APPROVAL_DENIED"
                    ),
                    "category": "response",
                    "severity": "low",
                    "source": "central",
                    "description": (
                        f"Acción {'aprobada' if approved else 'rechazada'} por "
                        f"{action['decided_by']}."
                    ),
                    "evidence": {
                        "approval_id": action["action_id"],
                        "decided_by": action["decided_by"],
                        "decided_at": action["decided_at"],
                        "reason": action["decision_reason"],
                        "status": action["status"],
                    },
                }
            )

        for row in rows:
            available = row["event_type"] is not None
            entries.append(
                {
                    "kind": str(row["kind"]),
                    "event_id": str(row["event_id"]),
                    "timestamp": str(row["occurred_at"] or row["linked_at"]),
                    "available": available,
                    "event_type": row["event_type"],
                    "category": row["category"],
                    "severity": row["severity"],
                    "source": row["source"],
                    "description": row["description"],
                    "evidence": (
                        json.loads(str(row["evidence_json"])) if available else {}
                    ),
                }
            )

        entries.sort(
            key=lambda entry: (
                entry["timestamp"],
                KIND_ORDER.get(entry["kind"], 9),
                entry["event_id"],
            )
        )
        return entries

    def actions(
        self,
        *,
        agent_id: str,
        incident_id: str,
    ) -> list[dict[str, Any]]:
        with self._read_connection() as connection:
            table = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' "
                "AND name = 'response_actions'"
            ).fetchone()
            if table is None:
                return []
            rows = connection.execute(
                """
                SELECT * FROM response_actions
                WHERE agent_id = ? AND incident_id = ?
                ORDER BY requested_at ASC, action_id ASC
                """,
                (agent_id, incident_id),
            ).fetchall()

        return [action_record(row) for row in rows]

    def instructions_for_agent(
        self,
        *,
        agent_id: str,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        if not self.database_path.is_file():
            return []

        with self._read_connection() as connection:
            table = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' "
                "AND name = 'response_actions'"
            ).fetchone()
            if table is None:
                return []
            rows = connection.execute(
                """
                SELECT * FROM response_actions
                WHERE agent_id = ?
                  AND status IN ('APPROVED', 'REJECTED')
                  AND result_status IS NULL
                ORDER BY decided_at ASC, action_id ASC
                LIMIT ?
                """,
                (agent_id, max(1, min(limit, 50))),
            ).fetchall()

        return [action_record(row) for row in rows]
