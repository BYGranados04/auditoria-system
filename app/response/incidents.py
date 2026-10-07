"""Incidentes del agente: agrupan eventos, detecciones, evidencia y respuestas.

Un incidente se identifica por (hostname, IP de origen) mientras exista
actividad dentro de ``grouping_seconds``. Los datos completos de cada evento
no se duplican: el incidente solo guarda referencias (``links``) a eventos que
ya existen en ``auditoria.db`` y que el outbox sincroniza al central.

Taxonomía de estados:

- OPEN: requiere atención (aprobación pendiente en ``assisted``, ejecución
  fallida o acción no autorizada en ``automatic``).
- OBSERVED: registrado sin contención (``audit_only``, dry-run o IP protegida).
- CONTAINED: la contención (bloqueo temporal) fue aplicada.
- CLOSED: sin actividad durante la ventana de agrupación.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from secrets import token_hex
from typing import Any

from app.core.events import SecurityEvent
from app.response.models import (
    EXECUTABLE_ACTIONS,
    ResponseDecision,
    ResponseExecutionResult,
)
from app.storage.event_repository import EventRepository

INCIDENT_ID_PATTERN = re.compile(r"^INC-[0-9A-F]{16}$")
INCIDENT_STATUSES = ("OPEN", "OBSERVED", "CONTAINED", "CLOSED")
LINK_KINDS = ("event", "detection", "evidence", "decision", "approval", "execution")
SEVERITY_ORDER = ("low", "medium", "high", "critical")
MAXIMUM_TRIGGER_LINKS = 50

# Detección -> tipo de evento de autenticación que la origina.
INCIDENT_DETECTIONS: dict[str, str] = {
    "SSH_USER_ENUMERATION_ATTEMPT": "SSH_INVALID_USER",
    "SSH_BRUTE_FORCE_ATTEMPT": "SSH_AUTH_FAILURE",
    "SSH_REPEATED_PREAUTH_ACTIVITY": "SSH_PREAUTH_CONNECTION_CLOSED",
}

Clock = Callable[[], datetime]


def new_incident_id() -> str:
    return f"INC-{token_hex(8).upper()}"


def is_valid_incident_id(value: object) -> bool:
    return isinstance(value, str) and INCIDENT_ID_PATTERN.fullmatch(value) is not None


def max_severity(first: str, second: str) -> str:
    def rank(value: str) -> int:
        return SEVERITY_ORDER.index(value) if value in SEVERITY_ORDER else 0

    return first if rank(first) >= rank(second) else second


@dataclass
class IncidentChange:
    incident: dict[str, Any]
    opened: bool
    links: list[dict[str, str]] = field(default_factory=list)


def link(event: SecurityEvent, kind: str) -> dict[str, str]:
    if kind not in LINK_KINDS:
        raise ValueError("Tipo de vínculo de incidente no soportado.")

    return {
        "event_id": str(event.event_id),
        "kind": kind,
        "occurred_at": event.timestamp.astimezone(UTC).isoformat(),
    }


class IncidentManager:
    def __init__(
        self,
        repository: EventRepository,
        *,
        grouping_seconds: int = 3600,
        clock: Clock | None = None,
    ) -> None:
        self.repository = repository
        self.grouping_seconds = grouping_seconds
        self.clock = clock or (lambda: datetime.now(UTC))

    @staticmethod
    def source_ip(event: SecurityEvent) -> str | None:
        value = event.evidence.get("source_ip")

        if not isinstance(value, str):
            return None

        try:
            return str(ip_address(value))
        except ValueError:
            return None

    def is_candidate(self, event: SecurityEvent) -> bool:
        return (
            event.category == "detection"
            and event.event_type in INCIDENT_DETECTIONS
            and self.source_ip(event) is not None
        )

    def close_stale(self, *, now: datetime | None = None) -> list[dict[str, Any]]:
        current = (now or self.clock()).astimezone(UTC)
        cutoff = current - timedelta(seconds=self.grouping_seconds)
        closed: list[dict[str, Any]] = []

        for incident in self.repository.list_stale_incidents(inactive_before=cutoff):
            closed.append(
                self.repository.update_incident(
                    str(incident["incident_id"]),
                    updated_at=current,
                    status="CLOSED",
                    closed_at=current,
                )
            )

        return closed

    def open_or_update(self, detection: SecurityEvent) -> IncidentChange:
        source_ip = self.source_ip(detection)

        if not self.is_candidate(detection) or source_ip is None:
            raise ValueError("La detección no admite incidente.")

        occurred_at = detection.timestamp.astimezone(UTC)
        existing = self.repository.find_active_incident(
            hostname=detection.hostname,
            source_ip=source_ip,
            active_since=occurred_at - timedelta(seconds=self.grouping_seconds),
        )

        opened = existing is None

        if existing is None:
            existing = self.repository.create_incident(
                incident_id=new_incident_id(),
                hostname=detection.hostname,
                incident_type=detection.event_type,
                severity=detection.severity,
                source_ip=source_ip,
                status="OPEN",
                opened_at=occurred_at,
            )

        last_activity = max(
            occurred_at,
            datetime.fromisoformat(str(existing["last_activity_at"])),
        )

        incident = self.repository.update_incident(
            str(existing["incident_id"]),
            updated_at=self.clock().astimezone(UTC),
            severity=max_severity(str(existing["severity"]), detection.severity),
            last_activity_at=last_activity,
            increment_detections=1,
        )

        links = [
            *self.trigger_links(detection, source_ip),
            link(detection, "detection"),
        ]

        return IncidentChange(incident=incident, opened=opened, links=links)

    def trigger_links(
        self,
        detection: SecurityEvent,
        source_ip: str,
    ) -> list[dict[str, str]]:
        """Eventos de autenticación que originaron la detección.

        Se reconstruyen desde la base local usando la ventana que la propia
        detección declara (first_seen/last_seen); no se modifica el detector.
        """

        event_type = INCIDENT_DETECTIONS.get(detection.event_type)

        if event_type is None:
            return []

        since = _parse_timestamp(detection.evidence.get("first_seen"))
        until = _parse_timestamp(detection.evidence.get("last_seen")) or (
            detection.timestamp
        )

        if since is None:
            window = detection.evidence.get("window_seconds")
            seconds = window if isinstance(window, int) and window > 0 else 60
            since = until - timedelta(seconds=seconds)

        rows = self.repository.list_events(
            category="authentication",
            event_type=event_type,
            hostname=detection.hostname,
            since=since,
            until=until,
            limit=1000,
        )

        matching = [
            row
            for row in rows
            if isinstance(row.get("evidence"), dict)
            and row["evidence"].get("ip") == source_ip
        ][:MAXIMUM_TRIGGER_LINKS]

        return [
            {
                "event_id": str(row["event_id"]),
                "kind": "event",
                "occurred_at": _iso(str(row["timestamp"])),
            }
            for row in reversed(matching)
        ]

    def set_status(
        self,
        incident_id: str,
        *,
        status: str,
        last_execution_status: str | None = None,
    ) -> dict[str, Any]:
        if status not in INCIDENT_STATUSES:
            raise ValueError("Estado de incidente no válido.")

        return self.repository.update_incident(
            incident_id,
            updated_at=self.clock().astimezone(UTC),
            status=status,
            last_execution_status=last_execution_status,
        )

    def apply_response(
        self,
        incident_id: str,
        *,
        decision: ResponseDecision,
        result: ResponseExecutionResult | None,
    ) -> dict[str, Any]:
        status = self.status_for(decision, result)
        current = self.repository.get_incident(incident_id)

        if (
            current is not None
            and current["status"] == "CONTAINED"
            and decision.action in EXECUTABLE_ACTIONS
            and result is not None
            and result.status == "SKIPPED"
        ):
            # Ya contenido (por ejemplo, bloqueo vigente equivalente): una
            # detección adicional del mismo ataque no degrada el estado.
            status = "CONTAINED"

        return self.repository.update_incident(
            incident_id,
            updated_at=self.clock().astimezone(UTC),
            status=status,
            recurrence_level=decision.recurrence_level,
            last_action=decision.action,
            last_execution_status=result.status if result is not None else None,
        )

    @staticmethod
    def status_for(
        decision: ResponseDecision,
        result: ResponseExecutionResult | None,
    ) -> str:
        if result is not None and result.status == "EXECUTED":
            return "CONTAINED"

        if decision.action == "NO_ACTION":
            return "OBSERVED"

        if decision.approval_required and not decision.execution_allowed:
            # assisted: pendiente de aprobación humana.
            return "OPEN"

        if result is not None and result.status == "FAILED":
            return "OPEN"

        if decision.action in EXECUTABLE_ACTIONS:
            # SKIPPED (dirección protegida, bloqueo vigente) o DRY_RUN: no
            # hubo una contención nueva.
            return "OBSERVED"

        if decision.mode == "automatic":
            # Recomendación en automatic: la acción no está autorizada.
            return "OPEN"

        return "OBSERVED"

    @staticmethod
    def event_evidence(
        incident: dict[str, Any],
        *,
        links: list[dict[str, str]],
    ) -> dict[str, Any]:
        return {
            "incident_id": incident["incident_id"],
            "incident_type": incident["incident_type"],
            "severity": incident["severity"],
            "source_ip": incident["source_ip"],
            "status": incident["status"],
            "opened_at": incident["opened_at"],
            "last_activity_at": incident["last_activity_at"],
            "closed_at": incident["closed_at"],
            "detection_count": incident["detection_count"],
            "recurrence_level": incident["recurrence_level"],
            "last_action": incident["last_action"],
            "last_execution_status": incident["last_execution_status"],
            "links": links,
        }


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None

    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        return None

    return parsed.astimezone(UTC)


def _iso(value: str) -> str:
    parsed = _parse_timestamp(value)
    return parsed.isoformat() if parsed is not None else value
