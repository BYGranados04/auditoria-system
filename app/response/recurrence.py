"""Reincidencia persistente de orígenes que activan respuestas defensivas.

Definiciones (documentadas también en docs/motor-defensivo-incidentes.md):

- Ofensa: una detección candidata a bloqueo (SSH_*) cuya decisión no fue
  NO_ACTION, proveniente de una IP no protegida. Se persiste en la tabla
  ``response_offenses`` de ``auditoria.db``.
- Reincidencia: cada ofensa previa del mismo origen, en el mismo servidor,
  dentro de la ventana deslizante ``escalation_window_seconds``.
- Nivel: ``1 + ofensas previas en la ventana``, acotado por la cantidad de
  niveles configurados (nunca infinito).
- Regreso al nivel inicial: cuando no existe ninguna ofensa del origen dentro
  de la ventana.
- Reinicio del agente: el nivel se recalcula desde SQLite; no depende de RAM.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from app.response.policy import ResponsePolicy
from app.storage.event_repository import EventRepository

Clock = Callable[[], datetime]


@dataclass(frozen=True)
class RecurrenceAssessment:
    source_ip: str
    recurrence_level: int
    previous_incidents: int
    maximum_level: int
    window_seconds: int
    escalation_enabled: bool
    selected_duration_seconds: int

    @property
    def capped(self) -> bool:
        return self.recurrence_level >= self.maximum_level


class RecurrenceTracker:
    def __init__(
        self,
        repository: EventRepository,
        policy: ResponsePolicy,
        *,
        clock: Clock | None = None,
    ) -> None:
        self.repository = repository
        self.policy = policy
        self.clock = clock or (lambda: datetime.now(UTC))

    def assess(
        self,
        *,
        hostname: str,
        source_ip: str,
        detection_event_id: str,
        now: datetime | None = None,
    ) -> RecurrenceAssessment:
        current = (now or self.clock()).astimezone(UTC)
        window = self.policy.escalation_window_seconds

        previous = self.repository.count_response_offenses(
            hostname=hostname,
            source_ip=source_ip,
            since=current - timedelta(seconds=window),
            until=current,
            exclude_detection_event_id=detection_event_id,
        )

        maximum = self.policy.maximum_recurrence_level
        level = min(previous + 1, maximum)

        if self.policy.escalation_enabled:
            duration = self.policy.duration_for_level(level)
        else:
            duration = self.policy.temporary_block_seconds

        return RecurrenceAssessment(
            source_ip=source_ip,
            recurrence_level=level,
            previous_incidents=previous,
            maximum_level=maximum,
            window_seconds=window,
            escalation_enabled=self.policy.escalation_enabled,
            selected_duration_seconds=duration,
        )

    def record(
        self,
        *,
        hostname: str,
        source_ip: str,
        detection_event_id: str,
        detection_type: str,
        incident_id: str | None,
        occurred_at: datetime,
        assessment: RecurrenceAssessment,
    ) -> bool:
        return self.repository.record_response_offense(
            offense_id=str(uuid4()),
            hostname=hostname,
            source_ip=source_ip,
            detection_event_id=detection_event_id,
            detection_type=detection_type,
            incident_id=incident_id,
            occurred_at=occurred_at,
            recurrence_level=assessment.recurrence_level,
            selected_duration_seconds=assessment.selected_duration_seconds,
        )
