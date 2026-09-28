from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.auth.web import AuthManager
from app.central.config import CentralSettings
from app.central.repository import (
    CentralEventConflictError,
    CentralEventRepository,
)
from app.core.events import SecurityEvent, Severity

agent_bearer_scheme = HTTPBearer(auto_error=False)


class AgentEventPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: UUID
    timestamp: datetime
    hostname: str = Field(min_length=1, max_length=255)
    source: str = Field(min_length=1, max_length=128)
    category: str = Field(min_length=1, max_length=128)
    event_type: str = Field(min_length=1, max_length=128)
    severity: Severity
    description: str = Field(min_length=1, max_length=4096)
    evidence: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp debe incluir zona horaria.")
        return value

    def to_security_event(self, *, agent_id: str) -> SecurityEvent:
        return SecurityEvent(
            agent_id=agent_id,
            **self.model_dump(),
        )


class AgentEventBatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[AgentEventPayload] = Field(min_length=1)


class AgentEventBatchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    accepted: int
    inserted: int
    duplicates: int


def build_agent_event_router(
    manager: AuthManager,
    repository: CentralEventRepository,
    settings: CentralSettings,
) -> APIRouter:
    router = APIRouter()

    def authenticate_agent(
        credentials: HTTPAuthorizationCredentials | None = Depends(  # noqa: B008
            agent_bearer_scheme
        ),
    ) -> dict[str, object]:
        if (
            credentials is None
            or credentials.scheme.casefold() != "bearer"
            or not credentials.credentials
            or credentials.credentials != credentials.credentials.strip()
            or len(credentials.credentials) > 512
        ):
            raise HTTPException(status_code=401, detail="Credencial no válida.")
        agent = manager.repository.authenticate_agent_credential(
            credentials.credentials
        )
        if agent is None:
            raise HTTPException(status_code=401, detail="Credencial no válida.")
        return agent

    @router.post(
        "/agent/events/batch",
        response_model=AgentEventBatchResponse,
        tags=["agent-connectivity"],
    )
    def ingest_agent_events(
        data: AgentEventBatchRequest,
        agent: dict[str, object] = Depends(authenticate_agent),  # noqa: B008
    ) -> AgentEventBatchResponse:
        if len(data.events) > settings.agent_event_batch_max:
            raise HTTPException(
                status_code=422,
                detail=(
                    "El batch supera el máximo de "
                    f"{settings.agent_event_batch_max} eventos."
                ),
            )

        now = manager.clock()
        maximum_timestamp = now + timedelta(
            seconds=settings.event_max_future_seconds
        )
        agent_id = str(agent["agent_id"])
        events: list[SecurityEvent] = []
        for index, item in enumerate(data.events):
            if item.timestamp > maximum_timestamp:
                raise HTTPException(
                    status_code=422,
                    detail=f"events[{index}].timestamp está demasiado en el futuro.",
                )
            try:
                evidence_size = len(
                    json.dumps(
                        item.evidence,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    ).encode("utf-8")
                )
            except (TypeError, ValueError) as exc:
                raise HTTPException(
                    status_code=422,
                    detail=f"events[{index}].evidence no es JSON válido.",
                ) from exc
            if evidence_size > settings.event_evidence_max_bytes:
                raise HTTPException(
                    status_code=422,
                    detail=(
                        f"events[{index}].evidence supera el límite de "
                        f"{settings.event_evidence_max_bytes} bytes."
                    ),
                )
            events.append(item.to_security_event(agent_id=agent_id))

        try:
            result = repository.add_events(
                agent_id=agent_id,
                events=tuple(events),
            )
        except CentralEventConflictError as exc:
            raise HTTPException(
                status_code=409,
                detail="El batch contiene un event_id con payload conflictivo.",
            ) from exc
        except sqlite3.Error as exc:
            raise HTTPException(
                status_code=503,
                detail="Almacenamiento central no disponible.",
            ) from exc

        return AgentEventBatchResponse(
            accepted=result.accepted,
            inserted=result.inserted,
            duplicates=result.duplicates,
        )

    return router
