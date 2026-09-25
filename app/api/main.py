from __future__ import annotations

import platform
import sqlite3
from datetime import UTC, datetime

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict

from app.core.config import AgentSettings, load_agent_settings
from app.storage.event_repository import EventRepository


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    service: str


class StatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    service: str
    hostname: str

    response_mode: str
    automatic_blocking_enabled: bool

    total_events: int
    live_response_blocks: int
    by_severity: dict[str, int]


def create_app(
    *,
    settings: AgentSettings | None = None,
    repository: EventRepository | None = None,
) -> FastAPI:
    resolved_settings = settings or load_agent_settings()

    resolved_repository = repository or EventRepository(resolved_settings.database_file)

    application = FastAPI(
        title="Auditoria System API",
        description=("API local de consulta para Auditoria System."),
        version="0.6.0-dev",
    )

    @application.get(
        "/health",
        response_model=HealthResponse,
        tags=["system"],
    )
    def health() -> HealthResponse:
        return HealthResponse(
            status="ok",
            service="auditoria-system-api",
        )

    @application.get(
        "/status",
        response_model=StatusResponse,
        tags=["system"],
    )
    def system_status() -> StatusResponse:
        if not resolved_settings.database_file.is_file():
            raise HTTPException(
                status_code=503,
                detail="Base de datos no disponible.",
            )

        try:
            statistics = resolved_repository.statistics()

            live_blocks = resolved_repository.list_live_response_blocks(
                now=datetime.now(UTC)
            )
        except sqlite3.Error as exc:
            raise HTTPException(
                status_code=503,
                detail="Base de datos no disponible.",
            ) from exc

        automatic_blocking_enabled = (
            resolved_settings.response_mode == "automatic"
            and resolved_settings.allow_temporary_ip_block
        )

        return StatusResponse(
            status="ok",
            service="auditoria-system-api",
            hostname=platform.node(),
            response_mode=(resolved_settings.response_mode),
            automatic_blocking_enabled=(automatic_blocking_enabled),
            total_events=statistics["total"],
            live_response_blocks=len(live_blocks),
            by_severity=statistics["by_severity"],
        )

    return application


app = create_app()
