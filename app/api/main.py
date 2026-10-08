from __future__ import annotations

import sqlite3
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict

from app.agents.events import build_agent_event_router
from app.agents.web import build_agent_router
from app.api.incidents import build_incident_router
from app.auth.config import AuthSettings, load_auth_settings
from app.auth.repository import AuthenticatedSession, AuthRepository
from app.auth.web import AuthManager, build_auth_router
from app.central.config import CentralSettings, load_central_settings
from app.central.incidents import CentralIncidentReader, CentralResponseActionStore
from app.central.repository import CentralEventRepository
from app.core.config import AgentSettings, load_agent_settings
from app.notifications.repository import NotificationRepository
from app.notifications.web import build_notification_router
from app.storage.event_repository import EventRepository

Severity = Literal[
    "low",
    "medium",
    "high",
    "critical",
]

DASHBOARD_DIRECTORY = Path(__file__).with_name("dashboard")


def _html_security_headers() -> dict[str, str]:
    return {
        "Cache-Control": "no-store",
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'none'; "
            "frame-ancestors 'none'; "
            "form-action 'self'"
        ),
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
    }


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    service: str


class StatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    service: str
    agent_id: str | None
    hostname: str
    presence: Literal["unknown", "online", "offline"] | None
    last_seen_at: datetime | None

    response_mode: str | None
    automatic_blocking_enabled: bool | None

    total_events: int
    live_response_blocks: int | None
    by_severity: dict[str, int]


class EventResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str
    event_id: str
    timestamp: datetime
    hostname: str
    source: str
    category: str
    event_type: str
    severity: Severity
    description: str
    evidence: dict[str, Any]


def _require_timezone(
    value: datetime | None,
    *,
    field_name: str,
) -> None:
    if value is None:
        return

    if value.tzinfo is None or value.utcoffset() is None:
        raise HTTPException(
            status_code=422,
            detail=(f"{field_name} debe incluir zona horaria."),
        )


def create_app(
    *,
    settings: AgentSettings | None = None,
    repository: EventRepository | None = None,
    auth_settings: AuthSettings | None = None,
    auth_repository: AuthRepository | None = None,
    central_settings: CentralSettings | None = None,
    central_repository: CentralEventRepository | None = None,
    clock: Callable[[], datetime] | None = None,
) -> FastAPI:
    resolved_settings = settings or load_agent_settings()

    resolved_auth_settings = auth_settings or load_auth_settings()
    resolved_auth_repository = auth_repository or AuthRepository(
        resolved_auth_settings.database_file
    )
    auth_manager = AuthManager(
        resolved_auth_repository,
        resolved_auth_settings,
        clock=clock,
    )
    resolved_central_settings = central_settings or load_central_settings()
    resolved_central_repository = central_repository or CentralEventRepository(
        resolved_central_settings.database_file,
        clock=auth_manager.clock,
    )

    application = FastAPI(
        title="Nexora API",
        description=(
            "API local de consulta de Nexora. "
            "Monitoreo y seguridad de tu infraestructura."
        ),
        version="1.0.0",
    )
    application.include_router(build_auth_router(auth_manager))
    application.include_router(build_agent_router(auth_manager))
    application.include_router(
        build_agent_event_router(
            auth_manager,
            resolved_central_repository,
            resolved_central_settings,
        )
    )
    application.include_router(
        build_incident_router(
            auth_manager,
            CentralIncidentReader(resolved_central_settings.database_file),
            CentralResponseActionStore(resolved_central_settings.database_file),
        )
    )
    application.include_router(
        build_notification_router(
            auth_manager,
            NotificationRepository(
                resolved_settings.state_dir / "notifications.db",
                read_only=True,
            ),
        )
    )

    @application.get(
        "/login",
        include_in_schema=False,
        response_class=FileResponse,
    )
    def login_page(request: Request) -> Response:
        if auth_manager.session_from_request(request) is not None:
            return RedirectResponse("/dashboard", status_code=303)
        return FileResponse(
            DASHBOARD_DIRECTORY / "login.html",
            media_type="text/html",
            headers=_html_security_headers(),
        )

    @application.get(
        "/dashboard/notifications",
        include_in_schema=False,
        response_class=FileResponse,
    )
    @application.get(
        "/dashboard/users",
        include_in_schema=False,
        response_class=FileResponse,
    )
    @application.get(
        "/dashboard/servers",
        include_in_schema=False,
        response_class=FileResponse,
    )
    @application.get(
        "/dashboard/incidents",
        include_in_schema=False,
        response_class=FileResponse,
    )
    @application.get(
        "/dashboard/responses",
        include_in_schema=False,
        response_class=FileResponse,
    )
    @application.get(
        "/dashboard/detections",
        include_in_schema=False,
        response_class=FileResponse,
    )
    @application.get(
        "/dashboard/events",
        include_in_schema=False,
        response_class=FileResponse,
    )
    @application.get(
        "/dashboard",
        include_in_schema=False,
        response_class=FileResponse,
    )
    def dashboard(request: Request) -> Response:
        session = auth_manager.session_from_request(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if request.url.path == "/dashboard/users" and session.role != "superadmin":
            raise HTTPException(status_code=403, detail="Permisos insuficientes.")
        return FileResponse(
            DASHBOARD_DIRECTORY / "index.html",
            media_type="text/html",
            headers=_html_security_headers(),
        )

    @application.get(
        "/dashboard/assets/styles.css",
        include_in_schema=False,
        response_class=FileResponse,
    )
    def dashboard_styles() -> FileResponse:
        return FileResponse(
            DASHBOARD_DIRECTORY / "styles.css",
            media_type="text/css",
        )

    @application.get(
        "/dashboard/assets/dashboard.js",
        include_in_schema=False,
        response_class=FileResponse,
    )
    def dashboard_script() -> FileResponse:
        return FileResponse(
            DASHBOARD_DIRECTORY / "dashboard.js",
            media_type="text/javascript",
        )

    @application.get(
        "/dashboard/assets/login.js",
        include_in_schema=False,
        response_class=FileResponse,
    )
    def login_script() -> FileResponse:
        return FileResponse(
            DASHBOARD_DIRECTORY / "login.js",
            media_type="text/javascript",
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
    def system_status(
        agent_id: str | None = None,
        session: AuthenticatedSession = Depends(  # noqa: B008
            auth_manager.require_authenticated
        ),
    ) -> StatusResponse:
        try:
            allowed_agent_ids = auth_manager.resolve_agent_scope(session, agent_id)
            statistics = resolved_central_repository.statistics(
                agent_ids=allowed_agent_ids
            )
            owner_user_id = None if session.role == "superadmin" else session.user_id
            agents = resolved_auth_repository.list_agents(
                owner_user_id=owner_user_id,
                now=auth_manager.clock(),
                offline_after_seconds=(
                    resolved_auth_settings.agent_offline_after_seconds
                ),
            )
            if agent_id is not None:
                agents = [item for item in agents if item["agent_id"] == agent_id]
        except sqlite3.Error as exc:
            raise HTTPException(
                status_code=503,
                detail="Base de datos no disponible.",
            ) from exc

        selected = agents[0] if len(agents) == 1 else None
        if selected is not None:
            status_hostname = str(selected["hostname"])
        elif agents:
            status_hostname = f"{len(agents)} servidores"
        else:
            status_hostname = "Sin servidores asignados"

        return StatusResponse(
            status="ok",
            service="auditoria-system-api",
            agent_id=str(selected["agent_id"]) if selected is not None else None,
            hostname=status_hostname,
            presence=(str(selected["presence"]) if selected is not None else None),
            last_seen_at=(selected["last_seen_at"] if selected is not None else None),
            # Modo efectivo confirmado por el agente seleccionado. None si no
            # hay un único servidor o si el agente (v1.0) nunca lo reportó.
            response_mode=(
                str(selected["effective_response_mode"])
                if selected is not None
                and selected["effective_response_mode"] is not None
                else None
            ),
            automatic_blocking_enabled=None,
            total_events=statistics["total"],
            live_response_blocks=None,
            by_severity=statistics["by_severity"],
        )

    @application.get(
        "/events",
        response_model=list[EventResponse],
        tags=["events"],
    )
    def list_events(
        agent_id: str | None = None,
        severity: Severity | None = None,
        event_type: str | None = None,
        hostname: str | None = None,
        category: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = Query(
            default=100,
            ge=1,
            le=1000,
        ),
        session: AuthenticatedSession = Depends(  # noqa: B008
            auth_manager.require_authenticated
        ),
    ) -> list[EventResponse]:
        _require_timezone(
            since,
            field_name="since",
        )
        _require_timezone(
            until,
            field_name="until",
        )

        if since is not None and until is not None and since > until:
            raise HTTPException(
                status_code=422,
                detail=("since no puede ser posterior a until."),
            )

        try:
            allowed_agent_ids = auth_manager.resolve_agent_scope(session, agent_id)
            rows = resolved_central_repository.list_events(
                agent_ids=allowed_agent_ids,
                agent_id=agent_id,
                severity=severity,
                event_type=event_type,
                hostname=hostname,
                category=category,
                since=since,
                until=until,
                limit=limit,
            )
        except sqlite3.Error as exc:
            raise HTTPException(
                status_code=503,
                detail="Base de datos no disponible.",
            ) from exc

        return [
            EventResponse(
                agent_id=row["agent_id"],
                event_id=row["event_id"],
                timestamp=row["occurred_at"],
                hostname=row["hostname"],
                source=row["source"],
                category=row["category"],
                event_type=row["event_type"],
                severity=row["severity"],
                description=row["description"],
                evidence=row["evidence"],
            )
            for row in rows
        ]

    @application.get(
        "/detections",
        response_model=list[EventResponse],
        tags=["detections"],
    )
    def list_detections(
        agent_id: str | None = None,
        severity: Severity | None = None,
        event_type: str | None = None,
        hostname: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = Query(
            default=100,
            ge=1,
            le=1000,
        ),
        session: AuthenticatedSession = Depends(  # noqa: B008
            auth_manager.require_authenticated
        ),
    ) -> list[EventResponse]:
        _require_timezone(
            since,
            field_name="since",
        )
        _require_timezone(
            until,
            field_name="until",
        )

        if since is not None and until is not None and since > until:
            raise HTTPException(
                status_code=422,
                detail=("since no puede ser posterior a until."),
            )

        try:
            allowed_agent_ids = auth_manager.resolve_agent_scope(session, agent_id)
            rows = resolved_central_repository.list_events(
                agent_ids=allowed_agent_ids,
                agent_id=agent_id,
                severity=severity,
                event_type=event_type,
                hostname=hostname,
                category="detection",
                since=since,
                until=until,
                limit=limit,
            )
        except sqlite3.Error as exc:
            raise HTTPException(
                status_code=503,
                detail="Base de datos no disponible.",
            ) from exc

        return [
            EventResponse(
                agent_id=row["agent_id"],
                event_id=row["event_id"],
                timestamp=row["occurred_at"],
                hostname=row["hostname"],
                source=row["source"],
                category=row["category"],
                event_type=row["event_type"],
                severity=row["severity"],
                description=row["description"],
                evidence=row["evidence"],
            )
            for row in rows
        ]

    @application.get(
        "/responses",
        response_model=list[EventResponse],
        tags=["responses"],
    )
    def list_responses(
        agent_id: str | None = None,
        event_type: str | None = Query(
            default=None,
            min_length=1,
            max_length=128,
            pattern=r"^[A-Z0-9_]+$",
        ),
        hostname: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = Query(
            default=100,
            ge=1,
            le=1000,
        ),
        session: AuthenticatedSession = Depends(  # noqa: B008
            auth_manager.require_authenticated
        ),
    ) -> list[EventResponse]:
        _require_timezone(
            since,
            field_name="since",
        )
        _require_timezone(
            until,
            field_name="until",
        )

        if since is not None and until is not None and since > until:
            raise HTTPException(
                status_code=422,
                detail=("since no puede ser posterior a until."),
            )

        try:
            allowed_agent_ids = auth_manager.resolve_agent_scope(session, agent_id)
            rows = resolved_central_repository.list_events(
                agent_ids=allowed_agent_ids,
                agent_id=agent_id,
                event_type=event_type,
                hostname=hostname,
                category="response",
                since=since,
                until=until,
                limit=limit,
            )
        except sqlite3.Error as exc:
            raise HTTPException(
                status_code=503,
                detail="Base de datos no disponible.",
            ) from exc

        return [
            EventResponse(
                agent_id=row["agent_id"],
                event_id=row["event_id"],
                timestamp=row["occurred_at"],
                hostname=row["hostname"],
                source=row["source"],
                category=row["category"],
                event_type=row["event_type"],
                severity=row["severity"],
                description=row["description"],
                evidence=row["evidence"],
            )
            for row in rows
        ]

    return application


app = create_app()
