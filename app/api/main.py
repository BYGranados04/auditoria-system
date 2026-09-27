from __future__ import annotations

import platform
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict

from app.agents.web import build_agent_router
from app.auth.config import AuthSettings, load_auth_settings
from app.auth.repository import AuthenticatedSession, AuthRepository
from app.auth.web import AuthManager, build_auth_router
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

ResponseEventType = Literal[
    "RESPONSE_DECISION",
    "RESPONSE_EXECUTION",
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
    hostname: str

    response_mode: str
    automatic_blocking_enabled: bool

    total_events: int
    live_response_blocks: int
    by_severity: dict[str, int]


class EventResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

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
    clock: Callable[[], datetime] | None = None,
) -> FastAPI:
    resolved_settings = settings or load_agent_settings()

    resolved_repository = repository or EventRepository(
        resolved_settings.database_file,
        read_only=True,
    )
    resolved_auth_settings = auth_settings or load_auth_settings()
    resolved_auth_repository = auth_repository or AuthRepository(
        resolved_auth_settings.database_file
    )
    auth_manager = AuthManager(
        resolved_auth_repository,
        resolved_auth_settings,
        clock=clock,
    )

    application = FastAPI(
        title="Auditoria System API",
        description=("API local de consulta para Auditoria System."),
        version="0.7.0",
    )
    application.include_router(build_auth_router(auth_manager))
    application.include_router(build_agent_router(auth_manager))
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
        session: AuthenticatedSession = Depends(  # noqa: B008
            auth_manager.require_authenticated
        ),
    ) -> StatusResponse:
        if not resolved_settings.database_file.is_file():
            raise HTTPException(
                status_code=503,
                detail="Base de datos no disponible.",
            )

        try:
            allowed_hostnames = auth_manager.get_allowed_hostnames(session)
            statistics = resolved_repository.statistics(hostnames=allowed_hostnames)

            live_blocks = resolved_repository.list_live_response_blocks(
                now=datetime.now(UTC),
                hostnames=allowed_hostnames,
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

        if allowed_hostnames is None:
            status_hostname = platform.node()
        elif len(allowed_hostnames) == 1:
            status_hostname = allowed_hostnames[0]
        elif allowed_hostnames:
            status_hostname = f"{len(allowed_hostnames)} servidores"
        else:
            status_hostname = "Sin servidores asignados"

        return StatusResponse(
            status="ok",
            service="auditoria-system-api",
            hostname=status_hostname,
            response_mode=(resolved_settings.response_mode),
            automatic_blocking_enabled=(automatic_blocking_enabled),
            total_events=statistics["total"],
            live_response_blocks=len(live_blocks),
            by_severity=statistics["by_severity"],
        )

    @application.get(
        "/events",
        response_model=list[EventResponse],
        tags=["events"],
    )
    def list_events(
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

        if not resolved_settings.database_file.is_file():
            raise HTTPException(
                status_code=503,
                detail="Base de datos no disponible.",
            )

        try:
            allowed_hostnames = auth_manager.resolve_hostname_scope(
                session,
                hostname,
            )
            rows = resolved_repository.list_events(
                severity=severity,
                event_type=event_type,
                hostname=hostname,
                hostnames=allowed_hostnames,
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
                event_id=row["event_id"],
                timestamp=row["timestamp"],
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

        if not resolved_settings.database_file.is_file():
            raise HTTPException(
                status_code=503,
                detail="Base de datos no disponible.",
            )

        try:
            allowed_hostnames = auth_manager.resolve_hostname_scope(
                session,
                hostname,
            )
            rows = resolved_repository.list_events(
                severity=severity,
                event_type=event_type,
                hostname=hostname,
                hostnames=allowed_hostnames,
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
                event_id=row["event_id"],
                timestamp=row["timestamp"],
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
        event_type: ResponseEventType | None = None,
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

        if not resolved_settings.database_file.is_file():
            raise HTTPException(
                status_code=503,
                detail="Base de datos no disponible.",
            )

        try:
            allowed_hostnames = auth_manager.resolve_hostname_scope(
                session,
                hostname,
            )
            if event_type is None:
                rows = resolved_repository.list_events(
                    event_types=(
                        "RESPONSE_DECISION",
                        "RESPONSE_EXECUTION",
                    ),
                    hostname=hostname,
                    hostnames=allowed_hostnames,
                    category="response",
                    since=since,
                    until=until,
                    limit=limit,
                )
            else:
                rows = resolved_repository.list_events(
                    event_type=event_type,
                    hostname=hostname,
                    hostnames=allowed_hostnames,
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
                event_id=row["event_id"],
                timestamp=row["timestamp"],
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
