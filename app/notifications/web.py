from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict

from app.auth.repository import AuthenticatedSession
from app.auth.web import AuthManager
from app.notifications.models import NotificationAttempt
from app.notifications.repository import NotificationRepository


class NotificationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: int
    event_id: str
    agent_id: str | None
    channel: str
    provider: str
    recipient: str
    hostname: str
    severity: Literal["low", "medium", "high", "critical"]
    status: Literal["pending", "sent", "failed"]
    created_at: datetime
    sent_at: datetime | None
    error: str | None
    provider_message_id: str | None


class NotificationSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    total: int
    pending: int
    sent: int
    failed: int
    high: int
    critical: int


def _response(item: NotificationAttempt) -> NotificationResponse:
    return NotificationResponse.model_validate(item.__dict__)


def build_notification_router(
    manager: AuthManager,
    repository: NotificationRepository,
) -> APIRouter:
    router = APIRouter(tags=["notifications"])

    def scope(session: AuthenticatedSession) -> tuple[str, ...] | None:
        return manager.get_allowed_agent_ids(session)

    @router.get("/notifications", response_model=list[NotificationResponse])
    def list_notifications(
        status: Literal["pending", "sent", "failed"] | None = None,
        severity: Literal["low", "medium", "high", "critical"] | None = None,
        hostname: str | None = None,
        limit: int = Query(default=100, ge=1, le=1000),
        session: AuthenticatedSession = Depends(  # noqa: B008
            manager.require_authenticated
        ),
    ) -> list[NotificationResponse]:
        allowed = scope(session)
        return [
            _response(item)
            for item in repository.list(
                agent_ids=allowed,
                hostnames=(hostname,) if hostname is not None else None,
                status=status,
                severity=severity,
                limit=limit,
            )
        ]

    @router.get("/notifications/summary", response_model=NotificationSummary)
    def notification_summary(
        session: AuthenticatedSession = Depends(  # noqa: B008
            manager.require_authenticated
        ),
    ) -> NotificationSummary:
        return NotificationSummary(**repository.summary(agent_ids=scope(session)))

    @router.get("/notifications/{notification_id}", response_model=NotificationResponse)
    def get_notification(
        notification_id: int,
        session: AuthenticatedSession = Depends(  # noqa: B008
            manager.require_authenticated
        ),
    ) -> NotificationResponse:
        notification = repository.get(notification_id)
        if notification is None:
            raise HTTPException(status_code=404, detail="Notificación no encontrada.")
        allowed = scope(session)
        if allowed is not None and notification.agent_id not in allowed:
            raise HTTPException(status_code=404, detail="Notificación no encontrada.")
        return _response(notification)

    return router
