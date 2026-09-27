from __future__ import annotations

import shlex
from datetime import datetime
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

from app.auth.repository import (
    AuthConflictError,
    AuthenticatedSession,
    AuthNotFoundError,
    AuthValidationError,
)
from app.auth.web import AuthManager

AGENT_IDENTITY_PATH = "/etc/auditoria-system/agent-identity.json"
REGISTRATION_TOKEN_SECONDS = 15 * 60
bearer_scheme = HTTPBearer(auto_error=False)


def _configured_central_url(value: str | None) -> str:
    if value is None or not value.strip():
        raise HTTPException(
            status_code=503,
            detail="AUDITORIA_CENTRAL_URL debe configurarse para registrar agentes.",
        )
    normalized = value.strip().rstrip("/")
    parsed = urlsplit(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(
            status_code=503,
            detail="AUDITORIA_CENTRAL_URL debe ser una URL http o https válida.",
        )
    return normalized


class AgentResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str
    hostname: str
    status: str
    registered_at: datetime
    last_seen_at: datetime | None
    created_at: datetime
    updated_at: datetime


class RegistrationTokenResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str
    expires_at: datetime
    command: str


class AgentEnrollRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    registration_token: str = Field(min_length=16, max_length=512)
    hostname: str = Field(min_length=1, max_length=255)
    metadata: dict[str, str] | None = None


class AgentEnrollResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str
    credential: str


class AgentHeartbeatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=16, max_length=255)


def _agent_response(agent: dict[str, object]) -> AgentResponse:
    return AgentResponse.model_validate(
        {key: value for key, value in agent.items() if key != "owner_user_id"}
    )


def build_agent_router(manager: AuthManager) -> APIRouter:
    router = APIRouter()

    @router.post(
        "/agents/registration-token",
        response_model=RegistrationTokenResponse,
        tags=["agents"],
    )
    def create_registration_token(
        request: Request,
        session: AuthenticatedSession = Depends(  # noqa: B008
            manager.require_authenticated
        ),
    ) -> RegistrationTokenResponse:
        manager.verify_csrf(request, session)
        central_url = _configured_central_url(manager.settings.central_url)
        try:
            registration = manager.repository.create_agent_registration_token(
                session.user_id,
                ttl_seconds=REGISTRATION_TOKEN_SECONDS,
                now=manager.clock(),
            )
        except AuthNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        command = " ".join(
            (
                "sudo",
                "/opt/auditoria-system/.venv/bin/python",
                "-m",
                "app.agent",
                "register",
                "--server",
                shlex.quote(central_url),
                "--token",
                shlex.quote(registration.token),
            )
        )
        return RegistrationTokenResponse(
            token=registration.token,
            expires_at=registration.expires_at,
            command=command,
        )

    @router.post(
        "/agent/enroll",
        response_model=AgentEnrollResponse,
        tags=["agent-connectivity"],
    )
    def enroll_agent(data: AgentEnrollRequest) -> AgentEnrollResponse:
        try:
            enrollment = manager.repository.enroll_agent(
                registration_token=data.registration_token,
                hostname=data.hostname,
                now=manager.clock(),
            )
        except AuthValidationError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        except AuthConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return AgentEnrollResponse(
            agent_id=str(enrollment.agent["agent_id"]),
            credential=enrollment.credential,
        )

    @router.post(
        "/agent/heartbeat",
        response_model=AgentResponse,
        tags=["agent-connectivity"],
    )
    def agent_heartbeat(
        data: AgentHeartbeatRequest,
        credentials: HTTPAuthorizationCredentials | None = Depends(  # noqa: B008
            bearer_scheme
        ),
    ) -> AgentResponse:
        if credentials is None or credentials.scheme.casefold() != "bearer":
            raise HTTPException(status_code=401, detail="Credencial no válida.")
        agent = manager.repository.record_agent_heartbeat(
            agent_id=data.agent_id,
            credential=credentials.credentials,
            now=manager.clock(),
        )
        if agent is None:
            raise HTTPException(status_code=401, detail="Credencial no válida.")
        return _agent_response(agent)

    @router.get(
        "/agents",
        response_model=list[AgentResponse],
        tags=["agents"],
    )
    def list_agents(
        session: AuthenticatedSession = Depends(  # noqa: B008
            manager.require_authenticated
        ),
    ) -> list[AgentResponse]:
        owner_user_id = None if session.role == "superadmin" else session.user_id
        return [
            _agent_response(agent)
            for agent in manager.repository.list_agents(
                owner_user_id=owner_user_id,
            )
        ]

    @router.get(
        "/agents/{agent_id}",
        response_model=AgentResponse,
        tags=["agents"],
    )
    def get_agent(
        agent_id: str,
        session: AuthenticatedSession = Depends(  # noqa: B008
            manager.require_authenticated
        ),
    ) -> AgentResponse:
        owner_user_id = None if session.role == "superadmin" else session.user_id
        agent = manager.repository.get_agent(
            agent_id,
            owner_user_id=owner_user_id,
        )
        if agent is None:
            raise HTTPException(status_code=404, detail="Servidor no encontrado.")
        return _agent_response(agent)

    return router
