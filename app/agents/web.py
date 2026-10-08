from __future__ import annotations

import shlex
import unicodedata
from datetime import datetime
from typing import Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.auth.repository import (
    CONFIG_STATUS_REASON_MAX_LENGTH,
    AgentConfigStaleError,
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


ResponseModeValue = Literal["audit_only", "assisted", "automatic"]


class AgentResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str
    hostname: str
    status: str
    presence: str
    registered_at: datetime
    last_seen_at: datetime | None
    created_at: datetime
    updated_at: datetime
    # Control plane v1.1. hostname sigue siendo la referencia técnica.
    display_name: str | None
    agent_version: str | None
    config_protocol: int | None
    desired_response_mode: ResponseModeValue | None
    config_revision: int
    config_updated_at: datetime | None
    applied_config_revision: int
    effective_response_mode: ResponseModeValue | None
    config_source: Literal["local", "central"] | None
    blocking_enabled: bool | None
    config_reported_at: datetime | None
    config_status: Literal["pending", "applied", "rejected"] | None
    config_status_revision: int | None
    config_status_reason: str | None
    config_pending: bool


class AgentDisplayNameRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # La validación fina (64 caracteres tras trim, categoría Unicode C) vive
    # en el repositorio; aquí solo se acota el tamaño del cuerpo.
    display_name: str | None = Field(max_length=256)


class AgentResponseModeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    response_mode: ResponseModeValue
    expected_revision: int = Field(strict=True, ge=0, le=2_147_483_647)


class AgentConfigResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    revision: int
    response_mode: ResponseModeValue | None


class AgentConfigStateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # strict: true/false o "1" no son revisiones válidas.
    applied_revision: int = Field(strict=True, ge=0, le=2_147_483_647)
    effective_response_mode: ResponseModeValue
    config_source: Literal["local", "central"]
    blocking_enabled: bool = Field(strict=True)
    status: Literal["applied", "rejected"]
    # Motivo corto generado por Nexora. Se rechaza (422) si excede el límite
    # o trae caracteres de control; el repositorio además lo sanea.
    reason: str | None = Field(
        default=None, max_length=CONFIG_STATUS_REASON_MAX_LENGTH
    )

    @field_validator("reason")
    @classmethod
    def reason_must_be_plain_text(cls, value: str | None) -> str | None:
        if value is not None and any(
            unicodedata.category(character).startswith("C") for character in value
        ):
            raise ValueError("reason contiene caracteres no permitidos.")
        return value


class AgentConfigStateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    accepted: bool
    stale: bool


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
    # Deprecated compatibility field. The bearer credential remains authoritative.
    agent_id: str | None = Field(default=None, min_length=16, max_length=255)
    hostname: str | None = Field(default=None, min_length=1, max_length=255)
    agent_version: str | None = Field(default=None, min_length=1, max_length=128)


def _agent_bearer(
    credentials: HTTPAuthorizationCredentials | None,
) -> str:
    if (
        credentials is None
        or credentials.scheme.casefold() != "bearer"
        or not credentials.credentials
        or credentials.credentials != credentials.credentials.strip()
        or len(credentials.credentials) > 512
    ):
        raise HTTPException(status_code=401, detail="Credencial no válida.")
    return credentials.credentials


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
        authenticated = manager.repository.authenticate_agent_credential(
            credentials.credentials
        )
        if authenticated is None or (
            data.agent_id is not None
            and data.agent_id != str(authenticated["agent_id"])
        ):
            raise HTTPException(status_code=401, detail="Credencial no válida.")
        try:
            agent = manager.repository.record_agent_heartbeat(
                credential=credentials.credentials,
                now=manager.clock(),
                offline_after_seconds=manager.settings.agent_offline_after_seconds,
                agent_version=data.agent_version,
            )
        except AuthValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if agent is None:
            raise HTTPException(status_code=401, detail="Credencial no válida.")
        return _agent_response(agent)

    @router.get(
        "/agent/config",
        response_model=AgentConfigResponse,
        tags=["agent-connectivity"],
    )
    def agent_config(
        credentials: HTTPAuthorizationCredentials | None = Depends(  # noqa: B008
            bearer_scheme
        ),
    ) -> AgentConfigResponse:
        """Configuración solicitada para el agente dueño de la credencial.

        Nunca contiene comandos, rutas ni secretos: solo revisión y modo.
        """

        config = manager.repository.get_agent_config_for_credential(
            _agent_bearer(credentials)
        )
        if config is None:
            raise HTTPException(status_code=401, detail="Credencial no válida.")
        return AgentConfigResponse(
            revision=int(config["revision"]),
            response_mode=config["response_mode"],
        )

    @router.post(
        "/agent/config/state",
        response_model=AgentConfigStateResponse,
        tags=["agent-connectivity"],
    )
    def agent_config_state(
        data: AgentConfigStateRequest,
        credentials: HTTPAuthorizationCredentials | None = Depends(  # noqa: B008
            bearer_scheme
        ),
    ) -> AgentConfigStateResponse:
        # La identidad sale exclusivamente de la credencial: el cuerpo no
        # contiene agent_id, por lo que no se puede reportar por otro agente.
        try:
            updated = manager.repository.report_agent_config_state(
                credential=_agent_bearer(credentials),
                applied_revision=data.applied_revision,
                effective_response_mode=data.effective_response_mode,
                config_source=data.config_source,
                blocking_enabled=data.blocking_enabled,
                status=data.status,
                reason=data.reason,
                now=manager.clock(),
            )
        except AgentConfigStaleError:
            return AgentConfigStateResponse(accepted=False, stale=True)
        except AuthConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except AuthValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if updated is None:
            raise HTTPException(status_code=401, detail="Credencial no válida.")
        return AgentConfigStateResponse(accepted=True, stale=False)

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
                now=manager.clock(),
                offline_after_seconds=manager.settings.agent_offline_after_seconds,
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
            now=manager.clock(),
            offline_after_seconds=manager.settings.agent_offline_after_seconds,
        )
        if agent is None:
            raise HTTPException(status_code=404, detail="Servidor no encontrado.")
        return _agent_response(agent)

    @router.patch(
        "/agents/{agent_id}",
        response_model=AgentResponse,
        tags=["agents"],
    )
    def update_agent_display_name(
        agent_id: str,
        data: AgentDisplayNameRequest,
        request: Request,
        session: AuthenticatedSession = Depends(  # noqa: B008
            manager.require_superadmin
        ),
    ) -> AgentResponse:
        # superadmin + CSRF + mismo origen, igual que las aprobaciones.
        manager.verify_csrf(request, session)
        try:
            agent = manager.repository.set_agent_display_name(
                agent_id,
                display_name=data.display_name,
                actor_user_id=session.user_id,
                actor_username=session.username,
                now=manager.clock(),
                offline_after_seconds=manager.settings.agent_offline_after_seconds,
            )
        except AuthNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except AuthValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return _agent_response(agent)

    @router.put(
        "/agents/{agent_id}/response-mode",
        response_model=AgentResponse,
        tags=["agents"],
    )
    def update_agent_response_mode(
        agent_id: str,
        data: AgentResponseModeRequest,
        request: Request,
        session: AuthenticatedSession = Depends(  # noqa: B008
            manager.require_superadmin
        ),
    ) -> AgentResponse:
        # Solo se guarda la intención. El agente la obtiene por su canal
        # autenticado; el central no usa SSH, no edita agent.env y no
        # ejecuta comandos remotos.
        manager.verify_csrf(request, session)
        try:
            agent = manager.repository.set_desired_response_mode(
                agent_id,
                response_mode=data.response_mode,
                expected_revision=data.expected_revision,
                actor_user_id=session.user_id,
                actor_username=session.username,
                now=manager.clock(),
                offline_after_seconds=manager.settings.agent_offline_after_seconds,
            )
        except AuthNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except AuthConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except AuthValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return _agent_response(agent)

    return router
