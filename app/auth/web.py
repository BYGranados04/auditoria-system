from __future__ import annotations

import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from app.auth.config import AuthSettings
from app.auth.repository import (
    AuthConflictError,
    AuthenticatedSession,
    AuthNotFoundError,
    AuthRepository,
    AuthValidationError,
)

SESSION_COOKIE = "auditoria_session"
CSRF_COOKIE = "auditoria_csrf"


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)


class CreateUserRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=1024)
    role: Literal["superadmin", "viewer"]
    hostnames: list[str] = Field(default_factory=list)


class UserStatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    active: bool


class UserRoleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Literal["superadmin", "viewer"]
    hostnames: list[str] | None = None


class UserHostsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hostnames: list[str]


class UserResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: int
    username: str
    role: Literal["superadmin", "viewer"]
    active: bool
    created_at: datetime
    updated_at: datetime
    hostnames: list[str] | None


class MeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: int
    username: str
    role: Literal["superadmin", "viewer"]
    hostnames: list[str] | None
    csrf_token: str


class HostResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hostname: str


class AuthManager:
    def __init__(
        self,
        repository: AuthRepository,
        settings: AuthSettings,
        *,
        clock: Callable[[], datetime] | None = None,
        list_known_hostnames: Callable[[], list[str]] | None = None,
    ) -> None:
        self.repository = repository
        self.settings = settings
        self.clock = clock or (lambda: datetime.now(UTC))
        self._list_known_hostnames = list_known_hostnames or (lambda: [])

    def session_from_request(self, request: Request) -> AuthenticatedSession | None:
        token = request.cookies.get(SESSION_COOKIE)
        if not token:
            return None
        return self.repository.get_session(token, now=self.clock())

    def require_authenticated(self, request: Request) -> AuthenticatedSession:
        session = self.session_from_request(request)
        if session is None:
            raise HTTPException(
                status_code=401,
                detail="Autenticación requerida.",
                headers={"WWW-Authenticate": "Session"},
            )
        return session

    def require_superadmin(self, request: Request) -> AuthenticatedSession:
        session = self.require_authenticated(request)
        if session.role != "superadmin":
            raise HTTPException(status_code=403, detail="Permisos insuficientes.")
        return session

    def get_allowed_hostnames(
        self,
        session: AuthenticatedSession,
    ) -> tuple[str, ...] | None:
        if session.role == "superadmin":
            return None
        return self.repository.get_user_hostnames(session.user_id)

    def resolve_hostname_scope(
        self,
        session: AuthenticatedSession,
        requested_hostname: str | None,
    ) -> tuple[str, ...] | None:
        allowed = self.get_allowed_hostnames(session)
        if (
            requested_hostname is not None
            and allowed is not None
            and requested_hostname not in allowed
        ):
            raise HTTPException(
                status_code=403,
                detail="No tiene acceso al hostname solicitado.",
            )
        return allowed

    def list_known_hostnames(self) -> list[str]:
        try:
            return self._list_known_hostnames()
        except sqlite3.Error as exc:
            raise HTTPException(
                status_code=503,
                detail="Base de datos no disponible.",
            ) from exc

    def validate_known_hostnames(self, hostnames: list[str]) -> None:
        known = set(self.list_known_hostnames())
        unknown = sorted(set(hostnames) - known)
        if unknown:
            raise HTTPException(
                status_code=422,
                detail=f"Hostname no conocido: {', '.join(unknown)}.",
            )

    @staticmethod
    def verify_same_origin(request: Request) -> None:
        expected = str(request.base_url).rstrip("/")
        origin = request.headers.get("origin")
        if origin and origin.rstrip("/") != expected:
            raise HTTPException(status_code=403, detail="Origen no permitido.")
        referer = request.headers.get("referer")
        if referer:
            parsed = urlsplit(referer)
            referer_origin = f"{parsed.scheme}://{parsed.netloc}"
            if referer_origin != expected:
                raise HTTPException(status_code=403, detail="Origen no permitido.")

    def verify_csrf(self, request: Request, session: AuthenticatedSession) -> None:
        self.verify_same_origin(request)
        header_token = request.headers.get("x-csrf-token")
        cookie_token = request.cookies.get(CSRF_COOKIE)
        if (
            not header_token
            or not cookie_token
            or header_token != cookie_token
            or not self.repository.verify_csrf(session.session_id, header_token)
        ):
            raise HTTPException(status_code=403, detail="Token CSRF no válido.")

    def set_session_cookies(
        self,
        response: Response,
        *,
        token: str,
        csrf_token: str,
        expires_at: datetime,
    ) -> None:
        common = {
            "max_age": self.settings.session_seconds,
            "expires": expires_at,
            "path": "/",
            "secure": self.settings.cookie_secure,
            "samesite": "strict",
        }
        response.set_cookie(
            SESSION_COOKIE,
            token,
            httponly=True,
            **common,
        )
        response.set_cookie(
            CSRF_COOKIE,
            csrf_token,
            httponly=False,
            **common,
        )

    @staticmethod
    def clear_session_cookies(response: Response) -> None:
        response.delete_cookie(SESSION_COOKIE, path="/")
        response.delete_cookie(CSRF_COOKIE, path="/")


def build_auth_router(manager: AuthManager) -> APIRouter:
    router = APIRouter()

    @router.post("/auth/login", response_model=MeResponse, tags=["auth"])
    def login(data: LoginRequest, request: Request, response: Response) -> MeResponse:
        manager.verify_same_origin(request)
        user = manager.repository.authenticate(data.username, data.password)
        if user is None:
            raise HTTPException(status_code=401, detail="Credenciales no válidas.")
        session = manager.repository.create_session(
            int(user["id"]),
            session_seconds=manager.settings.session_seconds,
            now=manager.clock(),
        )
        manager.set_session_cookies(
            response,
            token=session.token,
            csrf_token=session.csrf_token,
            expires_at=session.expires_at,
        )
        return MeResponse(
            id=int(user["id"]),
            username=str(user["username"]),
            role=str(user["role"]),
            hostnames=user["hostnames"],
            csrf_token=session.csrf_token,
        )

    @router.get("/auth/me", response_model=MeResponse, tags=["auth"])
    def me(
        request: Request,
        session: AuthenticatedSession = Depends(  # noqa: B008
            manager.require_authenticated
        ),
    ) -> MeResponse:
        csrf_token = request.cookies.get(CSRF_COOKIE, "")
        if not csrf_token or not manager.repository.verify_csrf(
            session.session_id,
            csrf_token,
        ):
            raise HTTPException(status_code=401, detail="Sesión no válida.")
        return MeResponse(
            id=session.user_id,
            username=session.username,
            role=session.role,
            hostnames=manager.get_allowed_hostnames(session),
            csrf_token=csrf_token,
        )

    @router.post("/auth/logout", status_code=204, tags=["auth"])
    def logout(
        request: Request,
        response: Response,
        session: AuthenticatedSession = Depends(  # noqa: B008
            manager.require_authenticated
        ),
    ) -> None:
        manager.verify_csrf(request, session)
        token = request.cookies.get(SESSION_COOKIE)
        if token:
            manager.repository.delete_session(token)
        manager.clear_session_cookies(response)

    @router.get(
        "/admin/users",
        response_model=list[UserResponse],
        tags=["admin"],
    )
    def list_users(
        _session: AuthenticatedSession = Depends(  # noqa: B008
            manager.require_superadmin
        ),
    ) -> list[UserResponse]:
        return [
            UserResponse.model_validate(user)
            for user in manager.repository.list_users()
        ]

    @router.get(
        "/admin/hosts",
        response_model=list[HostResponse],
        tags=["admin"],
    )
    def list_hosts(
        _session: AuthenticatedSession = Depends(  # noqa: B008
            manager.require_superadmin
        ),
    ) -> list[HostResponse]:
        return [
            HostResponse(hostname=hostname)
            for hostname in manager.list_known_hostnames()
        ]

    @router.post(
        "/admin/users",
        response_model=UserResponse,
        status_code=201,
        tags=["admin"],
    )
    def create_user(
        data: CreateUserRequest,
        request: Request,
        session: AuthenticatedSession = Depends(  # noqa: B008
            manager.require_superadmin
        ),
    ) -> UserResponse:
        manager.verify_csrf(request, session)
        if data.hostnames:
            manager.validate_known_hostnames(data.hostnames)
        try:
            user = manager.repository.create_user(
                username=data.username,
                password=data.password,
                role=data.role,
                hostnames=data.hostnames,
                now=manager.clock(),
            )
        except AuthConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except AuthValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return UserResponse.model_validate(user)

    @router.post(
        "/admin/users/{user_id}/status",
        response_model=UserResponse,
        tags=["admin"],
    )
    def update_user_status(
        user_id: int,
        data: UserStatusRequest,
        request: Request,
        session: AuthenticatedSession = Depends(  # noqa: B008
            manager.require_superadmin
        ),
    ) -> UserResponse:
        manager.verify_csrf(request, session)
        try:
            user = manager.repository.set_user_active(
                user_id,
                active=data.active,
                actor_user_id=session.user_id,
                now=manager.clock(),
            )
        except AuthNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except AuthConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return UserResponse.model_validate(user)

    @router.post(
        "/admin/users/{user_id}/role",
        response_model=UserResponse,
        tags=["admin"],
    )
    def update_user_role(
        user_id: int,
        data: UserRoleRequest,
        request: Request,
        session: AuthenticatedSession = Depends(  # noqa: B008
            manager.require_superadmin
        ),
    ) -> UserResponse:
        manager.verify_csrf(request, session)
        if data.hostnames:
            manager.validate_known_hostnames(data.hostnames)
        try:
            user = manager.repository.set_user_role(
                user_id,
                role=data.role,
                actor_user_id=session.user_id,
                hostnames=data.hostnames,
                now=manager.clock(),
            )
        except AuthNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except (AuthConflictError, AuthValidationError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return UserResponse.model_validate(user)

    @router.post(
        "/admin/users/{user_id}/hosts",
        response_model=UserResponse,
        tags=["admin"],
    )
    def update_user_hosts(
        user_id: int,
        data: UserHostsRequest,
        request: Request,
        session: AuthenticatedSession = Depends(  # noqa: B008
            manager.require_superadmin
        ),
    ) -> UserResponse:
        manager.verify_csrf(request, session)
        if data.hostnames:
            manager.validate_known_hostnames(data.hostnames)
        try:
            user = manager.repository.replace_user_hostnames(
                user_id,
                hostnames=data.hostnames,
                now=manager.clock(),
            )
        except AuthNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except (AuthConflictError, AuthValidationError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return UserResponse.model_validate(user)

    return router
