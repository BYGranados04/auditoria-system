"""Consulta autenticada de decisiones humanas (assisted) desde el central.

El central solo informa APPROVE/REJECT para un ``action_id``. El agente nunca
ejecuta datos recibidos del central: busca la acción que él mismo propuso y
almacenó en ``response_approvals`` y la vuelve a validar localmente.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.agent.registration import (
    AgentIdentityError,
    central_response_actions_url,
    load_identity,
)
from app.agent.sync import SyncHttpResponse, SyncTransportError
from app.core.config import AgentSettings

MAX_RESPONSE_BYTES = 65_536
MAX_INSTRUCTIONS = 50


class ApprovalInstruction(BaseModel):
    model_config = ConfigDict(extra="ignore")

    action_id: UUID
    decision: Literal["APPROVE", "REJECT"]
    decided_by: str = Field(min_length=1, max_length=128)
    decided_at: datetime
    reason: str | None = Field(default=None, max_length=500)

    @field_validator("decided_at")
    @classmethod
    def decided_at_must_have_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("decided_at debe incluir zona horaria.")
        return value


class ApprovalTransport(Protocol):
    def get_json(
        self,
        url: str,
        *,
        headers: dict[str, str],
        timeout_seconds: int,
    ) -> SyncHttpResponse: ...


class UrllibApprovalTransport:
    def get_json(
        self,
        url: str,
        *,
        headers: dict[str, str],
        timeout_seconds: int,
    ) -> SyncHttpResponse:
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(  # noqa: S310
                request,
                timeout=timeout_seconds,
            ) as response:
                return SyncHttpResponse(
                    status_code=int(response.status),
                    body=response.read(MAX_RESPONSE_BYTES + 1),
                )
        except urllib.error.HTTPError as exc:
            return SyncHttpResponse(status_code=int(exc.code), body=b"")
        except (OSError, TimeoutError, urllib.error.URLError) as exc:
            raise SyncTransportError("No fue posible contactar al central.") from exc


@dataclass(frozen=True)
class ApprovalFetchResult:
    instructions: tuple[ApprovalInstruction, ...] = ()
    skipped: bool = False
    error: str | None = None


class ResponseApprovalClient:
    def __init__(
        self,
        settings: AgentSettings,
        *,
        transport: ApprovalTransport | None = None,
    ) -> None:
        self.settings = settings
        self.transport = transport or UrllibApprovalTransport()

    def fetch(self) -> ApprovalFetchResult:
        try:
            identity = load_identity(self.settings.identity_file)
        except AgentIdentityError:
            return ApprovalFetchResult(skipped=True, error="Identidad no válida.")
        if identity is None:
            return ApprovalFetchResult(skipped=True)

        try:
            response = self.transport.get_json(
                central_response_actions_url(identity.central_url),
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {identity.credential}",
                },
                timeout_seconds=self.settings.sync_timeout_seconds,
            )
        except (SyncTransportError, TimeoutError, OSError):
            return ApprovalFetchResult(error="Error temporal de red.")
        except Exception:
            return ApprovalFetchResult(error="Error inesperado al consultar.")

        if response.status_code != 200:
            return ApprovalFetchResult(
                error=f"Respuesta HTTP no aceptada ({response.status_code})."
            )

        if len(response.body) > MAX_RESPONSE_BYTES:
            return ApprovalFetchResult(error="Respuesta demasiado grande.")

        try:
            data = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return ApprovalFetchResult(error="Respuesta JSON no válida.")

        items = data.get("actions") if isinstance(data, dict) else None
        if not isinstance(items, list):
            return ApprovalFetchResult(error="Respuesta sin lista de acciones.")

        instructions: list[ApprovalInstruction] = []
        for item in items[:MAX_INSTRUCTIONS]:
            try:
                instructions.append(ApprovalInstruction.model_validate(item))
            except ValidationError:
                continue

        return ApprovalFetchResult(instructions=tuple(instructions))


def is_uuid(value: str) -> bool:
    try:
        return str(UUID(value)) == value
    except ValueError:
        return False
