from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

ResponseMode = Literal[
    "audit_only",
    "assisted",
    "automatic",
]

ResponseAction = Literal[
    "NO_ACTION",
    "RECOMMEND_BLOCK_IP",
    "TEMPORARY_BLOCK_IP",
    "RECOMMEND_BLOCK_IP_PORT",
    "TEMPORARY_BLOCK_IP_PORT",
]

ResponseProtocol = Literal["tcp", "udp"]

EXECUTABLE_ACTIONS: frozenset[str] = frozenset(
    {
        "TEMPORARY_BLOCK_IP",
        "TEMPORARY_BLOCK_IP_PORT",
    }
)

PORT_SCOPED_ACTIONS: frozenset[str] = frozenset(
    {
        "RECOMMEND_BLOCK_IP_PORT",
        "TEMPORARY_BLOCK_IP_PORT",
    }
)

ResponseExecutionStatus = Literal[
    "SKIPPED",
    "DRY_RUN",
    "EXECUTED",
    "FAILED",
]


class ResponseDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detection_event_id: UUID
    hostname: str
    mode: ResponseMode
    action: ResponseAction

    target_ip: str | None = None
    reason: str
    duration_seconds: int | None = None

    approval_required: bool = False
    execution_allowed: bool = False
    executed: bool = False

    # Campos opcionales agregados después de v1.0. Son opcionales para que
    # las decisiones ya persistidas sigan siendo válidas.
    protocol: ResponseProtocol | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    incident_id: str | None = None
    recurrence_level: int | None = Field(default=None, ge=1)
    previous_incidents: int | None = Field(default=None, ge=0)
    selected_duration_seconds: int | None = None
    # Flujo assisted: acción ejecutable propuesta y solicitud de aprobación.
    proposed_action: ResponseAction | None = None
    approval_id: str | None = None


class ResponseExecutionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detection_event_id: UUID
    action: ResponseAction
    target_ip: str | None = None
    duration_seconds: int | None = None

    status: ResponseExecutionStatus
    dry_run: bool
    executed: bool
    reason: str

    block_id: UUID | None = None

    protocol: ResponseProtocol | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    # True cuando la ejecución fue rechazada por una dirección protegida
    # (Tailscale, trusted admin, sesión SSH activa, IP local o gateway).
    protection_rejected: bool = False
    approval_id: str | None = None
