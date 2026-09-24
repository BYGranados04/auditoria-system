from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict

ResponseMode = Literal[
    "audit_only",
    "assisted",
    "automatic",
]

ResponseAction = Literal[
    "NO_ACTION",
    "RECOMMEND_BLOCK_IP",
    "TEMPORARY_BLOCK_IP",
]

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
