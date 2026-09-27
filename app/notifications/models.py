from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

NotificationStatus = Literal["pending", "sent", "failed"]


@dataclass(frozen=True)
class NotificationMessage:
    recipient: str
    subject: str
    text: str
    html: str


@dataclass(frozen=True)
class NotificationAttempt:
    id: int
    event_id: str
    channel: str
    provider: str
    recipient: str
    hostname: str
    severity: str
    status: NotificationStatus
    created_at: datetime
    sent_at: datetime | None
    error: str | None
    provider_message_id: str | None


@dataclass(frozen=True)
class ProviderResult:
    provider_message_id: str | None
