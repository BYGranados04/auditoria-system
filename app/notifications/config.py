from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlsplit

SEVERITIES = ("low", "medium", "high", "critical")


@dataclass(frozen=True)
class NotificationSettings:
    enabled: bool = False
    min_severity: str = "high"
    provider: str = "resend"
    resend_api_key: str | None = None
    sender: str | None = None
    recipient: str | None = None
    resend_api_url: str = "https://api.resend.com/emails"
    timeout_seconds: int = 5

    @property
    def complete(self) -> bool:
        return bool(self.resend_api_key and self.sender and self.recipient)


def _boolean(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _timeout() -> int:
    try:
        value = int(os.getenv("AUDITORIA_NOTIFICATION_TIMEOUT_SECONDS", "5"))
    except ValueError:
        return 5
    return value if 1 <= value <= 60 else 5


def load_notification_settings() -> NotificationSettings:
    severity = os.getenv("AUDITORIA_NOTIFICATION_MIN_SEVERITY", "high").strip().lower()
    provider = os.getenv("AUDITORIA_NOTIFICATION_PROVIDER", "resend").strip().lower()
    url = os.getenv("AUDITORIA_RESEND_API_URL", "https://api.resend.com/emails").strip()
    parsed = urlsplit(url)
    if severity not in SEVERITIES:
        severity = "high"
    if provider != "resend":
        provider = "resend"
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        url = ""
    return NotificationSettings(
        enabled=_boolean("AUDITORIA_NOTIFICATIONS_ENABLED", False),
        min_severity=severity,
        provider=provider,
        resend_api_key=os.getenv("AUDITORIA_RESEND_API_KEY") or None,
        sender=os.getenv("AUDITORIA_NOTIFICATION_FROM") or None,
        recipient=os.getenv("AUDITORIA_NOTIFICATION_TO") or None,
        resend_api_url=url,
        timeout_seconds=_timeout(),
    )
