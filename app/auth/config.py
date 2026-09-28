from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AuthSettings:
    database_file: Path
    session_seconds: int = 28_800
    cookie_secure: bool = False
    central_url: str | None = None
    agent_offline_after_seconds: int = 120


def _boolean(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


def _session_seconds() -> int:
    raw = os.getenv("AUDITORIA_AUTH_SESSION_SECONDS", "28800")
    try:
        value = int(raw)
    except ValueError:
        return 28_800
    return value if 300 <= value <= 86_400 else 28_800


def _agent_offline_after_seconds() -> int:
    raw = os.getenv("AUDITORIA_AGENT_OFFLINE_AFTER_SECONDS", "120")
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(
            "AUDITORIA_AGENT_OFFLINE_AFTER_SECONDS debe ser un entero."
        ) from exc
    if not 10 <= value <= 86_400:
        raise ValueError(
            "AUDITORIA_AGENT_OFFLINE_AFTER_SECONDS debe estar entre 10 y 86400."
        )
    return value


def load_auth_settings() -> AuthSettings:
    return AuthSettings(
        database_file=Path(
            os.getenv(
                "AUDITORIA_AUTH_DB",
                "/var/lib/auditoria-system-auth/auth.db",
            )
        ),
        session_seconds=_session_seconds(),
        cookie_secure=_boolean("AUDITORIA_AUTH_COOKIE_SECURE", False),
        central_url=os.getenv("AUDITORIA_CENTRAL_URL"),
        agent_offline_after_seconds=_agent_offline_after_seconds(),
    )
