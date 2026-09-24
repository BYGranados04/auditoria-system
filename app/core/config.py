from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AgentSettings:
    interval: int
    state_dir: Path
    log_dir: Path

    response_mode: str = "audit_only"
    trusted_admin_ips: tuple[str, ...] = ()
    allow_temporary_ip_block: bool = False
    temporary_block_seconds: int = 900

    @property
    def state_file(self) -> Path:
        return self.state_dir / "agent_state.json"

    @property
    def events_file(self) -> Path:
        return self.log_dir / "events.jsonl"

    @property
    def database_file(self) -> Path:
        return self.state_dir / "auditoria.db"


def _positive_integer(name: str, default: int) -> int:
    raw = os.getenv(name)

    if raw is None:
        return default

    try:
        value = int(raw)
    except ValueError:
        return default

    return value if value > 0 else default


def _bounded_integer(
    name: str,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    value = _positive_integer(name, default)

    if minimum <= value <= maximum:
        return value

    return default


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


def _response_mode() -> str:
    raw = (
        os.getenv(
            "AUDITORIA_RESPONSE_MODE",
            "audit_only",
        )
        .strip()
        .lower()
    )

    if raw in {
        "audit_only",
        "assisted",
        "automatic",
    }:
        return raw

    return "audit_only"


def _trusted_admin_ips() -> tuple[str, ...]:
    raw = os.getenv(
        "AUDITORIA_TRUSTED_ADMIN_IPS",
        "",
    )

    return tuple(value.strip() for value in raw.split(",") if value.strip())


def load_agent_settings() -> AgentSettings:
    return AgentSettings(
        interval=_positive_integer(
            "AUDITORIA_INTERVAL",
            10,
        ),
        state_dir=Path(
            os.getenv(
                "AUDITORIA_STATE_DIR",
                "/var/lib/auditoria-system",
            )
        ),
        log_dir=Path(
            os.getenv(
                "AUDITORIA_LOG_DIR",
                "/var/log/auditoria-system",
            )
        ),
        response_mode=_response_mode(),
        trusted_admin_ips=_trusted_admin_ips(),
        allow_temporary_ip_block=_boolean(
            "AUDITORIA_ALLOW_TEMPORARY_IP_BLOCK",
            False,
        ),
        temporary_block_seconds=_bounded_integer(
            "AUDITORIA_TEMPORARY_BLOCK_SECONDS",
            900,
            60,
            86400,
        ),
    )
