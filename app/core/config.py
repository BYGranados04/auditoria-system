from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AgentSettings:
    interval: int
    state_dir: Path
    log_dir: Path

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
    )
