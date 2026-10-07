from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CentralSettings:
    database_file: Path
    agent_event_batch_max: int = 100
    event_max_future_seconds: int = 300
    event_evidence_max_bytes: int = 65_536


def _bounded_integer(
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if minimum <= value <= maximum else default


def load_central_settings() -> CentralSettings:
    return CentralSettings(
        database_file=Path(
            os.getenv(
                "AUDITORIA_CENTRAL_DB",
                "/var/lib/auditoria-system-central/central.db",
            )
        ),
        agent_event_batch_max=_bounded_integer(
            "AUDITORIA_AGENT_EVENT_BATCH_MAX",
            100,
            minimum=1,
            maximum=1_000,
        ),
        event_max_future_seconds=_bounded_integer(
            "AUDITORIA_EVENT_MAX_FUTURE_SECONDS",
            300,
            minimum=0,
            maximum=86_400,
        ),
        event_evidence_max_bytes=_bounded_integer(
            "AUDITORIA_EVENT_EVIDENCE_MAX_BYTES",
            65_536,
            minimum=1_024,
            maximum=1_048_576,
        ),
    )
