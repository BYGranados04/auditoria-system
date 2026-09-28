from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CentralSettings:
    database_file: Path


def load_central_settings() -> CentralSettings:
    return CentralSettings(
        database_file=Path(
            os.getenv(
                "AUDITORIA_CENTRAL_DB",
                "/var/lib/auditoria-system-central/central.db",
            )
        )
    )
