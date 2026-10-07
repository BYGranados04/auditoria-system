from __future__ import annotations

from ipaddress import ip_address
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.response.models import ResponseMode

BlockScope = Literal["ip", "ip_port"]

DEFAULT_ESCALATION_SECONDS: tuple[int, ...] = (120, 600, 3600)
MINIMUM_BLOCK_SECONDS = 60
MAXIMUM_BLOCK_SECONDS = 86400
MAXIMUM_ESCALATION_LEVELS = 10


class ResponsePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: ResponseMode = "audit_only"

    trusted_admin_ips: set[str] = Field(
        default_factory=set,
    )

    allow_temporary_ip_block: bool = False

    temporary_block_seconds: int = Field(
        default=900,
        ge=MINIMUM_BLOCK_SECONDS,
        le=MAXIMUM_BLOCK_SECONDS,
    )

    # Alcance del bloqueo recomendado/aplicado. "ip" conserva el
    # comportamiento histórico (TEMPORARY_BLOCK_IP). "ip_port" bloquea
    # únicamente el servicio afectado (TEMPORARY_BLOCK_IP_PORT).
    block_scope: BlockScope = "ip"

    allow_temporary_ip_port_block: bool = False

    ssh_port: int = Field(
        default=22,
        ge=1,
        le=65535,
    )

    # Escalamiento por reincidencia. Desactivado por defecto para que la
    # duración histórica (temporary_block_seconds) no cambie.
    escalation_enabled: bool = False

    escalation_seconds: tuple[int, ...] = DEFAULT_ESCALATION_SECONDS

    escalation_window_seconds: int = Field(
        default=86400,
        ge=300,
        le=2_592_000,
    )

    @field_validator("trusted_admin_ips")
    @classmethod
    def normalize_trusted_admin_ips(
        cls,
        values: set[str],
    ) -> set[str]:
        return {str(ip_address(value)) for value in values}

    @field_validator("escalation_seconds")
    @classmethod
    def validate_escalation_seconds(
        cls,
        values: tuple[int, ...],
    ) -> tuple[int, ...]:
        if not values:
            raise ValueError("escalation_seconds requiere al menos un nivel.")

        if len(values) > MAXIMUM_ESCALATION_LEVELS:
            raise ValueError(
                "escalation_seconds admite como máximo "
                f"{MAXIMUM_ESCALATION_LEVELS} niveles."
            )

        for value in values:
            if not MINIMUM_BLOCK_SECONDS <= value <= MAXIMUM_BLOCK_SECONDS:
                raise ValueError(
                    "Cada nivel de escalamiento debe estar entre "
                    f"{MINIMUM_BLOCK_SECONDS} y {MAXIMUM_BLOCK_SECONDS} segundos."
                )

        if list(values) != sorted(values):
            raise ValueError("Los niveles de escalamiento deben ser no decrecientes.")

        return tuple(values)

    @property
    def maximum_recurrence_level(self) -> int:
        return len(self.escalation_seconds)

    def duration_for_level(self, level: int) -> int:
        bounded = min(max(level, 1), self.maximum_recurrence_level)
        return self.escalation_seconds[bounded - 1]
