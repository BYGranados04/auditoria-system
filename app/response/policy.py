from __future__ import annotations

from ipaddress import ip_address

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.response.models import ResponseMode


class ResponsePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: ResponseMode = "audit_only"

    trusted_admin_ips: set[str] = Field(
        default_factory=set,
    )

    allow_temporary_ip_block: bool = False

    temporary_block_seconds: int = Field(
        default=900,
        ge=60,
        le=86400,
    )

    @field_validator("trusted_admin_ips")
    @classmethod
    def normalize_trusted_admin_ips(
        cls,
        values: set[str],
    ) -> set[str]:
        return {str(ip_address(value)) for value in values}
