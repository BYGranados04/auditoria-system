from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    service: str


def create_app() -> FastAPI:
    application = FastAPI(
        title="Auditoria System API",
        description=("API local de consulta para Auditoria System."),
        version="0.6.0-dev",
    )

    @application.get(
        "/health",
        response_model=HealthResponse,
        tags=["system"],
    )
    def health() -> HealthResponse:
        return HealthResponse(
            status="ok",
            service="auditoria-system-api",
        )

    return application


app = create_app()
