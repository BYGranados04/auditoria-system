from __future__ import annotations

import re
import sqlite3
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from app.auth.repository import AuthenticatedSession
from app.auth.web import AuthManager
from app.central.incidents import (
    CentralIncidentReader,
    CentralResponseActionStore,
    ResponseActionConflictError,
)

IncidentStatus = Literal["OPEN", "OBSERVED", "CONTAINED", "CLOSED"]
Severity = Literal["low", "medium", "high", "critical"]

INCIDENT_ID_REGEX = r"^INC-[0-9A-F]{16}$"
ARTIFACT_FILE_PATTERN = re.compile(r"^[a-z0-9_]{1,64}\.(txt|json)$")
ARTIFACT_KEYS = ("name", "file", "status", "bytes", "sha256", "truncated", "error")


class IncidentSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str
    incident_id: str
    hostname: str
    incident_type: str
    severity: Severity
    source_ip: str | None
    status: IncidentStatus
    opened_at: datetime
    last_activity_at: datetime
    closed_at: datetime | None
    detection_count: int
    recurrence_level: int | None
    last_action: str | None
    last_execution_status: str | None
    updated_at: datetime


class IncidentPage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[IncidentSummary]
    total: int
    limit: int
    offset: int


class TimelineEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["event", "detection", "evidence", "decision", "approval", "execution"]
    event_id: str
    timestamp: datetime
    available: bool
    event_type: str | None
    category: str | None
    severity: str | None
    source: str | None
    description: str | None
    evidence: dict[str, Any]


class EvidenceArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    file: str | None
    status: str
    bytes: int
    sha256: str | None
    truncated: bool
    error: str | None


class EvidenceMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    capture_id: str
    event_id: str
    status: str
    detection_event_id: str | None
    captured_at: datetime | None
    completed_at: datetime | None
    total_bytes: int
    max_bytes: int | None
    truncated: bool
    storage: str
    artifacts: list[EvidenceArtifact]


class ResponseActionModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str
    action_id: str
    incident_id: str | None
    hostname: str
    action: str
    target_ip: str
    protocol: str | None
    port: int | None
    duration_seconds: int
    requested_at: datetime
    expires_at: datetime
    status: Literal[
        "PENDING_APPROVAL",
        "APPROVED",
        "REJECTED",
        "EXECUTED",
        "SKIPPED",
        "FAILED",
        "EXPIRED",
    ]
    decided_by: str | None
    decided_at: datetime | None
    decision_reason: str | None
    result_status: str | None
    result_reason: str | None
    result_at: datetime | None


class ApproveActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RejectActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(default=None, max_length=500)


class IncidentDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident: IncidentSummary
    actions: list[ResponseActionModel]
    detections: list[TimelineEntry]
    decision: TimelineEntry | None
    execution: TimelineEntry | None
    evidence: list[EvidenceMetadata]
    timeline_count: int


def _require_timezone(value: datetime | None, *, field_name: str) -> None:
    if value is None:
        return
    if value.tzinfo is None or value.utcoffset() is None:
        raise HTTPException(
            status_code=422,
            detail=f"{field_name} debe incluir zona horaria.",
        )


def _utc_text(value: datetime) -> str:
    return (
        value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    )


def _int_value(value: object, default: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return value


def _optional_datetime(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _evidence_metadata(entry: dict[str, Any]) -> EvidenceMetadata | None:
    """Metadatos de evidencia a partir del evento sincronizado.

    Nunca se accede al sistema de archivos: el contenido permanece en el
    agente. Los nombres de archivo se validan para no reflejar rutas.
    """

    evidence = entry.get("evidence") or {}

    if entry.get("event_type") != "FORENSIC_EVIDENCE_CAPTURED":
        return None

    try:
        capture_id = str(UUID(str(evidence.get("capture_id"))))
    except ValueError:
        return None

    artifacts: list[EvidenceArtifact] = []
    raw_artifacts = evidence.get("artifacts")

    for item in raw_artifacts if isinstance(raw_artifacts, list) else []:
        if not isinstance(item, dict):
            continue
        data = {key: item.get(key) for key in ARTIFACT_KEYS}
        file_name = data["file"]
        if not isinstance(file_name, str) or not ARTIFACT_FILE_PATTERN.fullmatch(
            file_name
        ):
            data["file"] = None
        artifacts.append(
            EvidenceArtifact(
                name=str(data["name"] or "desconocido")[:64],
                file=data["file"],
                status=str(data["status"] or "desconocido")[:32],
                bytes=_int_value(data["bytes"]),
                sha256=(
                    str(data["sha256"])
                    if isinstance(data["sha256"], str)
                    and re.fullmatch(r"[0-9a-f]{64}", data["sha256"])
                    else None
                ),
                truncated=bool(data["truncated"]),
                error=(str(data["error"])[:300] if data["error"] else None),
            )
        )

    detection_event_id = evidence.get("detection_event_id")

    return EvidenceMetadata(
        capture_id=capture_id,
        event_id=str(entry["event_id"]),
        status=str(evidence.get("status") or "desconocido")[:32],
        detection_event_id=(
            str(detection_event_id) if isinstance(detection_event_id, str) else None
        ),
        captured_at=_optional_datetime(evidence.get("captured_at")),
        completed_at=_optional_datetime(evidence.get("completed_at")),
        total_bytes=_int_value(evidence.get("total_bytes")),
        max_bytes=(
            _int_value(evidence.get("max_bytes"))
            if evidence.get("max_bytes") is not None
            else None
        ),
        truncated=bool(evidence.get("truncated")),
        storage="agent-local",
        artifacts=artifacts,
    )


def build_incident_router(
    manager: AuthManager,
    reader: CentralIncidentReader,
    store: CentralResponseActionStore | None = None,
) -> APIRouter:
    action_store = store or CentralResponseActionStore(reader.database_path)
    router = APIRouter(tags=["incidents"])

    incident_path = Path(pattern=INCIDENT_ID_REGEX)

    def resolve_incident(
        session: AuthenticatedSession,
        incident_id: str,
        agent_id: str | None,
    ) -> dict[str, Any]:
        allowed = manager.resolve_agent_scope(session, agent_id)
        try:
            matches = reader.find_incidents(
                incident_id=incident_id,
                agent_ids=allowed,
            )
        except sqlite3.Error as exc:
            raise HTTPException(
                status_code=503,
                detail="Base de datos no disponible.",
            ) from exc

        if not matches:
            raise HTTPException(status_code=404, detail="Incidente no encontrado.")

        if len(matches) > 1:
            raise HTTPException(
                status_code=409,
                detail="El incidente existe en varios servidores; indique agent_id.",
            )

        return matches[0]

    def load_timeline(incident: dict[str, Any]) -> list[dict[str, Any]]:
        try:
            return reader.timeline(
                agent_id=str(incident["agent_id"]),
                incident_id=str(incident["incident_id"]),
            )
        except sqlite3.Error as exc:
            raise HTTPException(
                status_code=503,
                detail="Base de datos no disponible.",
            ) from exc

    @router.get("/incidents", response_model=IncidentPage)
    def list_incidents(
        agent_id: str | None = None,
        severity: Severity | None = None,
        status: IncidentStatus | None = None,
        incident_type: str | None = Query(
            default=None,
            min_length=1,
            max_length=128,
            pattern=r"^[A-Z0-9_]+$",
        ),
        source_ip: str | None = Query(default=None, max_length=64),
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0, le=100_000),
        session: AuthenticatedSession = Depends(  # noqa: B008
            manager.require_authenticated
        ),
    ) -> IncidentPage:
        _require_timezone(since, field_name="since")
        _require_timezone(until, field_name="until")

        if since is not None and until is not None and since > until:
            raise HTTPException(
                status_code=422,
                detail="since no puede ser posterior a until.",
            )

        normalized_ip: str | None = None
        if source_ip is not None:
            try:
                normalized_ip = str(ip_address(source_ip))
            except ValueError as exc:
                raise HTTPException(
                    status_code=422,
                    detail="source_ip no es una dirección IP válida.",
                ) from exc

        try:
            allowed = manager.resolve_agent_scope(session, agent_id)
            items, total = reader.list_incidents(
                agent_ids=allowed,
                severity=severity,
                status=status,
                incident_type=incident_type,
                source_ip=normalized_ip,
                since=_utc_text(since) if since is not None else None,
                until=_utc_text(until) if until is not None else None,
                limit=limit,
                offset=offset,
            )
        except sqlite3.Error as exc:
            raise HTTPException(
                status_code=503,
                detail="Base de datos no disponible.",
            ) from exc

        return IncidentPage(
            items=[IncidentSummary(**item) for item in items],
            total=total,
            limit=limit,
            offset=offset,
        )

    @router.get("/incidents/{incident_id}", response_model=IncidentDetail)
    def get_incident(
        incident_id: str = incident_path,
        agent_id: str | None = None,
        session: AuthenticatedSession = Depends(  # noqa: B008
            manager.require_authenticated
        ),
    ) -> IncidentDetail:
        incident = resolve_incident(session, incident_id, agent_id)
        timeline = load_timeline(incident)

        def latest(kind: str) -> TimelineEntry | None:
            entries = [entry for entry in timeline if entry["kind"] == kind]
            return TimelineEntry(**entries[-1]) if entries else None

        evidence = [
            metadata
            for metadata in (
                _evidence_metadata(entry)
                for entry in timeline
                if entry["kind"] == "evidence"
            )
            if metadata is not None
        ]

        try:
            actions = reader.actions(
                agent_id=str(incident["agent_id"]),
                incident_id=str(incident["incident_id"]),
            )
        except sqlite3.Error as exc:
            raise HTTPException(
                status_code=503,
                detail="Base de datos no disponible.",
            ) from exc

        return IncidentDetail(
            incident=IncidentSummary(**incident),
            actions=[ResponseActionModel(**action) for action in actions],
            detections=[
                TimelineEntry(**entry)
                for entry in timeline
                if entry["kind"] == "detection"
            ],
            decision=latest("decision"),
            execution=latest("execution"),
            evidence=evidence,
            timeline_count=len(timeline),
        )

    @router.get(
        "/incidents/{incident_id}/timeline",
        response_model=list[TimelineEntry],
    )
    def get_incident_timeline(
        incident_id: str = incident_path,
        agent_id: str | None = None,
        session: AuthenticatedSession = Depends(  # noqa: B008
            manager.require_authenticated
        ),
    ) -> list[TimelineEntry]:
        incident = resolve_incident(session, incident_id, agent_id)
        return [TimelineEntry(**entry) for entry in load_timeline(incident)]

    @router.get(
        "/incidents/{incident_id}/evidence",
        response_model=list[EvidenceMetadata],
    )
    def list_incident_evidence(
        incident_id: str = incident_path,
        agent_id: str | None = None,
        session: AuthenticatedSession = Depends(  # noqa: B008
            manager.require_authenticated
        ),
    ) -> list[EvidenceMetadata]:
        incident = resolve_incident(session, incident_id, agent_id)
        return [
            metadata
            for metadata in (
                _evidence_metadata(entry)
                for entry in load_timeline(incident)
                if entry["kind"] == "evidence"
            )
            if metadata is not None
        ]

    def decide_action(
        *,
        request: Request,
        session: AuthenticatedSession,
        incident_id: str,
        action_id: UUID,
        agent_id: str | None,
        approve: bool,
        reason: str | None,
    ) -> ResponseActionModel:
        # Toda la autorización se valida aquí: superadmin + CSRF + origen.
        manager.verify_csrf(request, session)
        incident = resolve_incident(session, incident_id, agent_id)
        try:
            action = action_store.decide(
                agent_id=str(incident["agent_id"]),
                incident_id=str(incident["incident_id"]),
                action_id=str(action_id),
                approve=approve,
                user_id=session.user_id,
                username=session.username,
                reason=reason,
                now=_utc_text(manager.clock()),
            )
        except ResponseActionConflictError as exc:
            raise HTTPException(
                status_code=409,
                detail=f"{exc} Estado actual: {exc.status}.",
            ) from exc
        except sqlite3.Error as exc:
            raise HTTPException(
                status_code=503,
                detail="Base de datos no disponible.",
            ) from exc

        if action is None:
            raise HTTPException(status_code=404, detail="Acción no encontrada.")

        return ResponseActionModel(**action)

    @router.post(
        "/incidents/{incident_id}/actions/{action_id}/approve",
        response_model=ResponseActionModel,
    )
    def approve_action(
        request: Request,
        action_id: UUID,
        data: ApproveActionRequest,
        incident_id: str = incident_path,
        agent_id: str | None = None,
        session: AuthenticatedSession = Depends(  # noqa: B008
            manager.require_superadmin
        ),
    ) -> ResponseActionModel:
        del data
        return decide_action(
            request=request,
            session=session,
            incident_id=incident_id,
            action_id=action_id,
            agent_id=agent_id,
            approve=True,
            reason=None,
        )

    @router.post(
        "/incidents/{incident_id}/actions/{action_id}/reject",
        response_model=ResponseActionModel,
    )
    def reject_action(
        request: Request,
        action_id: UUID,
        data: RejectActionRequest,
        incident_id: str = incident_path,
        agent_id: str | None = None,
        session: AuthenticatedSession = Depends(  # noqa: B008
            manager.require_superadmin
        ),
    ) -> ResponseActionModel:
        return decide_action(
            request=request,
            session=session,
            incident_id=incident_id,
            action_id=action_id,
            agent_id=agent_id,
            approve=False,
            reason=data.reason,
        )

    @router.get(
        "/incidents/{incident_id}/evidence/{capture_id}",
        response_model=EvidenceMetadata,
    )
    def get_incident_evidence(
        capture_id: UUID,
        incident_id: str = incident_path,
        agent_id: str | None = None,
        session: AuthenticatedSession = Depends(  # noqa: B008
            manager.require_authenticated
        ),
    ) -> EvidenceMetadata:
        incident = resolve_incident(session, incident_id, agent_id)
        for entry in load_timeline(incident):
            if entry["kind"] != "evidence":
                continue
            metadata = _evidence_metadata(entry)
            if metadata is not None and metadata.capture_id == str(capture_id):
                return metadata

        raise HTTPException(status_code=404, detail="Evidencia no encontrada.")

    return router
