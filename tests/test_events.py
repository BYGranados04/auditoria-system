from datetime import datetime

import pytest
from pydantic import ValidationError

from app.core.events import SecurityEvent


def test_event_generates_uuid_and_timestamp() -> None:
    event = SecurityEvent(
        hostname="auditoria-server",
        source="continuous-agent",
        category="network",
        event_type="PORT_OPENED",
        severity="medium",
        description="Nuevo puerto detectado",
        evidence={"port": 8000},
    )

    assert event.event_id is not None
    assert isinstance(event.timestamp, datetime)
    assert event.timestamp.tzinfo is not None
    assert event.severity == "medium"


def test_legacy_event_without_agent_id_serializes_and_deserializes() -> None:
    event = SecurityEvent(
        hostname="legacy-server",
        source="continuous-agent",
        category="system",
        event_type="AGENT_STARTED",
        severity="low",
        description="Evento legacy",
    )

    serialized = event.model_dump(mode="json")
    restored = SecurityEvent.model_validate(serialized)

    assert serialized["agent_id"] is None
    assert restored == event


def test_event_with_agent_id_serializes_and_deserializes() -> None:
    event = SecurityEvent(
        agent_id="agt_stable-identity",
        hostname="renamed-server",
        source="continuous-agent",
        category="detection",
        event_type="SSH_BRUTE_FORCE_ATTEMPT",
        severity="high",
        description="Detección asociada al agente",
    )

    serialized = event.model_dump(mode="json")
    restored = SecurityEvent.model_validate(serialized)

    assert serialized["agent_id"] == "agt_stable-identity"
    assert restored.agent_id == "agt_stable-identity"


def test_event_rejects_unknown_severity() -> None:
    with pytest.raises(ValidationError):
        SecurityEvent(
            hostname="auditoria-server",
            source="test",
            category="test",
            event_type="TEST_EVENT",
            severity="extreme",
            description="Evento inválido",
        )


def test_event_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        SecurityEvent(
            hostname="auditoria-server",
            source="test",
            category="test",
            event_type="TEST_EVENT",
            severity="low",
            description="Evento inválido",
            unexpected_field="not-allowed",
        )
