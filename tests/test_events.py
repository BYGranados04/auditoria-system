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
