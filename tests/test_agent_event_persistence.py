import json
from pathlib import Path

from app.agent.continuous_agent import ContinuousAgent
from app.core.config import AgentSettings
from app.storage.event_repository import EventRepository


def test_emit_persists_event_in_sqlite_and_jsonl(
    tmp_path: Path,
) -> None:
    settings = AgentSettings(
        interval=1,
        state_dir=tmp_path / "state",
        log_dir=tmp_path / "logs",
        identity_file=tmp_path / "agent-identity.json",
    )

    agent = ContinuousAgent(
        interval=1,
        settings=settings,
    )

    agent.emit(
        category="network",
        event_type="PORT_OPENED",
        severity="medium",
        description="Puerto de prueba abierto.",
        evidence={
            "port": "tcp:127.0.0.1:9999",
        },
    )

    repository = EventRepository(settings.database_file)

    stored = repository.list_events()

    assert len(stored) == 1

    jsonl_event = json.loads(settings.events_file.read_text().strip())

    database_event = stored[0]

    assert database_event["event_id"] == jsonl_event["event_id"]
    assert database_event["event_type"] == jsonl_event["event_type"] == "PORT_OPENED"
    assert database_event["severity"] == jsonl_event["severity"] == "medium"
    assert database_event["evidence"] == {"port": "tcp:127.0.0.1:9999"}
    assert jsonl_event["evidence"] == {"port": "tcp:127.0.0.1:9999"}


def test_emit_preserves_explicit_timestamp(
    tmp_path: Path,
) -> None:
    from datetime import UTC, datetime

    settings = AgentSettings(
        interval=1,
        state_dir=tmp_path / "state",
        log_dir=tmp_path / "logs",
        identity_file=tmp_path / "agent-identity.json",
    )

    agent = ContinuousAgent(
        interval=1,
        settings=settings,
    )

    original_timestamp = datetime(
        2026,
        9,
        23,
        4,
        14,
        27,
        tzinfo=UTC,
    )

    agent.emit(
        category="authentication",
        event_type="SSH_INVALID_USER",
        severity="medium",
        description="Intento SSH de prueba.",
        evidence={
            "user": "usuario-prueba",
            "ip": "127.0.0.1",
        },
        timestamp=original_timestamp,
    )

    repository = EventRepository(settings.database_file)

    events = repository.list_events()

    assert len(events) == 1
    assert events[0]["timestamp"] == "2026-09-23T04:14:27Z"


def test_emit_returns_persisted_security_event(
    tmp_path: Path,
) -> None:
    settings = AgentSettings(
        interval=1,
        state_dir=tmp_path / "state",
        log_dir=tmp_path / "logs",
        identity_file=tmp_path / "agent-identity.json",
    )

    agent = ContinuousAgent(
        interval=1,
        settings=settings,
    )

    event = agent.emit(
        category="detection",
        event_type="TEST_DETECTION",
        severity="high",
        description="Detección de prueba.",
        evidence={"test": True},
        source="detection-engine",
    )

    repository = EventRepository(settings.database_file)

    stored = repository.list_events(limit=1)

    assert str(event.event_id) == stored[0]["event_id"]
    assert event.source == "detection-engine"
    assert stored[0]["source"] == "detection-engine"


def test_emit_preserves_explicit_event_id(
    tmp_path: Path,
) -> None:
    from uuid import UUID

    settings = AgentSettings(
        interval=1,
        state_dir=tmp_path / "state",
        log_dir=tmp_path / "logs",
        identity_file=tmp_path / "agent-identity.json",
    )

    agent = ContinuousAgent(
        interval=1,
        settings=settings,
    )

    expected_id = UUID("11111111-2222-4333-8444-555555555555")

    event = agent.emit(
        category="response",
        event_type="TEST_EXPLICIT_EVENT_ID",
        severity="low",
        description="Evento con UUID preasignado.",
        evidence={"test": True},
        event_id=expected_id,
    )

    repository = EventRepository(settings.database_file)

    stored = repository.list_events(limit=1)

    jsonl_event = json.loads(settings.events_file.read_text().strip())

    assert event.event_id == expected_id
    assert stored[0]["event_id"] == str(expected_id)
    assert jsonl_event["event_id"] == str(expected_id)
