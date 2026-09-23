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
