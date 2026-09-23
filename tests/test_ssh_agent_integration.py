from datetime import UTC, datetime
from typing import Any

from app.agent.continuous_agent import ContinuousAgent
from app.core.config import AgentSettings
from app.detection.ssh_collector import (
    SSHJournalBatch,
    SSHJournalRecord,
)


def ssh_record() -> SSHJournalRecord:
    return SSHJournalRecord(
        cursor="cursor-evento",
        timestamp=datetime(
            2026,
            9,
            23,
            4,
            0,
            tzinfo=UTC,
        ),
        event_type="SSH_AUTH_FAILURE",
        severity="medium",
        description="Fallo SSH de prueba.",
        evidence={
            "method": "password",
            "user": "admin",
            "ip": "192.168.1.50",
            "port": "50000",
        },
    )


def test_first_ssh_cycle_seeds_cursor_without_history(
    monkeypatch,
) -> None:
    agent = ContinuousAgent(interval=1)

    monkeypatch.setattr(
        agent.ssh_collector,
        "latest_cursor",
        lambda: "cursor-actual",
    )

    current: dict[str, Any] = {}

    agent._collect_ssh_events(
        {},
        current,
    )

    assert current["ssh_journal_cursor"] == ("cursor-actual")


def test_run_once_collects_new_ssh_event(
    tmp_path,
    monkeypatch,
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

    monkeypatch.setattr(
        "app.agent.continuous_agent.SSHCorrelationEngine.analyze",
        lambda *_args, **_kwargs: [],
    )

    previous = {
        "boot_id": "mismo-boot",
        "ssh_journal_cursor": "cursor-anterior",
    }
    current = {
        "boot_id": "mismo-boot",
    }

    events: list[dict[str, Any]] = []
    saved: list[dict[str, Any]] = []

    monkeypatch.setattr(
        agent,
        "load_state",
        lambda: previous,
    )
    monkeypatch.setattr(
        agent,
        "snapshot",
        lambda: current,
    )
    monkeypatch.setattr(
        agent,
        "compare",
        lambda old, new: None,
    )
    monkeypatch.setattr(
        agent,
        "save_state",
        saved.append,
    )
    monkeypatch.setattr(
        agent,
        "emit",
        lambda **kwargs: events.append(kwargs),
    )
    monkeypatch.setattr(
        agent.ssh_collector,
        "read_after",
        lambda cursor: SSHJournalBatch(
            records=[ssh_record()],
            cursor="cursor-nuevo",
        ),
    )

    agent.run_once()

    assert len(events) == 1

    event = events[0]

    assert event["event_type"] == "SSH_AUTH_FAILURE"
    assert event["timestamp"] == ssh_record().timestamp
    assert event["evidence"]["ip"] == "192.168.1.50"
    assert event["evidence"]["journal_cursor"] == "cursor-evento"

    assert saved[0]["ssh_journal_cursor"] == ("cursor-nuevo")


def test_empty_ssh_batch_preserves_cursor(
    monkeypatch,
) -> None:
    agent = ContinuousAgent(interval=1)

    previous = {
        "ssh_journal_cursor": "cursor-anterior",
    }
    current: dict[str, Any] = {}

    monkeypatch.setattr(
        agent.ssh_collector,
        "read_after",
        lambda cursor: SSHJournalBatch(
            records=[],
            cursor=None,
        ),
    )

    agent._collect_ssh_events(
        previous,
        current,
    )

    assert current["ssh_journal_cursor"] == ("cursor-anterior")


def test_invalid_ssh_cursor_resynchronizes(
    monkeypatch,
) -> None:
    agent = ContinuousAgent(interval=1)

    previous = {
        "ssh_journal_cursor": "cursor-viejo",
    }
    current: dict[str, Any] = {}
    events: list[dict[str, Any]] = []

    def fail_read(cursor: str) -> SSHJournalBatch:
        raise RuntimeError("cursor ya no disponible")

    monkeypatch.setattr(
        agent.ssh_collector,
        "read_after",
        fail_read,
    )
    monkeypatch.setattr(
        agent.ssh_collector,
        "latest_cursor",
        lambda: "cursor-resincronizado",
    )
    monkeypatch.setattr(
        agent,
        "emit",
        lambda **kwargs: events.append(kwargs),
    )

    agent._collect_ssh_events(
        previous,
        current,
    )

    assert current["ssh_journal_cursor"] == ("cursor-resincronizado")
    assert len(events) == 1
    assert events[0]["event_type"] == "SSH_JOURNAL_RESYNC"


def test_ssh_events_are_correlated_after_persistence(
    tmp_path,
    monkeypatch,
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

    previous = {
        "ssh_journal_cursor": "cursor-anterior",
    }
    current = {}

    records = []

    for index in range(5):
        records.append(
            SSHJournalRecord(
                cursor=f"cursor-{index}",
                timestamp=datetime(
                    2026,
                    9,
                    23,
                    5,
                    0,
                    index,
                    tzinfo=UTC,
                ),
                event_type="SSH_INVALID_USER",
                severity="medium",
                description=("Usuario SSH inexistente."),
                evidence={
                    "user": f"usuario-{index}",
                    "ip": "192.168.1.50",
                    "port": str(50000 + index),
                },
            )
        )

    monkeypatch.setattr(
        agent.ssh_collector,
        "read_after",
        lambda cursor: SSHJournalBatch(
            records=records,
            cursor="cursor-final",
        ),
    )

    agent._collect_ssh_events(
        previous,
        current,
    )

    from app.storage.event_repository import (
        EventRepository,
    )

    repository = EventRepository(settings.database_file)

    authentication = repository.list_events(
        category="authentication",
        limit=20,
    )

    detections = repository.list_events(
        category="detection",
        limit=20,
    )

    assert len(authentication) == 5
    assert len(detections) == 1

    detection = detections[0]

    assert detection["event_type"] == "SSH_USER_ENUMERATION_ATTEMPT"
    assert detection["severity"] == "high"
    assert detection["source"] == "detection-engine"
    assert detection["evidence"]["distinct_user_count"] == 5
    assert detection["evidence"]["source_ip"] == "192.168.1.50"

    assert current["ssh_journal_cursor"] == ("cursor-final")
