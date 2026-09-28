import sqlite3
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

import pytest

from app.central.config import load_central_settings
from app.central.repository import (
    CentralEventConflictError,
    CentralEventRepository,
    event_payload_hash,
)
from app.core.events import SecurityEvent

EVENT_ID = UUID("11111111-2222-4333-8444-555555555555")
OCCURRED_AT = datetime(2026, 9, 27, 10, 30, tzinfo=UTC)
RECEIVED_AT = datetime(2026, 9, 27, 10, 31, tzinfo=UTC)


def make_event(**updates: object) -> SecurityEvent:
    values = {
        "event_id": EVENT_ID,
        "timestamp": OCCURRED_AT,
        "agent_id": None,
        "hostname": "metadata-host",
        "source": "detection-engine",
        "category": "detection",
        "event_type": "SSH_BRUTE_FORCE_ATTEMPT",
        "severity": "high",
        "description": "Detección de prueba",
        "evidence": {"attempts": 12, "source_ip": "192.0.2.10"},
    }
    values.update(updates)
    return SecurityEvent.model_validate(values)


def repository(tmp_path: Path) -> CentralEventRepository:
    return CentralEventRepository(
        tmp_path / "central-state" / "central.db",
        clock=lambda: RECEIVED_AT,
    )


def test_central_config_uses_dedicated_default_and_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AUDITORIA_CENTRAL_DB", raising=False)
    monkeypatch.delenv("AUDITORIA_AGENT_EVENT_BATCH_MAX", raising=False)
    monkeypatch.delenv("AUDITORIA_EVENT_MAX_FUTURE_SECONDS", raising=False)
    monkeypatch.delenv("AUDITORIA_EVENT_EVIDENCE_MAX_BYTES", raising=False)
    defaults = load_central_settings()
    assert defaults.database_file == Path(
        "/var/lib/auditoria-system-central/central.db"
    )
    assert defaults.agent_event_batch_max == 100
    assert defaults.event_max_future_seconds == 300
    assert defaults.event_evidence_max_bytes == 65_536

    monkeypatch.setenv("AUDITORIA_CENTRAL_DB", "custom/central.db")
    monkeypatch.setenv("AUDITORIA_AGENT_EVENT_BATCH_MAX", "25")
    monkeypatch.setenv("AUDITORIA_EVENT_MAX_FUTURE_SECONDS", "90")
    monkeypatch.setenv("AUDITORIA_EVENT_EVIDENCE_MAX_BYTES", "8192")
    configured = load_central_settings()
    assert configured.database_file == Path("custom/central.db")
    assert configured.agent_event_batch_max == 25
    assert configured.event_max_future_seconds == 90
    assert configured.event_evidence_max_bytes == 8_192


def test_central_database_creation_schema_indexes_and_wal(tmp_path: Path) -> None:
    repo = repository(tmp_path)
    repo.initialize()
    repo.initialize()

    with sqlite3.connect(repo.database_path) as connection:
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(events)")
        }
        indexes = {
            row[1] for row in connection.execute("PRAGMA index_list(events)")
        }
        journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
        version = connection.execute("PRAGMA user_version").fetchone()[0]

    assert version == 1
    assert journal_mode == "wal"
    assert columns == {
        "id",
        "agent_id",
        "event_id",
        "occurred_at",
        "received_at",
        "hostname",
        "source",
        "category",
        "event_type",
        "severity",
        "description",
        "evidence_json",
        "payload_hash",
    }
    assert {
        "idx_central_events_agent_occurred",
        "idx_central_events_agent_category_occurred",
        "idx_central_events_agent_severity_occurred",
        "idx_central_events_received",
    } <= indexes


def test_identical_duplicate_is_idempotent(tmp_path: Path) -> None:
    repo = repository(tmp_path)
    event = make_event()

    first, first_created = repo.add_event(agent_id="agt_one", event=event)
    second, second_created = repo.add_event(agent_id="agt_one", event=event)

    assert first_created is True
    assert second_created is False
    assert second == first
    with sqlite3.connect(repo.database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1


def test_same_agent_and_event_id_with_changed_payload_conflicts(
    tmp_path: Path,
) -> None:
    repo = repository(tmp_path)
    repo.add_event(agent_id="agt_one", event=make_event())

    with pytest.raises(CentralEventConflictError, match="otro payload"):
        repo.add_event(
            agent_id="agt_one",
            event=make_event(description="Descripción alterada"),
        )

    with sqlite3.connect(repo.database_path) as connection:
        stored = connection.execute(
            "SELECT description FROM events"
        ).fetchall()
    assert stored == [("Detección de prueba",)]


def test_same_event_id_is_allowed_for_different_agents(tmp_path: Path) -> None:
    repo = repository(tmp_path)
    first, first_created = repo.add_event(agent_id="agt_one", event=make_event())
    second, second_created = repo.add_event(agent_id="agt_two", event=make_event())

    assert first_created is second_created is True
    assert first["event_id"] == second["event_id"]
    assert first["agent_id"] == "agt_one"
    assert second["agent_id"] == "agt_two"


def test_payload_hash_is_deterministic_and_normalizes_timestamp() -> None:
    first = make_event(
        evidence={"source_ip": "192.0.2.10", "attempts": 12},
    )
    equivalent_offset = make_event(
        timestamp=datetime(
            2026,
            9,
            27,
            4,
            30,
            tzinfo=timezone(-timedelta(hours=6)),
        ),
        evidence={"attempts": 12, "source_ip": "192.0.2.10"},
    )

    assert event_payload_hash(first) == event_payload_hash(equivalent_offset)
    assert event_payload_hash(first) != event_payload_hash(
        make_event(evidence={"attempts": 13, "source_ip": "192.0.2.10"})
    )


def test_received_at_is_generated_by_central_and_payload_agent_is_ignored(
    tmp_path: Path,
) -> None:
    repo = repository(tmp_path)

    stored, _ = repo.add_event(
        agent_id="agt_authenticated",
        event=make_event(agent_id="agt_untrusted_payload"),
    )

    assert stored["agent_id"] == "agt_authenticated"
    assert stored["received_at"] == "2026-09-27T10:31:00.000000Z"


def test_lists_only_events_for_requested_agent(tmp_path: Path) -> None:
    repo = repository(tmp_path)
    repo.add_event(agent_id="agt_one", event=make_event())
    repo.add_event(
        agent_id="agt_two",
        event=make_event(event_id=UUID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")),
    )

    events = repo.list_events(agent_id="agt_one")

    assert len(events) == 1
    assert events[0]["agent_id"] == "agt_one"
    assert events[0]["event_id"] == str(EVENT_ID)
