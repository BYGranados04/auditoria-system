import sqlite3
from datetime import UTC, datetime

import pytest

from app.core.events import SecurityEvent
from app.storage.event_repository import EventRepository


def build_event() -> SecurityEvent:
    return SecurityEvent(
        hostname="server-test",
        source="test",
        category="detection",
        event_type="TEST_DETECTION",
        severity="high",
        description="Evento de prueba.",
        evidence={
            "source_ip": "192.0.2.10",
        },
    )


def test_read_only_repository_can_query_existing_database(
    tmp_path,
) -> None:
    database = tmp_path / "auditoria.db"

    writable = EventRepository(database)
    writable.initialize()
    writable.add(build_event())

    read_only = EventRepository(
        database,
        read_only=True,
    )

    assert read_only.count() == 1

    events = read_only.list_events()

    assert len(events) == 1
    assert events[0]["event_type"] == "TEST_DETECTION"


def test_read_only_repository_rejects_initialization(
    tmp_path,
) -> None:
    database = tmp_path / "auditoria.db"

    writable = EventRepository(database)
    writable.initialize()

    read_only = EventRepository(
        database,
        read_only=True,
    )

    with pytest.raises(
        RuntimeError,
        match="solo lectura",
    ):
        read_only.initialize()


def test_read_only_repository_rejects_writes(
    tmp_path,
) -> None:
    database = tmp_path / "auditoria.db"

    writable = EventRepository(database)
    writable.initialize()

    writable.add(build_event())

    read_only = EventRepository(
        database,
        read_only=True,
    )

    with pytest.raises(
        sqlite3.OperationalError,
        match="readonly|read-only",
    ):
        read_only.add(build_event())

    with pytest.raises(
        sqlite3.OperationalError,
        match="readonly|read-only",
    ):
        read_only.delete_before(datetime.now(UTC))

    assert writable.count() == 1
