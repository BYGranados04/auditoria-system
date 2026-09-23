from pathlib import Path

from app.core.events import SecurityEvent
from app.storage.event_repository import EventRepository


def make_event(
    *,
    severity: str = "medium",
    event_type: str = "PORT_OPENED",
    hostname: str = "server-test",
) -> SecurityEvent:
    return SecurityEvent(
        hostname=hostname,
        source="test",
        category="network",
        event_type=event_type,
        severity=severity,
        description="Evento de prueba",
        evidence={
            "port": "tcp:127.0.0.1:8000",
        },
    )


def repository(tmp_path: Path) -> EventRepository:
    repo = EventRepository(tmp_path / "auditoria.db")
    repo.initialize()
    return repo


def test_initializes_database(tmp_path: Path) -> None:
    repo = repository(tmp_path)

    assert repo.database_path.exists()
    assert repo.count() == 0


def test_persists_event(tmp_path: Path) -> None:
    repo = repository(tmp_path)

    event = make_event()
    repo.add(event)

    assert repo.count() == 1

    stored = repo.list_events()

    assert len(stored) == 1
    assert stored[0]["event_id"] == str(event.event_id)
    assert stored[0]["event_type"] == "PORT_OPENED"
    assert stored[0]["severity"] == "medium"
    assert stored[0]["evidence"] == {"port": "tcp:127.0.0.1:8000"}


def test_filters_events(tmp_path: Path) -> None:
    repo = repository(tmp_path)

    repo.add(
        make_event(
            severity="high",
            event_type="SSH_ATTACK",
            hostname="server-a",
        )
    )
    repo.add(
        make_event(
            severity="low",
            event_type="PORT_CLOSED",
            hostname="server-b",
        )
    )

    high = repo.list_events(
        severity="high",
    )
    ssh = repo.list_events(
        event_type="SSH_ATTACK",
    )
    server_b = repo.list_events(
        hostname="server-b",
    )

    assert len(high) == 1
    assert high[0]["event_type"] == "SSH_ATTACK"

    assert len(ssh) == 1
    assert ssh[0]["severity"] == "high"

    assert len(server_b) == 1
    assert server_b[0]["event_type"] == "PORT_CLOSED"


def test_limits_results(tmp_path: Path) -> None:
    repo = repository(tmp_path)

    for _ in range(5):
        repo.add(make_event())

    events = repo.list_events(limit=2)

    assert len(events) == 2
    assert repo.count() == 5


def test_statistics_groups_events(tmp_path: Path) -> None:
    repo = repository(tmp_path)

    repo.add(
        make_event(
            severity="high",
            event_type="SSH_ATTACK",
        )
    )
    repo.add(
        make_event(
            severity="high",
            event_type="SSH_ATTACK",
        )
    )
    repo.add(
        make_event(
            severity="low",
            event_type="PORT_CLOSED",
        )
    )

    stats = repo.statistics()

    assert stats["total"] == 3
    assert stats["by_severity"]["high"] == 2
    assert stats["by_severity"]["low"] == 1
    assert stats["by_event_type"]["SSH_ATTACK"] == 2
    assert stats["by_event_type"]["PORT_CLOSED"] == 1


def test_filters_events_by_time_range(tmp_path: Path) -> None:
    from datetime import UTC, datetime

    repo = repository(tmp_path)

    first = make_event()
    first.timestamp = datetime(
        2026,
        9,
        23,
        3,
        10,
        tzinfo=UTC,
    )

    second = make_event()
    second.timestamp = datetime(
        2026,
        9,
        23,
        3,
        20,
        tzinfo=UTC,
    )

    third = make_event()
    third.timestamp = datetime(
        2026,
        9,
        23,
        3,
        30,
        tzinfo=UTC,
    )

    repo.add(first)
    repo.add(second)
    repo.add(third)

    events = repo.list_events(
        since=datetime(
            2026,
            9,
            23,
            3,
            15,
            tzinfo=UTC,
        ),
        until=datetime(
            2026,
            9,
            23,
            3,
            25,
            tzinfo=UTC,
        ),
    )

    assert len(events) == 1
    assert events[0]["event_id"] == str(second.event_id)
