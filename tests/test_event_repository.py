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
