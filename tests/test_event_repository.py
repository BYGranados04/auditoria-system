import sqlite3
from pathlib import Path

import pytest

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
    assert repo.schema_version() == 2


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


def test_initialize_is_idempotent(tmp_path: Path) -> None:
    repo = repository(tmp_path)

    event = make_event()
    repo.add(event)

    repo.initialize()
    repo.initialize()

    assert repo.schema_version() == 2
    assert repo.count() == 1


def test_migrates_existing_v0_database_without_losing_events(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "auditoria.db"

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                hostname TEXT NOT NULL,
                source TEXT NOT NULL,
                category TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                created_at TEXT NOT NULL
                    DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        connection.execute(
            """
            INSERT INTO events (
                event_id,
                timestamp,
                hostname,
                source,
                category,
                event_type,
                severity,
                description,
                evidence_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "legacy-event",
                "2026-09-23T03:00:00Z",
                "legacy-server",
                "continuous-agent",
                "network",
                "PORT_OPENED",
                "medium",
                "Evento existente",
                '{"port": "tcp:127.0.0.1:9000"}',
            ),
        )

        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0

    repo = EventRepository(database_path)
    repo.initialize()

    assert repo.schema_version() == 2
    assert repo.count() == 1

    events = repo.list_events()

    assert events[0]["event_id"] == "legacy-event"
    assert events[0]["event_type"] == "PORT_OPENED"


def test_rejects_database_from_future_schema(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "auditoria.db"

    with sqlite3.connect(database_path) as connection:
        connection.execute("PRAGMA user_version = 3")

    repo = EventRepository(database_path)

    with pytest.raises(
        RuntimeError,
        match="esquema más nuevo",
    ):
        repo.initialize()


def test_filters_events_by_category(tmp_path: Path) -> None:
    repo = repository(tmp_path)

    network = make_event()
    repo.add(network)

    agent = SecurityEvent(
        hostname="server-test",
        source="test",
        category="agent",
        event_type="AGENT_STARTED",
        severity="low",
        description="Agente iniciado",
        evidence={},
    )
    repo.add(agent)

    events = repo.list_events(category="network")

    assert len(events) == 1
    assert events[0]["category"] == "network"


def test_retention_counts_and_deletes_old_events(
    tmp_path: Path,
) -> None:
    from datetime import UTC, datetime

    repo = repository(tmp_path)

    old_event = make_event()
    old_event.timestamp = datetime(2026, 1, 1, tzinfo=UTC)

    recent_event = make_event()
    recent_event.timestamp = datetime(2026, 9, 1, tzinfo=UTC)

    repo.add(old_event)
    repo.add(recent_event)

    cutoff = datetime(2026, 6, 1, tzinfo=UTC)

    assert repo.count_before(cutoff) == 1

    deleted = repo.delete_before(cutoff)

    assert deleted == 1
    assert repo.count() == 1

    remaining = repo.list_events()

    assert remaining[0]["event_id"] == str(recent_event.event_id)


def test_migrates_v1_database_to_v2_without_losing_events(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "auditoria.db"

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                hostname TEXT NOT NULL,
                source TEXT NOT NULL,
                category TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                created_at TEXT NOT NULL
                    DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        connection.execute(
            """
            INSERT INTO events (
                event_id,
                timestamp,
                hostname,
                source,
                category,
                event_type,
                severity,
                description,
                evidence_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "event-before-v2",
                "2026-09-23T07:00:00Z",
                "auditoria-server",
                "detection-engine",
                "detection",
                "SSH_USER_ENUMERATION_ATTEMPT",
                "high",
                "Evento anterior a schema v2",
                '{"source_ip": "192.168.1.50"}',
            ),
        )

        connection.execute("PRAGMA user_version = 1")

    repo = EventRepository(database_path)
    repo.initialize()

    assert repo.schema_version() == 2
    assert repo.count() == 1

    events = repo.list_events()

    assert events[0]["event_id"] == "event-before-v2"

    with sqlite3.connect(database_path) as connection:
        table = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'response_blocks'
            """
        ).fetchone()

        assert table is not None

        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(response_blocks)")
        }

        assert {
            "block_id",
            "detection_event_id",
            "response_event_id",
            "execution_event_id",
            "hostname",
            "target_ip",
            "family",
            "duration_seconds",
            "requested_at",
            "applied_at",
            "expires_at",
            "status",
            "last_error",
            "created_at",
            "updated_at",
        } <= columns

        indexes = {
            row[1] for row in connection.execute("PRAGMA index_list(response_blocks)")
        }

        assert "idx_response_blocks_status" in indexes
        assert "idx_response_blocks_expires_at" in indexes
        assert "idx_response_blocks_target" in indexes
        assert "idx_response_blocks_live_target" in indexes


def test_v2_prevents_duplicate_live_blocks(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "auditoria.db"

    repo = EventRepository(database_path)
    repo.initialize()

    with sqlite3.connect(database_path) as connection:
        values = (
            "block-1",
            "detection-1",
            "response-1",
            "auditoria-server",
            "192.168.1.50",
            "ip",
            900,
            "2026-09-23T07:10:00Z",
            "2026-09-23T07:25:00Z",
            "ACTIVE",
        )

        connection.execute(
            """
            INSERT INTO response_blocks (
                block_id,
                detection_event_id,
                response_event_id,
                hostname,
                target_ip,
                family,
                duration_seconds,
                requested_at,
                expires_at,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            values,
        )

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO response_blocks (
                    block_id,
                    detection_event_id,
                    response_event_id,
                    hostname,
                    target_ip,
                    family,
                    duration_seconds,
                    requested_at,
                    expires_at,
                    status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "block-2",
                    "detection-2",
                    "response-2",
                    "auditoria-server",
                    "192.168.1.50",
                    "ip",
                    900,
                    "2026-09-23T07:11:00Z",
                    "2026-09-23T07:26:00Z",
                    "PENDING",
                ),
            )
