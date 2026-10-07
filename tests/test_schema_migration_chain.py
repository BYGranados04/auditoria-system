"""Cadena de migraciones versionada de auditoria.db (v3→v4→v5) y central.db
(v1→v2→v3). Cada etapa se construye con las funciones de migración reales
de su versión, sin heurísticas de existencia de tablas."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.central.incidents import migrate_incidents_v2
from app.central.repository import CentralEventRepository
from app.storage.event_repository import EventRepository

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)

V4_TABLES = {"incidents", "response_offenses"}
V5_TABLES = {"response_approvals", "forensic_capture_queue"}
CENTRAL_V2_TABLES = {"incidents", "incident_links"}
CENTRAL_V3_TABLES = {"response_actions"}


def tables(path: Path) -> set[str]:
    with sqlite3.connect(path) as connection:
        return {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }


def user_version(path: Path) -> int:
    with sqlite3.connect(path) as connection:
        return int(connection.execute("PRAGMA user_version").fetchone()[0])


# --------------------------------------------------------------------------
# auditoria.db
# --------------------------------------------------------------------------


def build_local(path: Path, version: int) -> None:
    migrations = {
        1: EventRepository._migrate_to_v1,
        2: EventRepository._migrate_to_v2,
        3: EventRepository._migrate_to_v3,
        4: EventRepository._migrate_to_v4,
        5: EventRepository._migrate_to_v5,
    }
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        for step in range(1, version + 1):
            migrations[step](connection)
        connection.execute(f"PRAGMA user_version = {version}")
        connection.commit()
    finally:
        connection.close()


def seed_v3(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            INSERT INTO events (
                event_id, timestamp, hostname, source, category, event_type,
                severity, description, evidence_json, agent_id
            ) VALUES ('evt-v3', ?, 'srv', 'legacy', 'agent', 'AGENT_STARTED',
                      'low', 'Evento v3', '{"x": 1}', 'agent-1')
            """,
            (NOW.isoformat(),),
        )
        connection.execute("INSERT INTO event_outbox (event_id) VALUES ('evt-v3')")
        connection.execute(
            """
            INSERT INTO response_blocks (
                block_id, detection_event_id, response_event_id, hostname,
                target_ip, family, duration_seconds, requested_at, expires_at,
                status
            ) VALUES ('block-v3', 'd', 'r', 'srv', '192.0.2.1', 'ip', 900, ?, ?,
                      'ACTIVE')
            """,
            (NOW.isoformat(), (NOW + timedelta(minutes=15)).isoformat()),
        )


def seed_v4(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            INSERT INTO response_blocks (
                block_id, detection_event_id, response_event_id, hostname,
                target_ip, family, duration_seconds, requested_at, expires_at,
                status, action, protocol, port
            ) VALUES ('block-v4', 'd4', 'r4', 'srv', '192.0.2.2', 'ip', 120, ?, ?,
                      'ACTIVE', 'TEMPORARY_BLOCK_IP_PORT', 'tcp', 22)
            """,
            (NOW.isoformat(), (NOW + timedelta(minutes=2)).isoformat()),
        )
        connection.execute(
            """
            INSERT INTO incidents (
                incident_id, hostname, incident_type, severity, source_ip,
                status, opened_at, last_activity_at, detection_count, updated_at
            ) VALUES ('INC-0000000000000004', 'srv', 'SSH_BRUTE_FORCE_ATTEMPT',
                      'high', '192.0.2.2', 'CONTAINED', ?, ?, 2, ?)
            """,
            (NOW.isoformat(), NOW.isoformat(), NOW.isoformat()),
        )
        connection.execute(
            """
            INSERT INTO response_offenses (
                offense_id, hostname, source_ip, detection_event_id,
                detection_type, occurred_at, recurrence_level,
                selected_duration_seconds
            ) VALUES ('off-v4', 'srv', '192.0.2.2', 'd4',
                      'SSH_BRUTE_FORCE_ATTEMPT', ?, 2, 600)
            """,
            (NOW.isoformat(),),
        )


def assert_v3_data_preserved(repo: EventRepository) -> None:
    assert repo.count() == 1
    assert repo.list_events(limit=5)[0]["evidence"] == {"x": 1}
    legacy = repo.get_response_block("block-v3")
    assert legacy is not None
    assert legacy["status"] == "ACTIVE"
    assert legacy["action"] == "TEMPORARY_BLOCK_IP"
    assert (legacy["protocol"], legacy["port"]) == (None, None)


def assert_v4_data_preserved(repo: EventRepository) -> None:
    block = repo.get_response_block("block-v4")
    assert block is not None
    assert (block["action"], block["protocol"], block["port"]) == (
        "TEMPORARY_BLOCK_IP_PORT",
        "tcp",
        22,
    )
    incident = repo.get_incident("INC-0000000000000004")
    assert incident is not None
    assert (incident["status"], incident["detection_count"]) == ("CONTAINED", 2)
    assert (
        repo.count_response_offenses(
            hostname="srv",
            source_ip="192.0.2.2",
            since=NOW - timedelta(days=1),
            until=NOW + timedelta(days=1),
        )
        == 1
    )


def test_schema_versions_are_explicit() -> None:
    assert EventRepository.SCHEMA_VERSION == 5
    assert CentralEventRepository.SCHEMA_VERSION == 3


def test_local_v3_migrates_through_v4_to_v5_preserving_data(tmp_path: Path) -> None:
    database = tmp_path / "auditoria.db"
    build_local(database, 3)
    seed_v3(database)
    assert not (V4_TABLES | V5_TABLES) & tables(database)

    repo = EventRepository(database)
    repo.initialize()

    assert user_version(database) == 5
    assert (V4_TABLES | V5_TABLES) <= tables(database)
    assert_v3_data_preserved(repo)
    with sqlite3.connect(database) as connection:
        outbox = connection.execute(
            "SELECT status FROM event_outbox WHERE event_id = 'evt-v3'"
        ).fetchone()
    assert outbox == ("pending",)


def test_local_v4_migrates_only_v4_to_v5(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "auditoria.db"
    build_local(database, 4)
    seed_v3(database)
    seed_v4(database)
    assert not V5_TABLES & tables(database)
    executed: list[int] = []

    for version in (1, 2, 3, 4, 5):
        original = getattr(EventRepository, f"_migrate_to_v{version}")

        def tracked(connection, *, _version=version, _original=original):
            executed.append(_version)
            return _original(connection)

        monkeypatch.setattr(
            EventRepository,
            f"_migrate_to_v{version}",
            staticmethod(tracked),
        )

    repo = EventRepository(database)
    repo.initialize()

    assert executed == [5]
    assert user_version(database) == 5
    assert V5_TABLES <= tables(database)
    assert_v3_data_preserved(repo)
    assert_v4_data_preserved(repo)


def test_local_v5_initialize_is_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "auditoria.db"
    repo = EventRepository(database)
    repo.initialize()
    repo.create_response_approval(
        action_id="00000000-0000-0000-0000-000000000005",
        incident_id=None,
        detection_event_id="det-5",
        decision_event_id="dec-5",
        hostname="srv",
        action="TEMPORARY_BLOCK_IP",
        target_ip="192.0.2.5",
        protocol=None,
        port=None,
        duration_seconds=900,
        requested_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )
    calls: list[int] = []
    monkeypatch.setattr(
        EventRepository,
        "_migrate_to_v5",
        staticmethod(lambda connection: calls.append(5)),
    )

    repo.initialize()
    repo.initialize()

    assert calls == []
    assert user_version(database) == 5
    approval = repo.get_response_approval("00000000-0000-0000-0000-000000000005")
    assert approval is not None
    assert approval["status"] == "PENDING_APPROVAL"


@pytest.mark.parametrize("future", [6, 99])
def test_local_future_version_is_rejected(tmp_path: Path, future: int) -> None:
    database = tmp_path / "auditoria.db"
    with sqlite3.connect(database) as connection:
        connection.execute(f"PRAGMA user_version = {future}")

    with pytest.raises(RuntimeError, match="esquema más nuevo"):
        EventRepository(database).initialize()

    assert user_version(database) == future


# --------------------------------------------------------------------------
# central.db
# --------------------------------------------------------------------------


def build_central(path: Path, version: int) -> None:
    connection = sqlite3.connect(path)
    try:
        CentralEventRepository._migrate_to_v1(connection)
        if version >= 2:
            migrate_incidents_v2(connection)
        connection.execute(f"PRAGMA user_version = {version}")
        connection.commit()
    finally:
        connection.close()


def seed_central(path: Path, *, with_incident: bool) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            INSERT INTO events (
                agent_id, event_id, occurred_at, received_at, hostname, source,
                category, event_type, severity, description, evidence_json,
                payload_hash
            ) VALUES ('agent-a', 'evt-1', '2026-10-05T12:00:00.000000Z',
                      '2026-10-05T12:00:01.000000Z', 'srv', 'legacy',
                      'detection', 'SSH_BRUTE_FORCE_ATTEMPT', 'high', 'Previo',
                      '{"source_ip": "192.0.2.9"}', 'hash')
            """
        )
        if with_incident:
            connection.execute(
                """
                INSERT INTO incidents (
                    agent_id, incident_id, hostname, incident_type, severity,
                    source_ip, status, opened_at, last_activity_at,
                    detection_count, last_event_at, last_event_id
                ) VALUES ('agent-a', 'INC-00000000000000C2', 'srv',
                          'SSH_BRUTE_FORCE_ATTEMPT', 'high', '192.0.2.9',
                          'OBSERVED', '2026-10-05T12:00:00.000000Z',
                          '2026-10-05T12:00:00.000000Z', 1,
                          '2026-10-05T12:00:02.000000Z', 'evt-inc')
                """
            )
            connection.execute(
                """
                INSERT INTO incident_links (
                    agent_id, incident_id, event_id, kind, occurred_at
                ) VALUES ('agent-a', 'INC-00000000000000C2', 'evt-1',
                          'detection', '2026-10-05T12:00:00.000000Z')
                """
            )


def test_central_v1_migrates_through_v2_to_v3_preserving_events(
    tmp_path: Path,
) -> None:
    database = tmp_path / "central.db"
    build_central(database, 1)
    seed_central(database, with_incident=False)
    assert not (CENTRAL_V2_TABLES | CENTRAL_V3_TABLES) & tables(database)

    repo = CentralEventRepository(database, clock=lambda: NOW)
    repo.initialize()

    assert user_version(database) == 3
    assert (CENTRAL_V2_TABLES | CENTRAL_V3_TABLES) <= tables(database)
    events = repo.list_events()
    assert [event["event_id"] for event in events] == ["evt-1"]
    assert events[0]["evidence"] == {"source_ip": "192.0.2.9"}


def test_central_v2_migrates_only_v2_to_v3(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "central.db"
    build_central(database, 2)
    seed_central(database, with_incident=True)
    executed: list[str] = []
    import app.central.repository as central_module

    original_v1 = CentralEventRepository._migrate_to_v1
    original_v2 = central_module.migrate_incidents_v2
    original_v3 = central_module.migrate_response_actions_v3
    monkeypatch.setattr(
        CentralEventRepository,
        "_migrate_to_v1",
        staticmethod(lambda c: (executed.append("v1"), original_v1(c))),
    )
    monkeypatch.setattr(
        central_module,
        "migrate_incidents_v2",
        lambda c: (executed.append("v2"), original_v2(c)),
    )
    monkeypatch.setattr(
        central_module,
        "migrate_response_actions_v3",
        lambda c: (executed.append("v3"), original_v3(c)),
    )

    repo = CentralEventRepository(database, clock=lambda: NOW)
    repo.initialize()

    assert executed == ["v3"]
    assert user_version(database) == 3
    assert CENTRAL_V3_TABLES <= tables(database)
    with sqlite3.connect(database) as connection:
        incident = connection.execute(
            "SELECT status, detection_count FROM incidents "
            "WHERE incident_id = 'INC-00000000000000C2'"
        ).fetchone()
        links = connection.execute("SELECT COUNT(*) FROM incident_links").fetchone()
    assert incident == ("OBSERVED", 1)
    assert links == (1,)
    assert len(repo.list_events()) == 1


def test_central_v3_initialize_is_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "central.db"
    repo = CentralEventRepository(database, clock=lambda: NOW)
    repo.initialize()
    seed_central(database, with_incident=True)
    import app.central.repository as central_module

    calls: list[str] = []
    monkeypatch.setattr(
        central_module,
        "migrate_response_actions_v3",
        lambda c: calls.append("v3"),
    )
    monkeypatch.setattr(
        central_module,
        "migrate_incidents_v2",
        lambda c: calls.append("v2"),
    )

    repo.initialize()
    repo.initialize()

    assert calls == []
    assert user_version(database) == 3
    assert len(repo.list_events()) == 1


@pytest.mark.parametrize("future", [4, 42])
def test_central_future_version_is_rejected(tmp_path: Path, future: int) -> None:
    database = tmp_path / "central.db"
    with sqlite3.connect(database) as connection:
        connection.execute(f"PRAGMA user_version = {future}")

    with pytest.raises(RuntimeError, match="esquema más nuevo"):
        CentralEventRepository(database).initialize()

    assert user_version(database) == future
