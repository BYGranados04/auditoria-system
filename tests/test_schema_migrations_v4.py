from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from app.central.repository import CentralEventRepository
from app.core.events import SecurityEvent
from app.response.firewall import NftablesFirewallPlanner, TemporaryBlockPlan
from app.response.recovery import ResponseRecoveryManager
from app.storage.event_repository import EventRepository

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)


def create_v3_database(path: Path) -> None:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        EventRepository._migrate_to_v1(connection)
        EventRepository._migrate_to_v2(connection)
        EventRepository._migrate_to_v3(connection)
        connection.execute("PRAGMA user_version = 3")
        connection.execute(
            """
            INSERT INTO response_blocks (
                block_id, detection_event_id, response_event_id, hostname,
                target_ip, family, duration_seconds, requested_at, applied_at,
                expires_at, status
            ) VALUES (?, ?, ?, 'srv', '192.168.1.50', 'ip', 900, ?, ?, ?, 'ACTIVE')
            """,
            (
                "legacy-block",
                str(uuid4()),
                str(uuid4()),
                NOW.isoformat(),
                NOW.isoformat(),
                (NOW + timedelta(seconds=900)).isoformat(),
            ),
        )
        connection.execute(
            """
            INSERT INTO events (
                event_id, timestamp, hostname, source, category, event_type,
                severity, description, evidence_json
            ) VALUES (?, ?, 'srv', 'legacy', 'agent', 'AGENT_STARTED', 'low',
                      'Evento previo', '{}')
            """,
            (str(uuid4()), NOW.isoformat()),
        )
        connection.commit()
    finally:
        connection.close()


class RecordingBackend:
    def __init__(self) -> None:
        self.added: list[object] = []
        self.port_prepare_calls = 0

    def prepare(self) -> bool:
        return False

    def prepare_port_blocking(self) -> bool:
        self.port_prepare_calls += 1
        return False

    def add_temporary_block(self, plan) -> None:
        self.added.append(plan)


def test_v3_database_migrates_without_losing_events_or_blocks(tmp_path: Path) -> None:
    database = tmp_path / "auditoria.db"
    create_v3_database(database)
    repo = EventRepository(database)

    repo.initialize()
    repo.initialize()

    assert repo.schema_version() == 5
    assert repo.count() == 1
    block = repo.get_response_block("legacy-block")
    assert block is not None
    assert block["status"] == "ACTIVE"
    assert block["action"] == "TEMPORARY_BLOCK_IP"
    assert block["protocol"] is None
    assert block["port"] is None
    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    assert {
        "incidents",
        "response_offenses",
        "response_approvals",
        "forensic_capture_queue",
    } <= tables


def test_legacy_active_block_is_restored_exactly_as_before(tmp_path: Path) -> None:
    database = tmp_path / "auditoria.db"
    create_v3_database(database)
    repo = EventRepository(database)
    repo.initialize()
    backend = RecordingBackend()

    summary = ResponseRecoveryManager(
        repository=repo,
        backend=backend,  # type: ignore[arg-type]
        planner=NftablesFirewallPlanner(),
    ).recover(now=NOW + timedelta(seconds=300))

    assert summary.restored_count == 1
    assert backend.port_prepare_calls == 0
    assert backend.added == [
        TemporaryBlockPlan(family="ip", target_ip="192.168.1.50", duration_seconds=600)
    ]


def test_central_v1_database_migrates_to_v2_preserving_events(tmp_path: Path) -> None:
    database = tmp_path / "central.db"
    connection = sqlite3.connect(database)
    CentralEventRepository._migrate_to_v1(connection)
    connection.execute("PRAGMA user_version = 1")
    connection.commit()
    connection.close()
    repo = CentralEventRepository(database, clock=lambda: NOW)
    repo.add_event(
        agent_id="agent-a",
        event=SecurityEvent(
            timestamp=NOW,
            hostname="srv",
            source="legacy",
            category="detection",
            event_type="SSH_BRUTE_FORCE_ATTEMPT",
            severity="high",
            description="Evento previo",
            evidence={"source_ip": "192.0.2.10"},
        ),
    )

    with sqlite3.connect(database) as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }

    assert version == 3
    assert {"events", "incidents", "incident_links", "response_actions"} <= tables
    assert len(repo.list_events()) == 1
