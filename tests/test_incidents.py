from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.agent.continuous_agent import ContinuousAgent
from app.central.repository import CentralEventRepository
from app.core.config import AgentSettings
from app.core.events import SecurityEvent
from app.detection.ssh_collector import SSHJournalBatch, SSHJournalRecord
from app.response.executor import ResponseExecutor
from app.response.incidents import (
    INCIDENT_ID_PATTERN,
    IncidentManager,
)
from app.response.models import ResponseDecision, ResponseExecutionResult
from app.storage.event_repository import EventRepository

BASE = datetime(2026, 10, 5, 10, 30, 0, tzinfo=UTC)


class FakeBackend:
    def __init__(self) -> None:
        self.added: list[object] = []
        self.prepare_calls = 0
        self.port_prepare_calls = 0

    def prepare(self) -> bool:
        self.prepare_calls += 1
        return False

    def prepare_port_blocking(self) -> bool:
        self.port_prepare_calls += 1
        return False

    def add_temporary_block(self, plan) -> None:
        self.added.append(plan)

    def remove_block(self, plan) -> None:  # pragma: no cover - no se usa
        raise AssertionError("No se esperaba remover bloqueos.")


class ForbiddenBackend(FakeBackend):
    def prepare(self) -> bool:
        raise AssertionError("audit_only nunca debe tocar el firewall.")

    def prepare_port_blocking(self) -> bool:
        raise AssertionError("audit_only nunca debe tocar el firewall.")

    def add_temporary_block(self, plan) -> None:
        raise AssertionError("audit_only nunca debe tocar el firewall.")


class FakeResolver:
    def __init__(self, protected: set[str] | None = None) -> None:
        self.protected = protected or set()

    def resolve(self):
        return SimpleNamespace(protected_ips=set(self.protected))


def build_agent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    protected: set[str] | None = None,
    **overrides: object,
) -> ContinuousAgent:
    values: dict[str, object] = {
        "interval": 1,
        "state_dir": tmp_path / "state",
        "log_dir": tmp_path / "logs",
        "identity_file": tmp_path / "agent-identity.json",
    }
    values.update(overrides)
    settings = AgentSettings(**values)  # type: ignore[arg-type]
    monkeypatch.setattr(
        ContinuousAgent,
        "_protection_resolver",
        lambda self: FakeResolver(protected),
    )
    agent = ContinuousAgent(interval=1, settings=settings)
    agent.evidence_collector._runner = lambda command, _timeout: (
        0,
        f"{command[0]} salida\n",
        "",
    )
    agent.evidence_collector._process_provider = lambda _ip: []
    return agent


def invalid_user_records(
    start: datetime,
    *,
    source_ip: str = "192.168.1.50",
    count: int = 5,
    prefix: str = "c",
) -> list[SSHJournalRecord]:
    return [
        SSHJournalRecord(
            cursor=f"{prefix}-{index}",
            timestamp=start + timedelta(seconds=4 * index),
            event_type="SSH_INVALID_USER",
            severity="medium",
            description="Usuario SSH inexistente.",
            evidence={
                "user": f"usuario-{index}",
                "ip": source_ip,
                "port": str(50000 + index),
            },
        )
        for index in range(count)
    ]


def auth_failure_records(
    start: datetime,
    *,
    source_ip: str = "192.168.1.50",
) -> list[SSHJournalRecord]:
    return [
        SSHJournalRecord(
            cursor=f"f-{index}",
            timestamp=start + timedelta(seconds=index),
            event_type="SSH_AUTH_FAILURE",
            severity="medium",
            description="Fallo de autenticación SSH.",
            evidence={
                "user": "root",
                "ip": source_ip,
                "port": str(40000 + index),
                "method": "password",
            },
        )
        for index in range(10)
    ]


def feed(
    agent: ContinuousAgent,
    monkeypatch: pytest.MonkeyPatch,
    records: list[SSHJournalRecord],
) -> None:
    monkeypatch.setattr(
        agent.ssh_collector,
        "read_after",
        lambda _cursor: SSHJournalBatch(records=records, cursor="final"),
    )
    agent._collect_ssh_events({"ssh_journal_cursor": "inicio"}, {})


def local_repository(agent: ContinuousAgent) -> EventRepository:
    return EventRepository(agent.settings.database_file)


def incident_events(agent: ContinuousAgent) -> list[dict]:
    events = local_repository(agent).list_events(category="incident", limit=100)
    return sorted(events, key=lambda event: event["timestamp"])


def only_incident(agent: ContinuousAgent) -> dict:
    opened = [
        event
        for event in incident_events(agent)
        if event["event_type"] == "INCIDENT_OPENED"
    ]
    assert len(opened) == 1
    incident = local_repository(agent).get_incident(
        opened[0]["evidence"]["incident_id"]
    )
    assert incident is not None
    return incident


def test_high_ssh_detection_creates_incident_with_complete_timeline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent = build_agent(tmp_path, monkeypatch, evidence_enabled=True)

    feed(agent, monkeypatch, invalid_user_records(BASE))
    # La captura ampliada se ejecuta después de la contención (tarea diferida).
    assert agent.process_forensic_queue() == 1

    incident = only_incident(agent)
    assert INCIDENT_ID_PATTERN.fullmatch(incident["incident_id"])
    assert incident["incident_type"] == "SSH_USER_ENUMERATION_ATTEMPT"
    assert incident["severity"] == "high"
    assert incident["source_ip"] == "192.168.1.50"
    assert incident["status"] == "OBSERVED"
    assert incident["detection_count"] == 1
    assert incident["last_action"] == "RECOMMEND_BLOCK_IP"

    events = incident_events(agent)
    assert [event["event_type"] for event in events] == [
        "INCIDENT_OPENED",
        "INCIDENT_UPDATED",
        "INCIDENT_UPDATED",
    ]
    links = [link for event in events for link in event["evidence"]["links"]]
    kinds = [link["kind"] for link in links]
    assert kinds == ["event"] * 5 + ["detection", "decision", "execution", "evidence"]

    repo = local_repository(agent)
    by_id = {event["event_id"]: event for event in repo.list_events(limit=200)}
    assert all(link["event_id"] in by_id for link in links)
    assert [by_id[link["event_id"]]["event_type"] for link in links] == [
        "SSH_INVALID_USER",
        "SSH_INVALID_USER",
        "SSH_INVALID_USER",
        "SSH_INVALID_USER",
        "SSH_INVALID_USER",
        "SSH_USER_ENUMERATION_ATTEMPT",
        "RESPONSE_DECISION",
        "RESPONSE_EXECUTION",
        "FORENSIC_EVIDENCE_CAPTURED",
    ]
    decision = by_id[links[6]["event_id"]]["evidence"]
    assert decision["incident_id"] == incident["incident_id"]
    assert decision["recurrence_level"] == 1
    assert decision["previous_incidents"] == 0
    evidence_dir = agent.settings.evidence_dir / links[5]["event_id"]
    assert (evidence_dir / "metadata.json").is_file()
    assert (evidence_dir / "quick_snapshot.json").is_file()
    assert agent.process_forensic_queue() == 0


def test_detections_from_same_source_are_grouped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent = build_agent(tmp_path, monkeypatch)

    feed(agent, monkeypatch, invalid_user_records(BASE))
    feed(agent, monkeypatch, auth_failure_records(BASE + timedelta(minutes=2)))

    incident = only_incident(agent)
    assert incident["detection_count"] == 2
    assert incident["incident_type"] == "SSH_USER_ENUMERATION_ATTEMPT"
    detections = [
        link
        for event in incident_events(agent)
        for link in event["evidence"]["links"]
        if link["kind"] == "detection"
    ]
    assert len(detections) == 2


def test_different_sources_create_different_incidents(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent = build_agent(tmp_path, monkeypatch)

    feed(agent, monkeypatch, invalid_user_records(BASE))
    feed(
        agent,
        monkeypatch,
        invalid_user_records(
            BASE + timedelta(seconds=30),
            source_ip="192.168.1.77",
            prefix="otro",
        ),
    )

    opened = [
        event["evidence"]
        for event in incident_events(agent)
        if event["event_type"] == "INCIDENT_OPENED"
    ]
    assert {item["source_ip"] for item in opened} == {"192.168.1.50", "192.168.1.77"}
    assert len({item["incident_id"] for item in opened}) == 2


def test_inactive_incident_is_closed_and_new_activity_opens_another(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent = build_agent(tmp_path, monkeypatch, incident_grouping_seconds=600)

    feed(agent, monkeypatch, invalid_user_records(BASE))
    feed(
        agent,
        monkeypatch,
        invalid_user_records(BASE + timedelta(hours=1), prefix="tarde"),
    )

    events = incident_events(agent)
    opened = [event for event in events if event["event_type"] == "INCIDENT_OPENED"]
    closed = [
        event
        for event in events
        if event["event_type"] == "INCIDENT_UPDATED"
        and event["evidence"]["status"] == "CLOSED"
    ]
    assert len(opened) == 2
    assert len(closed) == 1
    first = local_repository(agent).get_incident(opened[0]["evidence"]["incident_id"])
    assert first is not None
    assert first["status"] == "CLOSED"
    assert first["closed_at"] is not None


def test_audit_only_never_executes_firewall_but_records_incident(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent = build_agent(
        tmp_path,
        monkeypatch,
        response_mode="audit_only",
        allow_temporary_ip_block=True,
        allow_temporary_ip_port_block=True,
        response_block_scope="ip_port",
    )
    agent.response_executor = ResponseExecutor(
        agent.response_policy,
        dry_run=False,
        repository=local_repository(agent),
        backend=ForbiddenBackend(),  # type: ignore[arg-type]
        protection_resolver=FakeResolver(),  # type: ignore[arg-type]
    )

    feed(agent, monkeypatch, invalid_user_records(BASE))

    incident = only_incident(agent)
    assert incident["status"] == "OBSERVED"
    assert incident["last_action"] == "RECOMMEND_BLOCK_IP_PORT"
    assert local_repository(agent).list_live_response_blocks(now=BASE) == []


def test_assisted_mode_leaves_incident_open_pending_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent = build_agent(
        tmp_path,
        monkeypatch,
        response_mode="assisted",
        allow_temporary_ip_block=True,
    )
    agent.response_executor = ResponseExecutor(
        agent.response_policy,
        dry_run=False,
        repository=local_repository(agent),
        backend=ForbiddenBackend(),  # type: ignore[arg-type]
        protection_resolver=FakeResolver(),  # type: ignore[arg-type]
    )

    feed(agent, monkeypatch, invalid_user_records(BASE))

    incident = only_incident(agent)
    assert incident["status"] == "OPEN"
    responses = local_repository(agent).list_events(
        event_type="RESPONSE_DECISION",
        limit=5,
    )
    assert responses[0]["evidence"]["approval_required"] is True


def test_automatic_port_block_contains_incident_and_escalates_on_recurrence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent = build_agent(
        tmp_path,
        monkeypatch,
        response_mode="automatic",
        response_block_scope="ip_port",
        allow_temporary_ip_port_block=True,
        response_escalation_enabled=True,
    )
    backend = FakeBackend()
    agent.response_executor = ResponseExecutor(
        agent.response_policy,
        dry_run=False,
        repository=local_repository(agent),
        backend=backend,  # type: ignore[arg-type]
        protection_resolver=FakeResolver(),  # type: ignore[arg-type]
        clock=lambda: BASE + timedelta(seconds=30),
    )

    feed(agent, monkeypatch, invalid_user_records(BASE))
    local_repository(agent).expire_response_blocks(now=BASE + timedelta(minutes=5))
    agent.response_executor.clock = lambda: BASE + timedelta(minutes=10)
    feed(
        agent,
        monkeypatch,
        invalid_user_records(BASE + timedelta(minutes=9), prefix="reincide"),
    )

    incident = only_incident(agent)
    assert incident["status"] == "CONTAINED"
    assert incident["recurrence_level"] == 2
    assert [
        (plan.target_ip, plan.protocol, plan.port, plan.duration_seconds)
        for plan in backend.added
    ] == [("192.168.1.50", "tcp", 22, 120), ("192.168.1.50", "tcp", 22, 600)]
    executions = local_repository(agent).list_events(
        event_type="RESPONSE_EXECUTION",
        limit=10,
    )
    assert {event["evidence"]["status"] for event in executions} == {"EXECUTED"}


def test_automatic_respects_dynamic_protection_and_does_not_escalate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent = build_agent(
        tmp_path,
        monkeypatch,
        protected={"192.168.1.50"},
        response_mode="automatic",
        allow_temporary_ip_block=True,
        response_escalation_enabled=True,
    )
    backend = FakeBackend()
    agent.response_executor = ResponseExecutor(
        agent.response_policy,
        dry_run=False,
        repository=local_repository(agent),
        backend=backend,  # type: ignore[arg-type]
        protection_resolver=FakeResolver({"192.168.1.50"}),  # type: ignore[arg-type]
    )

    feed(agent, monkeypatch, invalid_user_records(BASE))

    assert backend.added == []
    incident = only_incident(agent)
    assert incident["status"] == "OBSERVED"
    # La decisión conserva el comportamiento histórico (TEMPORARY_BLOCK_IP) y
    # el ejecutor la rechaza por protección dinámica.
    assert incident["last_action"] == "TEMPORARY_BLOCK_IP"
    assert incident["last_execution_status"] == "SKIPPED"
    with local_repository(agent)._connection() as connection:
        offenses = connection.execute(
            "SELECT COUNT(*) FROM response_offenses"
        ).fetchone()[0]
    assert offenses == 0


def test_incidents_can_be_disabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent = build_agent(tmp_path, monkeypatch, incidents_enabled=False)

    feed(agent, monkeypatch, invalid_user_records(BASE))

    assert incident_events(agent) == []
    responses = local_repository(agent).list_events(category="response", limit=10)
    assert len(responses) == 2


@pytest.mark.parametrize(
    ("decision_kwargs", "result_status", "expected"),
    [
        (
            {"action": "TEMPORARY_BLOCK_IP", "mode": "automatic"},
            "EXECUTED",
            "CONTAINED",
        ),
        ({"action": "TEMPORARY_BLOCK_IP", "mode": "automatic"}, "FAILED", "OPEN"),
        ({"action": "TEMPORARY_BLOCK_IP", "mode": "automatic"}, "SKIPPED", "OBSERVED"),
        ({"action": "RECOMMEND_BLOCK_IP", "mode": "audit_only"}, "SKIPPED", "OBSERVED"),
        (
            {
                "action": "RECOMMEND_BLOCK_IP",
                "mode": "assisted",
                "approval_required": True,
            },
            "SKIPPED",
            "OPEN",
        ),
        ({"action": "RECOMMEND_BLOCK_IP", "mode": "automatic"}, "SKIPPED", "OPEN"),
        ({"action": "NO_ACTION", "mode": "automatic"}, "SKIPPED", "OBSERVED"),
    ],
)
def test_incident_status_taxonomy(
    decision_kwargs: dict,
    result_status: str,
    expected: str,
) -> None:
    detection_id = uuid4()
    decision = ResponseDecision(
        detection_event_id=detection_id,
        hostname="srv",
        target_ip="192.168.1.50",
        reason="prueba",
        **decision_kwargs,
    )
    result = ResponseExecutionResult(
        detection_event_id=detection_id,
        action=decision.action,
        status=result_status,
        dry_run=False,
        executed=result_status == "EXECUTED",
        reason="prueba",
    )

    assert IncidentManager.status_for(decision, result) == expected


# --------------------------------------------------------------------------
# Proyección central
# --------------------------------------------------------------------------


def sync_to_central(agent: ContinuousAgent, central: CentralEventRepository) -> None:
    rows = local_repository(agent).list_events(limit=1000)
    events = [
        SecurityEvent(
            event_id=row["event_id"],
            timestamp=row["timestamp"],
            hostname=row["hostname"],
            source=row["source"],
            category=row["category"],
            event_type=row["event_type"],
            severity=row["severity"],
            description=row["description"],
            evidence=row["evidence"],
        )
        for row in sorted(rows, key=lambda item: item["timestamp"])
    ]
    central.add_events(agent_id="agent-a", events=tuple(events))


def test_central_projects_incident_and_builds_timeline_without_duplication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.central.incidents import CentralIncidentReader

    agent = build_agent(tmp_path, monkeypatch, evidence_enabled=True)
    feed(agent, monkeypatch, invalid_user_records(BASE))
    agent.process_forensic_queue()
    central = CentralEventRepository(tmp_path / "central" / "central.db")

    sync_to_central(agent, central)
    sync_to_central(agent, central)

    reader = CentralIncidentReader(central.database_path)
    items, total = reader.list_incidents(agent_ids=None)
    assert total == 1
    incident = items[0]
    assert incident["status"] == "OBSERVED"
    assert incident["agent_id"] == "agent-a"
    timeline = reader.timeline(agent_id="agent-a", incident_id=incident["incident_id"])
    assert [entry["kind"] for entry in timeline] == [
        "event",
        "event",
        "event",
        "event",
        "event",
        "detection",
        "decision",
        "execution",
        "evidence",
    ]
    assert all(entry["available"] for entry in timeline)
    timestamps = [entry["timestamp"] for entry in timeline]
    assert timestamps == sorted(timestamps)

    import sqlite3

    with sqlite3.connect(central.database_path) as connection:
        links = connection.execute("SELECT COUNT(*) FROM incident_links").fetchone()[0]
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(incident_links)")
        }
    assert links == 9
    assert "evidence_json" not in columns
    assert "description" not in columns


def test_central_ignores_invalid_or_stale_incident_payloads(tmp_path: Path) -> None:
    from app.central.incidents import CentralIncidentReader

    central = CentralEventRepository(tmp_path / "central.db")
    incident_id = "INC-00112233445566AA"
    base = {
        "incident_id": incident_id,
        "incident_type": "SSH_BRUTE_FORCE_ATTEMPT",
        "severity": "high",
        "source_ip": "192.0.2.10",
        "opened_at": BASE.isoformat(),
        "last_activity_at": BASE.isoformat(),
        "closed_at": None,
        "detection_count": 1,
        "recurrence_level": None,
        "last_action": None,
        "last_execution_status": None,
        "links": [],
    }

    def incident_event(at: datetime, status: str, **extra: object) -> SecurityEvent:
        return SecurityEvent(
            timestamp=at,
            hostname="srv",
            source="incident-manager",
            category="incident",
            event_type="INCIDENT_UPDATED",
            severity="low",
            description="incidente",
            evidence={**base, "status": status, **extra},
        )

    central.add_events(
        agent_id="agent-a",
        events=(
            incident_event(BASE + timedelta(minutes=2), "CONTAINED"),
            incident_event(BASE + timedelta(minutes=1), "OPEN"),
            incident_event(BASE + timedelta(minutes=3), "HACKED"),
            incident_event(
                BASE + timedelta(minutes=4),
                "CLOSED",
                incident_id="../../etc/passwd",
            ),
            incident_event(
                BASE + timedelta(minutes=5),
                "CONTAINED",
                links=[
                    {"event_id": "no-uuid", "kind": "event", "occurred_at": "x"},
                    {"event_id": str(uuid4()), "kind": "otro", "occurred_at": "x"},
                ],
            ),
        ),
    )

    items, total = CentralIncidentReader(central.database_path).list_incidents(
        agent_ids=None
    )
    assert total == 1
    assert items[0]["incident_id"] == incident_id
    assert items[0]["status"] == "CONTAINED"
    assert (
        CentralIncidentReader(central.database_path).timeline(
            agent_id="agent-a",
            incident_id=incident_id,
        )
        == []
    )


def test_multiple_detections_of_same_attack_do_not_duplicate_block_or_offenses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent = build_agent(
        tmp_path,
        monkeypatch,
        response_mode="automatic",
        response_block_scope="ip_port",
        allow_temporary_ip_port_block=True,
        response_escalation_enabled=True,
    )
    backend = FakeBackend()
    agent.response_executor = ResponseExecutor(
        agent.response_policy,
        dry_run=False,
        repository=local_repository(agent),
        backend=backend,  # type: ignore[arg-type]
        protection_resolver=FakeResolver(),  # type: ignore[arg-type]
        clock=lambda: BASE + timedelta(seconds=30),
    )

    # Enumeración y fuerza bruta del mismo origen en el mismo ciclo.
    feed(
        agent,
        monkeypatch,
        [
            *invalid_user_records(BASE),
            *auth_failure_records(BASE + timedelta(seconds=20)),
        ],
    )

    incident = only_incident(agent)
    assert incident["detection_count"] == 2
    assert incident["status"] == "CONTAINED"
    assert len(backend.added) == 1
    statuses = [
        event["evidence"]["status"]
        for event in local_repository(agent).list_events(
            event_type="RESPONSE_EXECUTION", limit=10
        )
    ]
    assert sorted(statuses) == ["EXECUTED", "SKIPPED"]
    with local_repository(agent)._connection() as connection:
        offenses = connection.execute(
            "SELECT COUNT(*) FROM response_offenses"
        ).fetchone()[0]
    assert offenses == 1


@pytest.mark.parametrize("mode", ["audit_only", "automatic"])
def test_tailscale_source_keeps_decision_and_is_not_escalated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    agent = build_agent(
        tmp_path,
        monkeypatch,
        response_mode=mode,
        allow_temporary_ip_block=True,
        response_escalation_enabled=True,
    )
    backend = FakeBackend()
    agent.response_executor = ResponseExecutor(
        agent.response_policy,
        dry_run=mode != "automatic",
        repository=local_repository(agent),
        backend=backend,  # type: ignore[arg-type]
        protection_resolver=FakeResolver(),  # type: ignore[arg-type]
    )

    feed(agent, monkeypatch, invalid_user_records(BASE, source_ip="100.64.1.2"))

    decision = local_repository(agent).list_events(
        event_type="RESPONSE_DECISION", limit=5
    )[0]["evidence"]
    execution = local_repository(agent).list_events(
        event_type="RESPONSE_EXECUTION", limit=5
    )[0]["evidence"]
    expected = "TEMPORARY_BLOCK_IP" if mode == "automatic" else "RECOMMEND_BLOCK_IP"
    assert decision["action"] == expected
    assert decision["target_ip"] == "100.64.1.2"
    assert execution["status"] == "SKIPPED"
    if mode == "automatic":
        assert execution["protection_rejected"] is True
        assert "Tailscale" in execution["reason"]
    assert backend.added == []
    with local_repository(agent)._connection() as connection:
        offenses = connection.execute(
            "SELECT COUNT(*) FROM response_offenses"
        ).fetchone()[0]
    assert offenses == 0


def test_deferred_task_errors_do_not_stop_the_agent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent = build_agent(tmp_path, monkeypatch)

    def broken() -> int:
        raise RuntimeError("fallo simulado")

    monkeypatch.setattr(agent, "process_response_approvals", broken)
    calls: list[int] = []
    monkeypatch.setattr(agent, "process_forensic_queue", lambda: calls.append(1) or 0)

    agent._run_deferred_tasks()

    assert calls == [1]
    errors = local_repository(agent).list_events(event_type="AGENT_ERROR", limit=5)
    assert "fallo simulado" in errors[0]["evidence"]["error"]
