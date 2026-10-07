from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.api.main import create_app
from app.auth.config import AuthSettings
from app.auth.repository import AuthRepository
from app.central.config import CentralSettings
from app.central.repository import CentralEventRepository
from app.core.config import AgentSettings
from app.core.events import SecurityEvent
from app.storage.event_repository import EventRepository
from tests.api_test_helpers import TEST_PASSWORD, TEST_SCRYPT

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)


def build(
    tmp_path: Path,
    *,
    now: datetime = NOW,
) -> tuple[TestClient, AuthRepository, CentralEventRepository, dict[str, str]]:
    settings = AgentSettings(
        interval=1,
        state_dir=tmp_path / "state",
        log_dir=tmp_path / "logs",
        identity_file=tmp_path / "agent-identity.json",
    )
    settings.state_dir.mkdir(parents=True)
    local = EventRepository(settings.database_file)
    local.initialize()
    auth = AuthRepository(tmp_path / "auth" / "auth.db", scrypt_parameters=TEST_SCRYPT)
    users: dict[str, int] = {}
    for username, role in (
        ("admin", "superadmin"),
        ("viewer-a", "viewer"),
        ("viewer-b", "viewer"),
    ):
        users[username] = int(
            auth.create_user(username=username, password=TEST_PASSWORD, role=role)["id"]
        )
    agents: dict[str, str] = {}
    for owner, hostname in (("viewer-a", "srv-a"), ("viewer-b", "srv-b")):
        token = auth.create_agent_registration_token(users[owner], now=NOW)
        enrolled = auth.enroll_agent(
            registration_token=token.token,
            hostname=hostname,
            now=NOW,
        )
        agents[hostname] = str(enrolled.agent["agent_id"])

    central_settings = CentralSettings(
        database_file=tmp_path / "central" / "central.db"
    )
    central = CentralEventRepository(central_settings.database_file, clock=lambda: now)
    application = create_app(
        settings=settings,
        repository=local,
        auth_settings=AuthSettings(
            database_file=auth.database_path,
            central_url="https://central.example",
        ),
        auth_repository=auth,
        central_settings=central_settings,
        central_repository=central,
        clock=lambda: now,
    )
    return TestClient(application), auth, central, agents


def login(client: TestClient, username: str) -> None:
    response = client.post(
        "/auth/login",
        json={"username": username, "password": TEST_PASSWORD},
    )
    assert response.status_code == 200


def event(
    at: datetime,
    *,
    category: str,
    event_type: str,
    evidence: dict,
    hostname: str,
    severity: str = "low",
) -> SecurityEvent:
    return SecurityEvent(
        event_id=uuid4(),
        timestamp=at,
        hostname=hostname,
        source="test",
        category=category,
        event_type=event_type,
        severity=severity,
        description=f"{event_type} de prueba",
        evidence=evidence,
    )


def link(item: SecurityEvent, kind: str) -> dict[str, str]:
    return {
        "event_id": str(item.event_id),
        "kind": kind,
        "occurred_at": item.timestamp.isoformat(),
    }


def seed_incident(
    central: CentralEventRepository,
    *,
    agent_id: str,
    hostname: str,
    incident_id: str,
    opened_at: datetime,
    severity: str = "high",
    status: str = "CONTAINED",
    incident_type: str = "SSH_USER_ENUMERATION_ATTEMPT",
    source_ip: str = "192.168.1.50",
) -> dict[str, object]:
    attempts = [
        event(
            opened_at + timedelta(seconds=4 * index),
            category="authentication",
            event_type="SSH_INVALID_USER",
            evidence={"user": f"u{index}", "ip": source_ip},
            hostname=hostname,
            severity="medium",
        )
        for index in range(5)
    ]
    detection_at = opened_at + timedelta(seconds=17)
    detection = event(
        detection_at,
        category="detection",
        event_type=incident_type,
        evidence={"source_ip": source_ip, "attempt_count": 5},
        hostname=hostname,
        severity=severity,
    )
    capture_id = str(detection.event_id)
    evidence = event(
        detection_at + timedelta(seconds=1),
        category="forensics",
        event_type="FORENSIC_EVIDENCE_CAPTURED",
        evidence={
            "action": "COLLECT_FORENSIC_EVIDENCE",
            "capture_id": capture_id,
            "status": "partial",
            "incident_id": incident_id,
            "detection_event_id": str(detection.event_id),
            "captured_at": detection_at.isoformat(),
            "completed_at": detection_at.isoformat(),
            "total_bytes": 2048,
            "max_bytes": 262144,
            "truncated": False,
            "storage": "agent-local",
            "artifacts": [
                {
                    "name": "network_connections",
                    "file": "network_connections.txt",
                    "status": "ok",
                    "bytes": 2048,
                    "sha256": "a" * 64,
                    "truncated": False,
                    "error": None,
                },
                {
                    "name": "malicioso",
                    "file": "../../etc/shadow",
                    "status": "ok",
                    "bytes": 1,
                    "sha256": "no-hash",
                    "truncated": False,
                    "error": None,
                },
            ],
        },
        hostname=hostname,
    )
    decision = event(
        detection_at + timedelta(seconds=2),
        category="response",
        event_type="RESPONSE_DECISION",
        evidence={
            "action": "TEMPORARY_BLOCK_IP_PORT",
            "target_ip": source_ip,
            "protocol": "tcp",
            "port": 22,
            "duration_seconds": 120,
            "recurrence_level": 1,
            "previous_incidents": 0,
            "selected_duration_seconds": 120,
            "mode": "automatic",
            "reason": "Política automática.",
            "incident_id": incident_id,
        },
        hostname=hostname,
    )
    execution = event(
        detection_at + timedelta(seconds=3),
        category="response",
        event_type="RESPONSE_EXECUTION",
        evidence={
            "action": "TEMPORARY_BLOCK_IP_PORT",
            "status": "EXECUTED",
            "executed": True,
            "reason": "Aplicado.",
        },
        hostname=hostname,
    )
    common = {
        "incident_id": incident_id,
        "incident_type": incident_type,
        "severity": severity,
        "source_ip": source_ip,
        "opened_at": detection_at.isoformat(),
        "last_activity_at": detection_at.isoformat(),
        "closed_at": None,
        "detection_count": 1,
    }
    opened = event(
        detection_at + timedelta(milliseconds=500),
        category="incident",
        event_type="INCIDENT_OPENED",
        evidence={
            **common,
            "status": "OPEN",
            "recurrence_level": None,
            "last_action": None,
            "last_execution_status": None,
            "links": [
                *(link(item, "event") for item in attempts),
                link(detection, "detection"),
            ],
        },
        hostname=hostname,
    )
    updated = event(
        detection_at + timedelta(seconds=4),
        category="incident",
        event_type="INCIDENT_UPDATED",
        evidence={
            **common,
            "status": status,
            "recurrence_level": 1,
            "last_action": "TEMPORARY_BLOCK_IP_PORT",
            "last_execution_status": "EXECUTED",
            "links": [
                link(evidence, "evidence"),
                link(decision, "decision"),
                link(execution, "execution"),
            ],
        },
        hostname=hostname,
    )
    central.add_events(
        agent_id=agent_id,
        events=(*attempts, detection, opened, evidence, decision, execution, updated),
    )
    return {"capture_id": capture_id, "detection_id": str(detection.event_id)}


INCIDENT_A = "INC-AAAAAAAAAAAAAAAA"
INCIDENT_B = "INC-BBBBBBBBBBBBBBBB"


@pytest.fixture
def seeded(tmp_path: Path):
    client, auth, central, agents = build(tmp_path)
    data_a = seed_incident(
        central,
        agent_id=agents["srv-a"],
        hostname="srv-a",
        incident_id=INCIDENT_A,
        opened_at=NOW - timedelta(days=1),
    )
    seed_incident(
        central,
        agent_id=agents["srv-b"],
        hostname="srv-b",
        incident_id=INCIDENT_B,
        opened_at=NOW - timedelta(hours=1),
        severity="medium",
        status="OBSERVED",
        incident_type="SSH_REPEATED_PREAUTH_ACTIVITY",
        source_ip="2001:db8::9",
    )
    return client, agents, data_a


def test_incident_endpoints_require_authentication(seeded) -> None:
    client, _, _ = seeded

    for path in (
        "/incidents",
        f"/incidents/{INCIDENT_A}",
        f"/incidents/{INCIDENT_A}/timeline",
        f"/incidents/{INCIDENT_A}/evidence",
    ):
        assert client.get(path).status_code == 401


def test_superadmin_lists_paginated_incidents(seeded) -> None:
    client, agents, _ = seeded
    login(client, "admin")

    first = client.get("/incidents", params={"limit": 1})
    second = client.get("/incidents", params={"limit": 1, "offset": 1})

    assert first.status_code == 200
    body = first.json()
    assert body["total"] == 2
    assert body["limit"] == 1
    assert body["offset"] == 0
    assert [item["incident_id"] for item in body["items"]] == [INCIDENT_B]
    assert [item["incident_id"] for item in second.json()["items"]] == [INCIDENT_A]
    item = second.json()["items"][0]
    assert item["agent_id"] == agents["srv-a"]
    assert item["hostname"] == "srv-a"
    assert item["status"] == "CONTAINED"
    assert item["last_action"] == "TEMPORARY_BLOCK_IP_PORT"
    assert item["recurrence_level"] == 1


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ({"severity": "high"}, [INCIDENT_A]),
        ({"status": "OBSERVED"}, [INCIDENT_B]),
        ({"incident_type": "SSH_REPEATED_PREAUTH_ACTIVITY"}, [INCIDENT_B]),
        ({"source_ip": "2001:DB8::9"}, [INCIDENT_B]),
        ({"since": (NOW - timedelta(hours=2)).isoformat()}, [INCIDENT_B]),
        ({"until": (NOW - timedelta(hours=2)).isoformat()}, [INCIDENT_A]),
    ],
)
def test_incident_filters(seeded, params: dict, expected: list[str]) -> None:
    client, _, _ = seeded
    login(client, "admin")

    response = client.get("/incidents", params=params)

    assert response.status_code == 200
    assert [item["incident_id"] for item in response.json()["items"]] == expected


def test_incident_filter_by_agent(seeded) -> None:
    client, agents, _ = seeded
    login(client, "admin")

    response = client.get("/incidents", params={"agent_id": agents["srv-b"]})

    assert [item["incident_id"] for item in response.json()["items"]] == [INCIDENT_B]


@pytest.mark.parametrize(
    "params",
    [
        {"status": "HACKED"},
        {"severity": "urgent"},
        {"incident_type": "ssh;drop"},
        {"source_ip": "not-an-ip"},
        {"since": "2026-10-05T00:00:00"},
        {"limit": 0},
        {"limit": 201},
        {"offset": -1},
    ],
)
def test_incident_filters_are_validated(seeded, params: dict) -> None:
    client, _, _ = seeded
    login(client, "admin")

    assert client.get("/incidents", params=params).status_code == 422


def test_viewer_only_sees_incidents_of_owned_servers(seeded) -> None:
    client, agents, _ = seeded
    login(client, "viewer-a")

    listed = client.get("/incidents").json()
    foreign_detail = client.get(f"/incidents/{INCIDENT_B}")
    foreign_timeline = client.get(f"/incidents/{INCIDENT_B}/timeline")
    foreign_agent = client.get("/incidents", params={"agent_id": agents["srv-b"]})

    assert [item["incident_id"] for item in listed["items"]] == [INCIDENT_A]
    assert listed["total"] == 1
    assert foreign_detail.status_code == 404
    assert foreign_timeline.status_code == 404
    assert foreign_agent.status_code == 404
    assert client.get(f"/incidents/{INCIDENT_A}").status_code == 200


def test_incident_detail_includes_decision_execution_and_evidence(seeded) -> None:
    client, _, data = seeded
    login(client, "admin")

    response = client.get(f"/incidents/{INCIDENT_A}")

    assert response.status_code == 200
    detail = response.json()
    assert detail["incident"]["incident_id"] == INCIDENT_A
    assert detail["incident"]["source_ip"] == "192.168.1.50"
    assert detail["timeline_count"] == 9
    assert len(detail["detections"]) == 1
    assert detail["decision"]["evidence"]["action"] == "TEMPORARY_BLOCK_IP_PORT"
    assert detail["decision"]["evidence"]["port"] == 22
    assert detail["execution"]["evidence"]["status"] == "EXECUTED"
    assert len(detail["evidence"]) == 1
    capture = detail["evidence"][0]
    assert capture["capture_id"] == data["capture_id"]
    assert capture["storage"] == "agent-local"
    files = [artifact["file"] for artifact in capture["artifacts"]]
    assert files == ["network_connections.txt", None]
    assert capture["artifacts"][1]["sha256"] is None


def test_incident_timeline_is_chronological(seeded) -> None:
    client, _, _ = seeded
    login(client, "admin")

    response = client.get(f"/incidents/{INCIDENT_A}/timeline")

    assert response.status_code == 200
    timeline = response.json()
    assert [entry["event_type"] for entry in timeline] == [
        "SSH_INVALID_USER",
        "SSH_INVALID_USER",
        "SSH_INVALID_USER",
        "SSH_INVALID_USER",
        "SSH_INVALID_USER",
        "SSH_USER_ENUMERATION_ATTEMPT",
        "FORENSIC_EVIDENCE_CAPTURED",
        "RESPONSE_DECISION",
        "RESPONSE_EXECUTION",
    ]
    timestamps = [entry["timestamp"] for entry in timeline]
    assert timestamps == sorted(timestamps)


def test_incident_evidence_metadata_endpoints(seeded) -> None:
    client, _, data = seeded
    login(client, "admin")

    listing = client.get(f"/incidents/{INCIDENT_A}/evidence")
    single = client.get(f"/incidents/{INCIDENT_A}/evidence/{data['capture_id']}")
    foreign = client.get(f"/incidents/{INCIDENT_A}/evidence/{uuid4()}")

    assert listing.status_code == 200
    assert [item["capture_id"] for item in listing.json()] == [data["capture_id"]]
    assert single.status_code == 200
    assert single.json()["total_bytes"] == 2048
    assert foreign.status_code == 404


@pytest.mark.parametrize(
    "path",
    [
        "/incidents/..%2F..%2Fetc%2Fpasswd",
        "/incidents/INC-aaaaaaaaaaaaaaaa",
        "/incidents/INC-AAAAAAAAAAAAAAAA/evidence/..%2F..%2Fetc%2Fshadow",
        "/incidents/INC-AAAAAAAAAAAAAAAA/evidence/not-a-uuid",
    ],
)
def test_incident_paths_reject_traversal_and_invalid_identifiers(
    seeded,
    path: str,
) -> None:
    client, _, _ = seeded
    login(client, "admin")

    response = client.get(path)

    assert response.status_code in {404, 422}
    assert "root:" not in response.text


def test_unknown_incident_returns_404(seeded) -> None:
    client, _, _ = seeded
    login(client, "admin")

    assert client.get("/incidents/INC-0000000000000000").status_code == 404


def test_incidents_return_empty_page_before_central_database_exists(
    tmp_path: Path,
) -> None:
    client, _, central, _ = build(tmp_path)
    login(client, "admin")

    response = client.get("/incidents")

    assert response.status_code == 200
    assert response.json() == {"items": [], "total": 0, "limit": 50, "offset": 0}
    assert not central.database_path.exists()


def test_agent_ingestion_projects_incidents_end_to_end(tmp_path: Path) -> None:
    client, auth, central, agents = build(tmp_path)
    token = auth.create_agent_registration_token(1, now=NOW)
    enrolled = auth.enroll_agent(
        registration_token=token.token,
        hostname="srv-e2e",
        now=NOW,
    )
    detection = event(
        NOW - timedelta(minutes=1),
        category="detection",
        event_type="SSH_BRUTE_FORCE_ATTEMPT",
        evidence={"source_ip": "198.51.100.7"},
        hostname="srv-e2e",
        severity="high",
    )
    opened = event(
        NOW - timedelta(seconds=30),
        category="incident",
        event_type="INCIDENT_OPENED",
        evidence={
            "incident_id": "INC-0123456789ABCDEF",
            "incident_type": "SSH_BRUTE_FORCE_ATTEMPT",
            "severity": "high",
            "source_ip": "198.51.100.7",
            "status": "OPEN",
            "opened_at": detection.timestamp.isoformat(),
            "last_activity_at": detection.timestamp.isoformat(),
            "closed_at": None,
            "detection_count": 1,
            "recurrence_level": None,
            "last_action": None,
            "last_execution_status": None,
            "links": [link(detection, "detection")],
        },
        hostname="srv-e2e",
    )
    payload = {
        "events": [
            json.loads(item.model_dump_json(exclude={"agent_id"}))
            for item in (detection, opened)
        ]
    }

    ingest = client.post(
        "/agent/events/batch",
        headers={"Authorization": f"Bearer {enrolled.credential}"},
        json=payload,
    )
    duplicate = client.post(
        "/agent/events/batch",
        headers={"Authorization": f"Bearer {enrolled.credential}"},
        json=payload,
    )
    login(client, "admin")
    listing = client.get("/incidents", params={"agent_id": enrolled.agent["agent_id"]})

    assert ingest.status_code == 200
    assert duplicate.json()["duplicates"] == 2
    assert listing.json()["total"] == 1
    assert listing.json()["items"][0]["incident_id"] == "INC-0123456789ABCDEF"
    assert str(enrolled.credential) not in listing.text
    assert agents  # los demás agentes no interfieren


def test_dashboard_incidents_view_is_served(seeded) -> None:
    client, _, _ = seeded
    login(client, "admin")

    page = client.get("/dashboard/incidents")
    script = client.get("/dashboard/assets/dashboard.js").text

    assert page.status_code == 200
    assert 'data-module="incidents"' in page.text
    assert 'href="/dashboard/incidents"' in page.text
    assert 'id="incidents-filters"' in page.text
    assert 'id="incident-timeline"' in page.text
    assert '"/dashboard/incidents"' in script
    assert "innerHTML" not in script


def test_dashboard_incidents_requires_session(tmp_path: Path) -> None:
    client, _, _, _ = build(tmp_path)

    response = client.get("/dashboard/incidents", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


class _ClientTransport:
    def __init__(self, client: TestClient) -> None:
        self.client = client
        self.event_types: list[str] = []

    def post_json(self, url, payload, *, headers, timeout_seconds):
        from urllib.parse import urlsplit

        from app.agent.sync import SyncHttpResponse

        del timeout_seconds
        self.event_types.extend(item["event_type"] for item in payload["events"])
        response = self.client.post(urlsplit(url).path, json=payload, headers=headers)
        return SyncHttpResponse(status_code=response.status_code, body=response.content)


def test_agent_outbox_syncs_incident_flow_to_central_api(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from types import SimpleNamespace

    from app.agent.continuous_agent import ContinuousAgent
    from app.agent.registration import save_identity
    from app.agent.sync import AgentEventSynchronizer
    from app.detection.ssh_collector import SSHJournalBatch, SSHJournalRecord

    # El agente emite eventos con la hora real; el central debe aceptarlos.
    current = datetime.now(UTC)
    client, auth, _, _ = build(tmp_path, now=current)
    token = auth.create_agent_registration_token(1, now=current)
    enrolled = auth.enroll_agent(
        registration_token=token.token,
        hostname="srv-outbox",
        now=current,
    )
    agent_dir = tmp_path / "agente"
    identity_file = agent_dir / "agent-identity.json"
    save_identity(
        {
            "agent_id": str(enrolled.agent["agent_id"]),
            "central_url": "https://central.example",
            "credential": enrolled.credential,
        },
        identity_file,
    )
    settings = AgentSettings(
        interval=1,
        state_dir=agent_dir / "state",
        log_dir=agent_dir / "logs",
        identity_file=identity_file,
        evidence_enabled=True,
    )
    monkeypatch.setattr(
        ContinuousAgent,
        "_protection_resolver",
        lambda self: SimpleNamespace(
            resolve=lambda: SimpleNamespace(protected_ips=set())
        ),
    )
    agent = ContinuousAgent(interval=1, settings=settings)
    agent.evidence_collector._runner = lambda command, _t: (0, "salida\n", "")
    agent.evidence_collector._process_provider = lambda _ip: []
    start = current - timedelta(minutes=2)
    records = [
        SSHJournalRecord(
            cursor=f"c{index}",
            timestamp=start + timedelta(seconds=4 * index),
            event_type="SSH_INVALID_USER",
            severity="medium",
            description="Usuario SSH inexistente.",
            evidence={"user": f"u{index}", "ip": "192.168.1.50", "port": "5000"},
        )
        for index in range(5)
    ]
    monkeypatch.setattr(
        agent.ssh_collector,
        "read_after",
        lambda _cursor: SSHJournalBatch(records=records, cursor="fin"),
    )
    agent._collect_ssh_events({"ssh_journal_cursor": "inicio"}, {})
    agent.process_forensic_queue()

    transport = _ClientTransport(client)
    synchronizer = AgentEventSynchronizer(settings, transport=transport)
    result = synchronizer.run_once()
    while result.acknowledged and synchronizer.repository.list_pending_outbox(
        now=datetime.now(UTC), limit=100
    ):
        result = synchronizer.run_once()

    assert result.permanently_failed == 0
    assert (
        synchronizer.repository.list_pending_outbox(now=datetime.now(UTC), limit=100)
        == []
    )
    assert {"INCIDENT_OPENED", "INCIDENT_UPDATED", "FORENSIC_EVIDENCE_CAPTURED"} <= set(
        transport.event_types
    )

    login(client, "admin")
    listing = client.get(
        "/incidents", params={"agent_id": str(enrolled.agent["agent_id"])}
    ).json()
    assert listing["total"] == 1
    incident = listing["items"][0]
    assert incident["status"] == "OBSERVED"
    timeline = client.get(f"/incidents/{incident['incident_id']}/timeline").json()
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
    assert client.get("/health").json() == {
        "status": "ok",
        "service": "auditoria-system-api",
    }
