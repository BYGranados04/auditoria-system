from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient

from app.agent.continuous_agent import ContinuousAgent
from app.agent.registration import save_identity
from app.agent.sync import AgentEventSynchronizer, SyncHttpResponse
from app.api.main import create_app
from app.auth.config import AuthSettings
from app.auth.repository import AuthRepository
from app.central.config import CentralSettings
from app.central.repository import CentralEventRepository
from app.core.config import AgentSettings
from app.core.events import SecurityEvent
from app.detection.ssh_collector import SSHJournalBatch, SSHJournalRecord
from app.response.executor import ResponseExecutor
from app.storage.event_repository import EventRepository
from tests.api_test_helpers import TEST_PASSWORD, TEST_SCRYPT

ATTACKER = "192.168.1.50"


class Clock:
    def __init__(self) -> None:
        self.value = datetime.now(UTC)

    def __call__(self) -> datetime:
        return self.value


class FakeBackend:
    def __init__(self) -> None:
        self.added: list[object] = []

    def prepare(self) -> bool:
        return False

    def prepare_port_blocking(self) -> bool:
        return False

    def add_temporary_block(self, plan) -> None:
        self.added.append(plan)

    def remove_block(self, plan) -> None:  # pragma: no cover
        raise AssertionError("No se esperaba remover bloqueos.")


class MutableResolver:
    def __init__(self) -> None:
        self.protected: set[str] = set()
        self.calls = 0

    def resolve(self):
        self.calls += 1
        return SimpleNamespace(protected_ips=set(self.protected))


class ClientTransport:
    """Transporte del agente que enruta al TestClient del central."""

    def __init__(self, client: TestClient) -> None:
        self.client = client

    def post_json(self, url, payload, *, headers, timeout_seconds):
        del timeout_seconds
        response = self.client.post(urlsplit(url).path, json=payload, headers=headers)
        return SyncHttpResponse(response.status_code, response.content)

    def get_json(self, url, *, headers, timeout_seconds):
        del timeout_seconds
        response = self.client.get(urlsplit(url).path, headers=headers)
        return SyncHttpResponse(response.status_code, response.content)


class Lab:
    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.clock = Clock()
        self.auth = AuthRepository(
            tmp_path / "auth" / "auth.db",
            scrypt_parameters=TEST_SCRYPT,
        )
        self.users = {
            name: int(
                self.auth.create_user(username=name, password=TEST_PASSWORD, role=role)[
                    "id"
                ]
            )
            for name, role in (("admin", "superadmin"), ("owner", "viewer"))
        }
        central_settings = CentralSettings(
            database_file=tmp_path / "central" / "central.db"
        )
        self.central = CentralEventRepository(
            central_settings.database_file,
            clock=self.clock,
        )
        local_settings = AgentSettings(
            interval=1,
            state_dir=tmp_path / "api-state",
            log_dir=tmp_path / "api-logs",
            identity_file=tmp_path / "api-identity.json",
        )
        local_settings.state_dir.mkdir(parents=True)
        EventRepository(local_settings.database_file).initialize()
        application = create_app(
            settings=local_settings,
            repository=EventRepository(local_settings.database_file),
            auth_settings=AuthSettings(
                database_file=self.auth.database_path,
                central_url="https://central.example",
            ),
            auth_repository=self.auth,
            central_settings=central_settings,
            central_repository=self.central,
            clock=self.clock,
        )
        self.client = TestClient(application)
        self.agent_client = TestClient(application)

        token = self.auth.create_agent_registration_token(
            self.users["owner"],
            now=self.clock(),
        )
        enrolled = self.auth.enroll_agent(
            registration_token=token.token,
            hostname="srv-assisted",
            now=self.clock(),
        )
        self.agent_id = str(enrolled.agent["agent_id"])
        identity_file = tmp_path / "agente" / "agent-identity.json"
        save_identity(
            {
                "agent_id": self.agent_id,
                "central_url": "https://central.example",
                "credential": enrolled.credential,
            },
            identity_file,
        )
        self.settings = AgentSettings(
            interval=1,
            state_dir=tmp_path / "agente" / "state",
            log_dir=tmp_path / "agente" / "logs",
            identity_file=identity_file,
            response_mode="assisted",
            response_block_scope="ip_port",
            allow_temporary_ip_port_block=True,
        )
        self.resolver = MutableResolver()
        monkeypatch.setattr(
            ContinuousAgent,
            "_protection_resolver",
            lambda agent_self: self.resolver,
        )
        self.agent = ContinuousAgent(interval=1, settings=self.settings)
        self.backend = FakeBackend()
        self.agent.approval_executor = ResponseExecutor(
            self.agent.response_policy,
            dry_run=False,
            repository=EventRepository(self.settings.database_file),
            backend=self.backend,  # type: ignore[arg-type]
            protection_resolver=self.resolver,  # type: ignore[arg-type]
        )
        transport = ClientTransport(self.agent_client)
        self.agent.approval_client.transport = transport
        self.synchronizer = AgentEventSynchronizer(self.settings, transport=transport)
        self.monkeypatch = monkeypatch

    # -- utilidades -------------------------------------------------------

    @property
    def local(self) -> EventRepository:
        return EventRepository(self.settings.database_file)

    def attack(self) -> None:
        start = datetime.now(UTC) - timedelta(minutes=1)
        records = [
            SSHJournalRecord(
                cursor=f"c{index}",
                timestamp=start + timedelta(seconds=4 * index),
                event_type="SSH_INVALID_USER",
                severity="medium",
                description="Usuario SSH inexistente.",
                evidence={"user": f"u{index}", "ip": ATTACKER, "port": "5000"},
            )
            for index in range(5)
        ]
        self.monkeypatch.setattr(
            self.agent.ssh_collector,
            "read_after",
            lambda _cursor: SSHJournalBatch(records=records, cursor="fin"),
        )
        self.agent._collect_ssh_events({"ssh_journal_cursor": "inicio"}, {})

    def sync(self) -> None:
        for _ in range(20):
            result = self.synchronizer.run_once()
            assert result.permanently_failed == 0
            if not self.local.list_pending_outbox(now=datetime.now(UTC), limit=1):
                return
        raise AssertionError("El outbox no se vació.")

    def login(self, username: str) -> str:
        response = self.client.post(
            "/auth/login",
            json={"username": username, "password": TEST_PASSWORD},
        )
        assert response.status_code == 200
        return str(response.json()["csrf_token"])

    def incident(self) -> dict:
        listing = self.client.get("/incidents").json()
        assert listing["total"] == 1
        return listing["items"][0]

    def detail(self, incident_id: str) -> dict:
        response = self.client.get(f"/incidents/{incident_id}")
        assert response.status_code == 200
        return response.json()

    def decide(
        self,
        incident_id: str,
        action_id: str,
        verb: str,
        *,
        csrf: str | None,
        body: dict | None = None,
    ):
        headers = {"X-CSRF-Token": csrf} if csrf else {}
        return self.client.post(
            f"/incidents/{incident_id}/actions/{action_id}/{verb}",
            json=body or {},
            headers=headers,
        )

    def pending_action(self) -> tuple[str, str]:
        incident = self.incident()
        actions = self.detail(incident["incident_id"])["actions"]
        assert len(actions) == 1
        assert actions[0]["status"] == "PENDING_APPROVAL"
        return incident["incident_id"], actions[0]["action_id"]

    def events(self, event_type: str) -> list[dict]:
        return self.local.list_events(event_type=event_type, limit=50)


@pytest.fixture
def lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Lab:
    instance = Lab(tmp_path, monkeypatch)
    instance.attack()
    instance.sync()
    return instance


def test_assisted_creates_pending_action_without_touching_firewall(lab: Lab) -> None:
    decision = lab.events("RESPONSE_DECISION")[0]["evidence"]
    assert decision["action"] == "RECOMMEND_BLOCK_IP_PORT"
    assert decision["approval_required"] is True
    assert decision["execution_allowed"] is False
    assert decision["proposed_action"] == "TEMPORARY_BLOCK_IP_PORT"
    assert decision["selected_duration_seconds"] == 900
    approval = lab.local.get_response_approval(decision["approval_id"])
    assert approval is not None
    assert approval["status"] == "PENDING_APPROVAL"
    assert (approval["protocol"], approval["port"]) == ("tcp", 22)
    assert lab.backend.added == []

    lab.login("admin")
    incident_id, action_id = lab.pending_action()
    assert action_id == decision["approval_id"]
    assert lab.incident()["status"] == "OPEN"
    assert lab.agent.process_response_approvals() == 0
    assert lab.backend.added == []


def test_decisions_require_authentication(lab: Lab) -> None:
    lab.login("admin")
    incident_id, action_id = lab.pending_action()
    lab.client.post("/auth/logout", headers={"X-CSRF-Token": "x"})
    lab.client.cookies.clear()

    for verb in ("approve", "reject"):
        response = lab.decide(incident_id, action_id, verb, csrf=None)
        assert response.status_code == 401


def test_viewer_owner_cannot_approve_or_reject(lab: Lab) -> None:
    lab.login("admin")
    incident_id, action_id = lab.pending_action()
    lab.client.cookies.clear()
    csrf = lab.login("owner")

    assert lab.client.get(f"/incidents/{incident_id}").status_code == 200
    for verb in ("approve", "reject"):
        response = lab.decide(incident_id, action_id, verb, csrf=csrf)
        assert response.status_code == 403

    lab.client.cookies.clear()
    lab.login("admin")
    assert lab.detail(incident_id)["actions"][0]["status"] == "PENDING_APPROVAL"


def test_csrf_and_origin_are_required(lab: Lab) -> None:
    csrf = lab.login("admin")
    incident_id, action_id = lab.pending_action()

    assert lab.decide(incident_id, action_id, "approve", csrf=None).status_code == 403
    assert lab.decide(incident_id, action_id, "approve", csrf="otro").status_code == 403
    foreign = lab.client.post(
        f"/incidents/{incident_id}/actions/{action_id}/approve",
        json={},
        headers={"X-CSRF-Token": csrf, "Origin": "https://atacante.example"},
    )
    assert foreign.status_code == 403
    assert lab.detail(incident_id)["actions"][0]["status"] == "PENDING_APPROVAL"


def test_approve_executes_once_through_response_executor(lab: Lab) -> None:
    csrf = lab.login("admin")
    incident_id, action_id = lab.pending_action()

    approved = lab.decide(incident_id, action_id, "approve", csrf=csrf)
    second = lab.decide(incident_id, action_id, "approve", csrf=csrf)

    assert approved.status_code == 200
    assert approved.json()["status"] == "APPROVED"
    assert approved.json()["decided_by"] == "admin"
    assert approved.json()["decided_at"] is not None
    assert second.status_code == 409
    assert lab.decide(incident_id, action_id, "reject", csrf=csrf).status_code == 409

    resolver_calls = lab.resolver.calls
    assert lab.agent.process_response_approvals() == 1
    # Sin sincronizar aún: el central reenvía la misma instrucción.
    assert lab.agent.process_response_approvals() == 0
    assert lab.resolver.calls == resolver_calls + 1

    assert len(lab.backend.added) == 1
    plan = lab.backend.added[0]
    assert (plan.target_ip, plan.protocol, plan.port, plan.duration_seconds) == (
        ATTACKER,
        "tcp",
        22,
        900,
    )
    assert lab.local.get_response_approval(action_id)["status"] == "EXECUTED"
    executions = [
        event["evidence"]
        for event in lab.events("RESPONSE_EXECUTION")
        if event["evidence"].get("approval_id") == action_id
        and "approved_by" in event["evidence"]
    ]
    assert len(executions) == 1
    assert executions[0]["status"] == "EXECUTED"
    assert executions[0]["approved_by"] == "admin"
    assert executions[0]["approved_at"]

    lab.sync()
    assert lab.agent.process_response_approvals() == 0
    assert len(lab.backend.added) == 1
    detail = lab.detail(incident_id)
    assert detail["incident"]["status"] == "CONTAINED"
    assert detail["actions"][0]["status"] == "EXECUTED"
    assert detail["actions"][0]["result_status"] == "EXECUTED"

    timeline = lab.client.get(f"/incidents/{incident_id}/timeline").json()
    types = [entry["event_type"] for entry in timeline]
    assert "RESPONSE_APPROVAL_REQUESTED" in types
    assert "RESPONSE_APPROVAL_GRANTED" in types
    assert types.index("RESPONSE_APPROVAL_GRANTED") < len(types) - 1
    granted = next(
        entry
        for entry in timeline
        if entry["event_type"] == "RESPONSE_APPROVAL_GRANTED"
    )
    assert granted["evidence"]["decided_by"] == "admin"
    assert granted["source"] == "central"
    approved_executions = [
        entry
        for entry in timeline
        if entry["event_type"] == "RESPONSE_EXECUTION"
        and entry["evidence"].get("approved_by") == "admin"
    ]
    assert len(approved_executions) == 1


def test_reject_never_touches_firewall_and_records_reason(lab: Lab) -> None:
    csrf = lab.login("admin")
    incident_id, action_id = lab.pending_action()

    rejected = lab.decide(
        incident_id,
        action_id,
        "reject",
        csrf=csrf,
        body={"reason": "Falso positivo:\x00 prueba\nde laboratorio"},
    )

    assert rejected.status_code == 200
    body = rejected.json()
    assert body["status"] == "REJECTED"
    assert body["decided_by"] == "admin"
    assert body["decision_reason"] == "Falso positivo: prueba de laboratorio"
    assert lab.decide(incident_id, action_id, "approve", csrf=csrf).status_code == 409

    assert lab.agent.process_response_approvals() == 1
    assert lab.agent.process_response_approvals() == 0
    assert lab.backend.added == []
    assert lab.local.get_response_approval(action_id)["status"] == "REJECTED"
    applied = lab.events("RESPONSE_REJECTION_APPLIED")
    assert applied[0]["evidence"]["rejected_by"] == "admin"

    lab.sync()
    detail = lab.detail(incident_id)
    assert detail["incident"]["status"] == "OBSERVED"
    assert detail["actions"][0]["result_status"] == "REJECTED"
    timeline = lab.client.get(f"/incidents/{incident_id}/timeline").json()
    assert "RESPONSE_APPROVAL_DENIED" in [entry["event_type"] for entry in timeline]


def test_reject_reason_is_bounded(lab: Lab) -> None:
    csrf = lab.login("admin")
    incident_id, action_id = lab.pending_action()

    response = lab.decide(
        incident_id,
        action_id,
        "reject",
        csrf=csrf,
        body={"reason": "x" * 501},
    )
    extra = lab.decide(
        incident_id,
        action_id,
        "approve",
        csrf=csrf,
        body={"action": "TEMPORARY_BLOCK_IP", "target_ip": "10.0.0.1"},
    )

    assert response.status_code == 422
    assert extra.status_code == 422


def test_central_rejects_approval_of_expired_action(lab: Lab) -> None:
    csrf = lab.login("admin")
    incident_id, action_id = lab.pending_action()
    lab.clock.value = lab.clock.value + timedelta(hours=2)

    response = lab.decide(incident_id, action_id, "approve", csrf=csrf)

    assert response.status_code == 409
    assert "EXPIRED" in response.json()["detail"]
    assert lab.detail(incident_id)["actions"][0]["status"] == "EXPIRED"
    assert lab.agent.process_response_approvals() == 0
    assert lab.backend.added == []


def test_agent_never_executes_locally_expired_action(lab: Lab) -> None:
    csrf = lab.login("admin")
    incident_id, action_id = lab.pending_action()
    assert lab.decide(incident_id, action_id, "approve", csrf=csrf).status_code == 200
    with sqlite3.connect(lab.settings.database_file) as connection:
        connection.execute(
            "UPDATE response_approvals SET expires_at = ? WHERE action_id = ?",
            ((datetime.now(UTC) - timedelta(seconds=1)).isoformat(), action_id),
        )

    lab.agent.process_response_approvals()

    assert lab.backend.added == []
    assert lab.local.get_response_approval(action_id)["status"] == "EXPIRED"
    assert lab.events("RESPONSE_APPROVAL_EXPIRED")
    lab.sync()
    assert lab.detail(incident_id)["actions"][0]["status"] == "EXPIRED"


def test_ip_that_became_protected_is_not_blocked_after_approval(lab: Lab) -> None:
    csrf = lab.login("admin")
    incident_id, action_id = lab.pending_action()
    assert lab.decide(incident_id, action_id, "approve", csrf=csrf).status_code == 200
    # Antes de que el agente aplique la aprobación, la IP pasa a ser una
    # sesión SSH administrativa activa.
    lab.resolver.protected = {ATTACKER}

    assert lab.agent.process_response_approvals() == 1

    assert lab.backend.added == []
    approval = lab.local.get_response_approval(action_id)
    assert approval["status"] == "SKIPPED"
    execution = [
        event["evidence"]
        for event in lab.events("RESPONSE_EXECUTION")
        if event["evidence"].get("approved_by") == "admin"
    ][0]
    assert execution["status"] == "SKIPPED"
    assert execution["protection_rejected"] is True
    lab.sync()
    detail = lab.detail(incident_id)
    assert detail["actions"][0]["status"] == "SKIPPED"
    assert detail["incident"]["status"] == "OBSERVED"


def test_approval_is_skipped_if_agent_no_longer_authorizes_blocking(lab: Lab) -> None:
    csrf = lab.login("admin")
    incident_id, action_id = lab.pending_action()
    assert lab.decide(incident_id, action_id, "approve", csrf=csrf).status_code == 200
    lab.agent.settings = AgentSettings(
        **{
            **lab.settings.__dict__,
            "allow_temporary_ip_port_block": False,
        }
    )

    assert lab.agent.process_response_approvals() == 1

    assert lab.backend.added == []
    assert lab.local.get_response_approval(action_id)["status"] == "SKIPPED"


def test_agent_reported_results_cannot_forge_approval(lab: Lab) -> None:
    lab.login("admin")
    incident_id, action_id = lab.pending_action()

    forged = SecurityEvent(
        hostname="srv-assisted",
        source="response-executor",
        category="response",
        event_type="RESPONSE_EXECUTION",
        severity="low",
        description="Resultado falsificado",
        evidence={"approval_id": action_id, "status": "EXECUTED"},
    )
    lab.central.add_events(agent_id=lab.agent_id, events=(forged,))

    assert lab.detail(incident_id)["actions"][0]["status"] == "PENDING_APPROVAL"


def test_agent_endpoint_requires_agent_credential_and_scopes_by_agent(
    lab: Lab,
) -> None:
    csrf = lab.login("admin")
    incident_id, action_id = lab.pending_action()
    assert lab.decide(incident_id, action_id, "approve", csrf=csrf).status_code == 200

    anonymous = lab.agent_client.get("/agent/response-actions")
    token = lab.auth.create_agent_registration_token(
        lab.users["owner"],
        now=lab.clock(),
    )
    other = lab.auth.enroll_agent(
        registration_token=token.token,
        hostname="otro",
        now=lab.clock(),
    )
    other_view = lab.agent_client.get(
        "/agent/response-actions",
        headers={"Authorization": f"Bearer {other.credential}"},
    )

    assert anonymous.status_code == 401
    assert other_view.status_code == 200
    assert other_view.json() == {"actions": []}


def test_interrupted_execution_is_failed_on_restart(lab: Lab) -> None:
    csrf = lab.login("admin")
    incident_id, action_id = lab.pending_action()
    assert lab.decide(incident_id, action_id, "approve", csrf=csrf).status_code == 200
    claimed = lab.local.claim_response_approval(
        action_id,
        decided_by="admin",
        decided_at=datetime.now(UTC),
        now=datetime.now(UTC),
    )
    assert claimed is not None

    lab.agent._recover_interrupted_approvals()
    lab.agent.process_response_approvals()

    assert lab.local.get_response_approval(action_id)["status"] == "FAILED"
    assert lab.backend.added == []
