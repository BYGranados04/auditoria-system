"""Soporte remoto seguro del modo de respuesta en el agente (v1.1)."""

from __future__ import annotations

import json
import os
from ipaddress import ip_address
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.agent.continuous_agent import ContinuousAgent
from app.agent.heartbeat import AgentHeartbeatSender
from app.agent.registration import save_identity
from app.agent.remote_config import (
    LOCAL_MANAGEMENT_REASON,
    LocalResponseConfig,
    LocalResponseConfigError,
    RemoteConfigCoordinator,
    load_local_response_config,
    parse_central_config,
    save_local_response_config,
)
from app.agent.sync import SyncHttpResponse
from app.api.main import create_app
from app.auth.config import AuthSettings
from app.auth.repository import AuthRepository
from app.central.config import CentralSettings
from app.central.repository import CentralEventRepository
from app.core.config import AgentSettings, load_agent_settings
from app.response.engine import ResponsePolicyEngine
from app.response.models import ResponseDecision
from app.response.protection import ProtectionSnapshot, ResponseProtectionResolver
from tests.api_test_helpers import TEST_PASSWORD, TEST_SCRYPT

POSIX = os.name != "nt"
TRUSTED_ADMIN = "203.0.113.10"


class FakeTransport:
    """GET /agent/config y POST /agent/config/state simulados."""

    def __init__(
        self,
        *,
        config: object = None,
        get_status: int = 200,
        post_status: int = 200,
    ) -> None:
        self.config = config
        self.get_status = get_status
        self.post_status = post_status
        self.gets: list[str] = []
        self.posts: list[tuple[str, dict[str, object]]] = []

    def get_json(self, url, *, headers, timeout_seconds):
        self.gets.append(url)
        body = (
            self.config
            if isinstance(self.config, bytes)
            else json.dumps(self.config).encode()
        )
        return SyncHttpResponse(self.get_status, body)

    def post_json(self, url, payload, *, headers, timeout_seconds):
        self.posts.append((url, payload))
        return SyncHttpResponse(self.post_status, b"{}")


class FakeBackend:
    def __init__(self) -> None:
        self.added = []

    def prepare(self) -> bool:
        return True

    def add_temporary_block(self, plan) -> None:
        self.added.append(plan)

    def remove_block(self, plan) -> None:
        pass


def make_settings(tmp_path: Path, **overrides: object) -> AgentSettings:
    values: dict[str, object] = {
        "interval": 1,
        "state_dir": tmp_path / "state",
        "log_dir": tmp_path / "logs",
        "identity_file": tmp_path / "identity" / "agent-identity.json",
        "trusted_admin_ips": (TRUSTED_ADMIN,),
    }
    values.update(overrides)
    return AgentSettings(**values)  # type: ignore[arg-type]


def install_identity(settings: AgentSettings) -> None:
    save_identity(
        {
            "agent_id": "agt_local",
            "credential": "agc_test_credential",
            "central_url": "https://central.example",
        },
        settings.identity_file,
    )


def build_agent(
    tmp_path: Path,
    transport: FakeTransport,
    **overrides: object,
) -> tuple[ContinuousAgent, list[dict[str, object]]]:
    settings = make_settings(tmp_path, **overrides)
    install_identity(settings)
    agent = ContinuousAgent(interval=1, settings=settings)
    agent.remote_config.transport = transport
    events: list[dict[str, object]] = []
    agent.emit = lambda **kwargs: events.append(kwargs)  # type: ignore[method-assign]
    return agent, events


def decision(target_ip: str) -> ResponseDecision:
    return ResponseDecision(
        detection_event_id=uuid4(),
        hostname="srv-web-01",
        mode="automatic",
        action="TEMPORARY_BLOCK_IP",
        target_ip=target_ip,
        reason="Prueba de protecciones.",
        duration_seconds=900,
        execution_allowed=True,
        executed=False,
    )


# ------------------------------------------------------- configuración


def test_mode_source_defaults_to_local(monkeypatch) -> None:
    monkeypatch.delenv("AUDITORIA_RESPONSE_MODE_SOURCE", raising=False)
    assert load_agent_settings().response_mode_source == "local"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("central", "central"),
        (" CENTRAL ", "central"),
        ("local", "local"),
        ("remote", "local"),
        ("", "local"),
        ("automatic", "local"),
    ],
)
def test_invalid_mode_source_falls_back_to_local(
    monkeypatch, value: str, expected: str
) -> None:
    monkeypatch.setenv("AUDITORIA_RESPONSE_MODE_SOURCE", value)
    assert load_agent_settings().response_mode_source == expected


@pytest.mark.parametrize(
    "payload",
    [
        b"[]",
        b"no-json",
        json.dumps({"revision": -1, "response_mode": "assisted"}).encode(),
        json.dumps({"revision": True, "response_mode": "assisted"}).encode(),
        json.dumps({"revision": "3", "response_mode": "assisted"}).encode(),
        json.dumps({"revision": 3, "response_mode": "AUTOMATIC"}).encode(),
        json.dumps({"revision": 3, "response_mode": None}).encode(),
        json.dumps({"revision": 3, "response_mode": "disabled"}).encode(),
    ],
)
def test_invalid_central_payloads_are_rejected(payload: bytes) -> None:
    with pytest.raises((ValueError, UnicodeDecodeError)):
        parse_central_config(payload)


def test_valid_central_payload_is_parsed() -> None:
    config = parse_central_config(b'{"revision": 4, "response_mode": "automatic"}')
    assert (config.revision, config.response_mode) == (4, "automatic")
    assert parse_central_config(b'{"revision": 0, "response_mode": null}').revision == 0


# -------------------------------------------------- persistencia local


def test_local_config_round_trip_is_atomic_and_private(tmp_path: Path) -> None:
    path = tmp_path / "state" / "response_config.json"

    save_local_response_config(
        path, LocalResponseConfig(revision=7, response_mode="assisted")
    )

    assert load_local_response_config(path) == LocalResponseConfig(7, "assisted")
    assert set(json.loads(path.read_text())) == {
        "revision",
        "response_mode",
        "applied_at",
    }
    assert [item.name for item in path.parent.iterdir()] == ["response_config.json"]
    if POSIX:
        assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "content",
    [
        "{corrupto",
        "[]",
        json.dumps({"revision": 1, "response_mode": "automatic"}),
        json.dumps({"revision": 0, "response_mode": "automatic", "applied_at": "x"}),
        json.dumps({"revision": 1, "response_mode": "yolo", "applied_at": "x"}),
        json.dumps(
            {"revision": 1, "response_mode": "automatic", "applied_at": "x", "extra": 1}
        ),
    ],
)
def test_corrupt_local_config_is_rejected(tmp_path: Path, content: str) -> None:
    path = tmp_path / "response_config.json"
    path.write_text(content)
    path.chmod(0o600)

    with pytest.raises(LocalResponseConfigError):
        load_local_response_config(path)


@pytest.mark.skipif(not POSIX, reason="Permisos POSIX.")
def test_insecure_or_symlinked_local_config_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "response_config.json"
    save_local_response_config(path, LocalResponseConfig(1, "assisted"))
    path.chmod(0o644)
    with pytest.raises(LocalResponseConfigError):
        load_local_response_config(path)

    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(LocalResponseConfigError):
        load_local_response_config(link)


def test_corrupt_file_starts_in_audit_only_and_emits_event(tmp_path: Path) -> None:
    settings = make_settings(
        tmp_path,
        response_mode="automatic",
        response_mode_source="central",
        allow_temporary_ip_block=True,
    )
    settings.state_dir.mkdir(parents=True)
    settings.response_config_file.write_text("{corrupto")
    settings.response_config_file.chmod(0o600)

    agent, events = build_agent(
        tmp_path,
        FakeTransport(),
        response_mode="automatic",
        response_mode_source="central",
        allow_temporary_ip_block=True,
    )
    agent._process_remote_config()

    assert agent.settings.response_mode == "audit_only"
    assert agent.response_policy.mode == "audit_only"
    assert agent.response_executor.dry_run is True
    assert [event["event_type"] for event in events] == ["AGENT_CONFIG_INVALID"]
    assert events[0]["evidence"]["fallback_mode"] == "audit_only"


def test_central_source_without_file_starts_with_agent_env_mode(tmp_path: Path) -> None:
    agent, _ = build_agent(
        tmp_path,
        FakeTransport(),
        response_mode="assisted",
        response_mode_source="central",
    )

    assert agent.settings.response_mode == "assisted"
    assert agent.remote_config.processed_revision == 0


def test_central_source_restores_last_applied_mode(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    save_local_response_config(
        settings.response_config_file, LocalResponseConfig(5, "assisted")
    )

    agent, _ = build_agent(
        tmp_path,
        FakeTransport(),
        response_mode="audit_only",
        response_mode_source="central",
    )

    assert agent.settings.response_mode == "assisted"
    assert agent.remote_config.processed_revision == 5


def test_local_source_ignores_stored_central_file(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    save_local_response_config(
        settings.response_config_file, LocalResponseConfig(5, "automatic")
    )

    agent, _ = build_agent(tmp_path, FakeTransport(), response_mode="audit_only")

    assert agent.settings.response_mode == "audit_only"


# ----------------------------------------------- coordinador (heartbeat)


def test_central_v1_0_returns_404_and_agent_stops_asking(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    install_identity(settings)
    transport = FakeTransport(get_status=404)
    coordinator = RemoteConfigCoordinator(settings, transport=transport)

    coordinator.on_heartbeat(None)
    coordinator.on_heartbeat(None)
    coordinator.on_heartbeat(7)
    report = SimpleNamespace(payload=lambda: {})
    coordinator.queue_report(report)  # type: ignore[arg-type]

    assert coordinator.unsupported is True
    assert len(transport.gets) == 1
    assert coordinator.flush_report() is False
    assert transport.posts == []
    assert coordinator.take_pending() is None


def test_new_revision_is_fetched_once_and_left_pending(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    install_identity(settings)
    transport = FakeTransport(config={"revision": 3, "response_mode": "automatic"})
    coordinator = RemoteConfigCoordinator(settings, transport=transport)

    coordinator.on_heartbeat(3)
    coordinator.on_heartbeat(3)

    assert transport.gets == ["https://central.example/agent/config"]
    pending = coordinator.take_pending()
    assert (pending.revision, pending.response_mode) == (3, "automatic")
    assert coordinator.take_pending() is None


def test_already_processed_revision_is_not_fetched_again(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    install_identity(settings)
    transport = FakeTransport(config={"revision": 3, "response_mode": "assisted"})
    coordinator = RemoteConfigCoordinator(
        settings, transport=transport, processed_revision=3
    )

    coordinator.on_heartbeat(3)  # primer contacto: consulta única
    coordinator.on_heartbeat(3)
    coordinator.on_heartbeat(2)

    assert len(transport.gets) == 1
    assert coordinator.take_pending() is None


def test_invalid_central_config_is_reported_once_without_loop(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    install_identity(settings)
    transport = FakeTransport(config={"revision": 4, "response_mode": "yolo"})
    coordinator = RemoteConfigCoordinator(settings, transport=transport)

    coordinator.on_heartbeat(4)
    coordinator.on_heartbeat(4)
    coordinator.on_heartbeat(4)

    assert len(transport.gets) == 1
    assert coordinator.take_pending() is None
    assert [notice.event_type for notice in coordinator.take_notices()] == [
        "AGENT_CONFIG_INVALID"
    ]


def test_heartbeat_passes_revision_and_survives_listener_errors(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    install_identity(settings)
    seen: list[int | None] = []

    class Listener:
        def on_heartbeat(self, revision):
            seen.append(revision)
            raise RuntimeError("fallo del listener")

    class HeartbeatTransport:
        def __init__(self, body: bytes) -> None:
            self.body = body

        def post_json(self, url, payload, *, headers, timeout_seconds):
            return SyncHttpResponse(200, self.body)

    v11 = AgentHeartbeatSender(
        settings,
        transport=HeartbeatTransport(b'{"config_revision": 6}'),
        hostname="srv",
        config_listener=Listener(),
    ).run_once()
    v10 = AgentHeartbeatSender(
        settings,
        transport=HeartbeatTransport(b'{"presence": "online"}'),
        hostname="srv",
        config_listener=Listener(),
    ).run_once()

    assert v11.sent is True and v11.config_revision == 6
    assert v10.sent is True and v10.config_revision is None
    assert seen == [6, None]


# ---------------------------------------------- aplicación en el agente


def test_local_mode_rejects_central_change_and_keeps_agent_env(tmp_path: Path) -> None:
    transport = FakeTransport(config={"revision": 2, "response_mode": "automatic"})
    agent, events = build_agent(
        tmp_path,
        transport,
        response_mode="assisted",
        allow_temporary_ip_block=True,
    )
    executor_before = agent.response_executor

    agent.remote_config.on_heartbeat(2)
    agent._process_remote_config()

    assert agent.settings.response_mode == "assisted"
    assert agent.response_policy.mode == "assisted"
    assert agent.response_executor is executor_before
    assert not agent.settings.response_config_file.exists()
    assert transport.posts == [
        (
            "https://central.example/agent/config/state",
            {
                "applied_revision": 2,
                "effective_response_mode": "assisted",
                "config_source": "local",
                "blocking_enabled": True,
                "status": "rejected",
                "reason": LOCAL_MANAGEMENT_REASON,
            },
        )
    ]
    assert [event["event_type"] for event in events] == ["AGENT_CONFIG_REJECTED"]


def test_central_mode_applies_and_rebuilds_every_mode_component(
    tmp_path: Path,
) -> None:
    transport = FakeTransport(config={"revision": 4, "response_mode": "assisted"})
    agent, events = build_agent(
        tmp_path,
        transport,
        response_mode="audit_only",
        response_mode_source="central",
        allow_temporary_ip_block=True,
    )
    assert agent.approval_executor is None

    agent.remote_config.on_heartbeat(4)
    # El hilo de heartbeat nunca cambia el modo.
    assert agent.settings.response_mode == "audit_only"
    agent._process_remote_config()

    policy = agent.response_policy
    assert agent.settings.response_mode == "assisted"
    assert policy.mode == "assisted"
    assert isinstance(agent.response_engine, ResponsePolicyEngine)
    assert agent.response_engine.policy is policy
    assert agent.recurrence_tracker.policy is policy
    assert agent.response_executor.policy is policy
    assert agent.response_executor.dry_run is True
    assert agent.approval_executor is not None
    assert agent.approval_executor.policy is policy
    assert agent.approval_client.settings is agent.settings
    assert load_local_response_config(agent.settings.response_config_file) == (
        LocalResponseConfig(4, "assisted")
    )
    assert transport.posts[-1][1] == {
        "applied_revision": 4,
        "effective_response_mode": "assisted",
        "config_source": "central",
        "blocking_enabled": True,
        "status": "applied",
    }
    assert [event["event_type"] for event in events] == ["AGENT_CONFIG_APPLIED"]
    assert agent.remote_config.processed_revision == 4


def test_automatic_without_allow_flags_does_not_really_block(tmp_path: Path) -> None:
    transport = FakeTransport(config={"revision": 1, "response_mode": "automatic"})
    agent, _ = build_agent(tmp_path, transport, response_mode_source="central")

    agent.remote_config.on_heartbeat(1)
    agent._process_remote_config()

    assert agent.settings.response_mode == "automatic"
    assert agent.response_executor.dry_run is True
    assert agent.settings.allow_temporary_ip_block is False
    assert transport.posts[-1][1]["blocking_enabled"] is False
    result = agent.response_executor.execute(decision("198.51.100.20"))
    assert result.executed is False


def test_automatic_from_central_keeps_every_protection(tmp_path: Path) -> None:
    transport = FakeTransport(config={"revision": 1, "response_mode": "automatic"})
    agent, _ = build_agent(
        tmp_path,
        transport,
        response_mode_source="central",
        allow_temporary_ip_block=True,
    )
    agent.event_repository.initialize()

    agent.remote_config.on_heartbeat(1)
    agent._process_remote_config()

    executor = agent.response_executor
    assert executor.dry_run is False
    resolver = executor.protection_resolver
    assert isinstance(resolver, ResponseProtectionResolver)
    assert resolver.trusted_admin_ips == (TRUSTED_ADMIN,)
    assert TRUSTED_ADMIN in agent.response_policy.trusted_admin_ips

    backend = FakeBackend()
    executor.backend = backend  # type: ignore[assignment]
    session_ip, local_ip, gateway_ip = "198.51.100.30", "192.0.2.40", "192.0.2.1"
    resolver.resolve = lambda: ProtectionSnapshot(  # type: ignore[method-assign]
        configured_ips=frozenset({TRUSTED_ADMIN}),
        ssh_peer_ips=frozenset({session_ip}),
        local_ips=frozenset({local_ip}),
        gateway_ips=frozenset({gateway_ip}),
    )

    for protected in (
        TRUSTED_ADMIN,  # trusted admin
        "100.100.10.20",  # Tailscale
        "127.0.0.1",  # loopback local
        local_ip,  # IP local
        gateway_ip,  # gateway
        session_ip,  # sesión SSH administrativa activa
    ):
        result = executor.execute(
            decision(protected),
            response_event_id=uuid4(),
            execution_event_id=uuid4(),
        )
        assert result.executed is False, protected
        assert result.protection_rejected is True, protected
    assert backend.added == []

    allowed = executor.execute(
        decision("198.51.100.99"),
        response_event_id=uuid4(),
        execution_event_id=uuid4(),
    )
    assert allowed.executed is True
    assert str(ip_address(backend.added[0].target_ip)) == "198.51.100.99"


def test_failed_persistence_leaves_previous_state_intact(
    tmp_path: Path, monkeypatch
) -> None:
    transport = FakeTransport(config={"revision": 2, "response_mode": "automatic"})
    agent, events = build_agent(
        tmp_path,
        transport,
        response_mode="assisted",
        response_mode_source="central",
        allow_temporary_ip_block=True,
    )
    before = (
        agent.settings,
        agent.response_policy,
        agent.response_engine,
        agent.recurrence_tracker,
        agent.response_executor,
        agent.approval_executor,
    )

    def broken_save(*_args, **_kwargs):
        raise OSError("disco lleno")

    monkeypatch.setattr(
        "app.agent.continuous_agent.save_local_response_config", broken_save
    )
    agent.remote_config.on_heartbeat(2)
    agent._process_remote_config()

    assert (
        agent.settings,
        agent.response_policy,
        agent.response_engine,
        agent.recurrence_tracker,
        agent.response_executor,
        agent.approval_executor,
    ) == before
    assert transport.posts[-1][1]["status"] == "rejected"
    assert transport.posts[-1][1]["effective_response_mode"] == "assisted"
    assert [event["event_type"] for event in events] == ["AGENT_CONFIG_REJECTED"]


def test_component_build_failure_leaves_previous_state_intact(
    tmp_path: Path, monkeypatch
) -> None:
    transport = FakeTransport(config={"revision": 2, "response_mode": "assisted"})
    agent, _ = build_agent(
        tmp_path,
        transport,
        response_mode="audit_only",
        response_mode_source="central",
        allow_temporary_ip_block=True,
    )
    policy_before = agent.response_policy

    def broken(*_args, **_kwargs):
        raise RuntimeError("fallo al construir")

    monkeypatch.setattr(agent, "_build_approval_executor", broken)
    agent.remote_config.on_heartbeat(2)
    agent._process_remote_config()

    assert agent.settings.response_mode == "audit_only"
    assert agent.response_policy is policy_before
    assert not agent.settings.response_config_file.exists()


def test_report_failure_is_retried_without_reapplying(tmp_path: Path) -> None:
    transport = FakeTransport(
        config={"revision": 1, "response_mode": "assisted"},
        post_status=503,
    )
    agent, events = build_agent(tmp_path, transport, response_mode_source="central")

    agent.remote_config.on_heartbeat(1)
    agent._process_remote_config()
    transport.post_status = 200
    agent._process_remote_config()

    assert [payload["status"] for _, payload in transport.posts] == [
        "applied",
        "applied",
    ]
    assert [event["event_type"] for event in events] == ["AGENT_CONFIG_APPLIED"]


def test_rejected_report_from_central_is_not_retried_in_loop(tmp_path: Path) -> None:
    transport = FakeTransport(
        config={"revision": 1, "response_mode": "assisted"},
        post_status=409,
    )
    agent, events = build_agent(tmp_path, transport, response_mode_source="central")

    agent.remote_config.on_heartbeat(1)
    agent._process_remote_config()
    agent._process_remote_config()
    agent._process_remote_config()

    assert len(transport.posts) == 1
    assert [event["event_type"] for event in events] == [
        "AGENT_CONFIG_APPLIED",
        "AGENT_CONFIG_REPORT_REJECTED",
    ]


def test_run_once_applies_pending_config_before_monitoring(
    tmp_path: Path, monkeypatch
) -> None:
    transport = FakeTransport(config={"revision": 1, "response_mode": "assisted"})
    agent, _ = build_agent(tmp_path, transport, response_mode_source="central")
    observed: list[str] = []
    monkeypatch.setattr(
        agent,
        "_reconcile_expired_response_blocks",
        lambda: observed.append(agent.settings.response_mode),
    )
    monkeypatch.setattr(agent, "load_state", lambda: None)
    monkeypatch.setattr(agent, "initialize_baseline", lambda: {})

    agent.remote_config.on_heartbeat(1)
    agent.run_once()

    assert observed == ["assisted"]


# ------------------------------------------- extremo a extremo con el central


class ClientTransport:
    """Transporte del agente enrutado al TestClient del central v1.1."""

    def __init__(self, client) -> None:
        self.client = client

    def post_json(self, url, payload, *, headers, timeout_seconds):
        response = self.client.post(urlsplit(url).path, json=payload, headers=headers)
        return SyncHttpResponse(response.status_code, response.content)

    def get_json(self, url, *, headers, timeout_seconds):
        response = self.client.get(urlsplit(url).path, headers=headers)
        return SyncHttpResponse(response.status_code, response.content)


@pytest.mark.parametrize("source", ["central", "local"])
def test_end_to_end_mode_change_through_real_central(
    tmp_path: Path, source: str
) -> None:
    auth = AuthRepository(
        tmp_path / "central-auth" / "auth.db", scrypt_parameters=TEST_SCRYPT
    )
    admin_id = int(
        auth.create_user(
            username="admin", password=TEST_PASSWORD, role="superadmin"
        )["id"]
    )
    central_settings = CentralSettings(
        database_file=tmp_path / "central" / "central.db"
    )
    app = create_app(
        settings=make_settings(tmp_path / "api"),
        auth_settings=AuthSettings(
            database_file=auth.database_path,
            central_url="https://central.example",
        ),
        auth_repository=auth,
        central_settings=central_settings,
        central_repository=CentralEventRepository(central_settings.database_file),
    )
    agent_client = TestClient(app)
    token = auth.create_agent_registration_token(admin_id)
    enrolled = auth.enroll_agent(registration_token=token.token, hostname="srv-web-01")
    agent_id = str(enrolled.agent["agent_id"])

    settings = make_settings(
        tmp_path / "agent",
        response_mode="assisted",
        response_mode_source=source,
    )
    save_identity(
        {
            "agent_id": agent_id,
            "credential": enrolled.credential,
            "central_url": "https://central.example",
        },
        settings.identity_file,
    )
    agent = ContinuousAgent(interval=1, settings=settings)
    agent.emit = lambda **_kwargs: None  # type: ignore[method-assign]
    transport = ClientTransport(agent_client)
    agent.remote_config.transport = transport
    agent.heartbeat_sender.transport = transport

    # Arranque: estado inicial + primer heartbeat (marca config_protocol).
    agent.remote_config.queue_report(
        agent._config_state_report(revision=0, status="applied")
    )
    assert agent.heartbeat_sender.run_once().sent is True
    stored = auth.get_agent(agent_id)
    assert stored["config_protocol"] == 1
    assert stored["effective_response_mode"] == "assisted"
    assert stored["config_source"] == source
    assert stored["agent_version"] is not None

    admin = TestClient(app)
    login = admin.post(
        "/auth/login", json={"username": "admin", "password": TEST_PASSWORD}
    ).json()
    changed = admin.put(
        f"/agents/{agent_id}/response-mode",
        headers={"X-CSRF-Token": login["csrf_token"]},
        json={"response_mode": "automatic", "expected_revision": 0},
    )
    assert changed.status_code == 200
    assert changed.json()["config_pending"] is True

    agent.heartbeat_sender.run_once()  # detecta la revisión y la deja pendiente
    assert agent.settings.response_mode == "assisted"
    agent._process_remote_config()  # inicio de run_once

    final = admin.get(f"/agents/{agent_id}").json()
    if source == "central":
        assert agent.settings.response_mode == "automatic"
        assert final["effective_response_mode"] == "automatic"
        assert final["applied_config_revision"] == 1
        assert final["config_pending"] is False
        assert final["config_status"] == "applied"
        assert final["config_status_revision"] == 1
        # automatic sin allow flags locales: no hay bloqueo real.
        assert final["blocking_enabled"] is False
    else:
        assert agent.settings.response_mode == "assisted"
        assert final["effective_response_mode"] == "assisted"
        assert final["config_source"] == "local"
        # MODE_SOURCE=local termina en REJECTED, no en PENDING.
        assert final["config_status"] == "rejected"
        assert final["config_status_revision"] == 1
        assert final["config_status_reason"] == LOCAL_MANAGEMENT_REASON
        assert final["config_pending"] is False
        assert final["applied_config_revision"] == 0
