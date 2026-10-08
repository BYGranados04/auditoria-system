import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.agent.heartbeat import AgentHeartbeatSender, AgentHeartbeatWorker
from app.agent.registration import save_identity
from app.agent.sync import SyncHttpResponse
from app.agent.version import agent_version
from app.api.main import create_app
from app.auth.config import AuthSettings
from app.auth.repository import AuthRepository
from app.core.config import AgentSettings
from app.storage.event_repository import EventRepository
from tests.api_test_helpers import TEST_PASSWORD, TEST_SCRYPT

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)


class FakeTransport:
    def __init__(self, response: object) -> None:
        self.response = response
        self.calls: list[dict[str, object]] = []

    def post_json(
        self,
        url: str,
        payload: dict[str, object],
        *,
        headers: dict[str, str],
        timeout_seconds: int,
    ) -> SyncHttpResponse:
        self.calls.append(
            {
                "url": url,
                "payload": payload,
                "headers": headers,
                "timeout_seconds": timeout_seconds,
            }
        )
        if isinstance(self.response, BaseException):
            raise self.response
        assert isinstance(self.response, SyncHttpResponse)
        return self.response


def settings(tmp_path: Path) -> AgentSettings:
    return AgentSettings(
        interval=1,
        state_dir=tmp_path / "state",
        log_dir=tmp_path / "logs",
        identity_file=tmp_path / "identity.json",
        sync_timeout_seconds=7,
        sync_retry_max_seconds=300,
        heartbeat_interval=30,
        agent_offline_after_seconds=120,
    )


def build_application(
    tmp_path: Path,
    current: list[datetime],
) -> tuple[TestClient, AuthRepository, dict[str, int]]:
    agent_settings = settings(tmp_path)
    agent_settings.state_dir.mkdir(parents=True)
    repository = EventRepository(agent_settings.database_file)
    repository.initialize()
    auth = AuthRepository(
        tmp_path / "auth" / "auth.db",
        scrypt_parameters=TEST_SCRYPT,
    )
    users = {
        name: int(
            auth.create_user(
                username=name,
                password=TEST_PASSWORD,
                role=role,
            )["id"]
        )
        for name, role in (("admin", "superadmin"), ("owner-a", "viewer"))
    }
    return (
        TestClient(
            create_app(
                settings=agent_settings,
                repository=repository,
                auth_settings=AuthSettings(
                    database_file=auth.database_path,
                    central_url="https://central.example",
                    agent_offline_after_seconds=120,
                ),
                auth_repository=auth,
                clock=lambda: current[0],
            )
        ),
        auth,
        users,
    )


def enroll(auth: AuthRepository, owner_user_id: int, hostname: str) -> dict[str, str]:
    token = auth.create_agent_registration_token(owner_user_id, now=NOW)
    enrolled = auth.enroll_agent(
        registration_token=token.token,
        hostname=hostname,
        now=NOW,
    )
    return {
        "agent_id": str(enrolled.agent["agent_id"]),
        "credential": enrolled.credential,
    }


def heartbeat(
    client: TestClient,
    credential: str,
    body: dict[str, object] | None = None,
):
    return client.post(
        "/agent/heartbeat",
        headers={"Authorization": f"Bearer {credential}"},
        json=body or {},
    )


def test_presence_is_derived_from_central_clock(tmp_path: Path) -> None:
    current = [NOW]
    client, auth, users = build_application(tmp_path, current)
    identity = enroll(auth, users["owner-a"], "agent-a")

    assert auth.get_agent(identity["agent_id"], now=current[0])["presence"] == "unknown"
    assert client.post(
        "/auth/login",
        json={"username": "owner-a", "password": TEST_PASSWORD},
    ).status_code == 200
    assert client.get("/agents").json()[0]["presence"] == "unknown"
    assert heartbeat(client, identity["credential"]).json()["presence"] == "online"
    current[0] += timedelta(seconds=120)
    assert auth.get_agent(identity["agent_id"], now=current[0])["presence"] == "online"
    assert client.get("/agents").json()[0]["presence"] == "online"
    current[0] += timedelta(seconds=1)
    assert auth.get_agent(identity["agent_id"], now=current[0])["presence"] == "offline"
    current[0] += timedelta(seconds=29)
    assert heartbeat(client, identity["credential"]).json()["presence"] == "online"


def test_heartbeat_uses_credential_not_body_identity_or_client_time(
    tmp_path: Path,
) -> None:
    current = [NOW]
    client, auth, users = build_application(tmp_path, current)
    agent_a = enroll(auth, users["owner-a"], "agent-a")
    agent_b = enroll(auth, users["owner-a"], "agent-b")

    spoofed = heartbeat(
        client,
        agent_a["credential"],
        {"agent_id": agent_b["agent_id"]},
    )
    client_time = heartbeat(
        client,
        agent_a["credential"],
        {"last_seen_at": "2099-01-01T00:00:00Z"},
    )
    accepted = heartbeat(
        client,
        agent_a["credential"],
        {"agent_id": agent_a["agent_id"], "hostname": "untrusted-name"},
    )

    assert spoofed.status_code == 401
    assert client_time.status_code == 422
    assert accepted.status_code == 200
    assert accepted.json()["agent_id"] == agent_a["agent_id"]
    with sqlite3.connect(auth.database_path) as connection:
        rows = connection.execute(
            "SELECT agent_id, hostname, last_seen_at FROM agents ORDER BY hostname"
        ).fetchall()
    assert rows == [
        (agent_a["agent_id"], "agent-a", NOW.isoformat()),
        (agent_b["agent_id"], "agent-b", None),
    ]


@pytest.mark.parametrize("header", [{}, {"Authorization": "Basic nope"}])
def test_missing_or_malformed_authorization_is_rejected(
    tmp_path: Path,
    header: dict[str, str],
) -> None:
    current = [NOW]
    client, _, _ = build_application(tmp_path, current)

    assert client.post("/agent/heartbeat", headers=header, json={}).status_code == 401


def test_invalid_revoked_and_inactive_credentials_are_rejected(tmp_path: Path) -> None:
    current = [NOW]
    client, auth, users = build_application(tmp_path, current)
    identity = enroll(auth, users["owner-a"], "agent-a")
    assert heartbeat(client, "agc_invalid").status_code == 401
    with sqlite3.connect(auth.database_path) as connection:
        connection.execute(
            "UPDATE agent_credentials SET revoked_at = ? WHERE agent_id = ?",
            (NOW.isoformat(), identity["agent_id"]),
        )
    assert heartbeat(client, identity["credential"]).status_code == 401

    other = enroll(auth, users["owner-a"], "agent-b")
    auth.set_user_active(
        users["owner-a"],
        active=False,
        actor_user_id=users["admin"],
        now=NOW,
    )
    assert heartbeat(client, other["credential"]).status_code == 401


def install_identity(
    agent_settings: AgentSettings,
    central_url: str = "https://central.example/",
) -> None:
    save_identity(
        {
            "agent_id": "agt_local",
            "credential": "agc_test_credential",
            "central_url": central_url,
        },
        agent_settings.identity_file,
    )


def test_heartbeat_sender_posts_periodically_with_metadata_only(tmp_path: Path) -> None:
    agent_settings = settings(tmp_path)
    install_identity(agent_settings, "https://central.example/auditoria/")
    transport = FakeTransport(SyncHttpResponse(200, b"{}"))

    result = AgentHeartbeatSender(
        agent_settings, transport=transport, hostname="agent-host"
    ).run_once()

    assert result.sent is True
    assert result.next_delay_seconds == 30
    assert transport.calls[0]["url"] == "https://central.example/auditoria/agent/heartbeat"
    assert transport.calls[0]["payload"] == {
        "hostname": "agent-host",
        "agent_version": agent_version(),
    }
    assert transport.calls[0]["headers"] == {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": "Bearer agc_test_credential",
    }
    assert transport.calls[0]["timeout_seconds"] == 7


@pytest.mark.parametrize(
    ("response", "delay"),
    [
        (SyncHttpResponse(401, b"denied"), 300),
        (SyncHttpResponse(403, b"denied"), 300),
        (SyncHttpResponse(422, b"invalid"), 300),
        (SyncHttpResponse(429, b"slow"), 30),
        (SyncHttpResponse(500, b"error"), 30),
        (TimeoutError(), 30),
    ],
)
def test_heartbeat_failures_are_safe_and_do_not_retry_aggressively(
    tmp_path: Path,
    response: object,
    delay: int,
) -> None:
    agent_settings = settings(tmp_path)
    install_identity(agent_settings)
    transport = FakeTransport(response)

    result = AgentHeartbeatSender(agent_settings, transport=transport).run_once()

    assert result.sent is False
    assert result.next_delay_seconds == delay
    assert len(transport.calls) == 1


def test_missing_or_invalid_identity_makes_no_http_request(tmp_path: Path) -> None:
    agent_settings = settings(tmp_path)
    transport = FakeTransport(SyncHttpResponse(200, b"{}"))
    assert AgentHeartbeatSender(agent_settings, transport=transport).run_once().skipped
    agent_settings.identity_file.write_text(json.dumps({"agent_id": "agt"}))
    assert AgentHeartbeatSender(agent_settings, transport=transport).run_once().skipped
    assert transport.calls == []


def test_worker_has_one_thread_and_stops_cleanly(tmp_path: Path) -> None:
    agent_settings = settings(tmp_path)
    install_identity(agent_settings)
    transport = FakeTransport(SyncHttpResponse(401, b"denied"))
    worker = AgentHeartbeatWorker(
        AgentHeartbeatSender(agent_settings, transport=transport)
    )
    worker.start()
    first_thread = worker._thread
    worker.start()
    worker.stop()
    worker.join(timeout=1)

    assert first_thread is worker._thread
    assert first_thread is not None
    assert not first_thread.is_alive()
