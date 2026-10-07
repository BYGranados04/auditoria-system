from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.api.main import create_app
from app.auth.config import AuthSettings
from app.auth.repository import AuthRepository
from app.core.config import AgentSettings
from app.notifications.repository import NotificationRepository
from app.storage.event_repository import EventRepository
from tests.api_test_helpers import TEST_PASSWORD, TEST_SCRYPT


def build_client(tmp_path: Path, *, populate_notifications: bool = True):
    settings = AgentSettings(
        interval=1, state_dir=tmp_path / "state", log_dir=tmp_path / "logs",
        identity_file=tmp_path / "agent-identity.json",
    )
    settings.state_dir.mkdir(parents=True)
    auth = AuthRepository(tmp_path / "auth.db", scrypt_parameters=TEST_SCRYPT)
    users = {}
    for name, role in (
        ("admin", "superadmin"),
        ("viewer-a", "viewer"),
        ("viewer-b", "viewer"),
        ("viewer-empty", "viewer"),
    ):
        users[name] = int(
            auth.create_user(username=name, password=TEST_PASSWORD, role=role)["id"]
        )
    agents = {}
    for name, hostname in (("viewer-a", "host-a"), ("viewer-b", "host-b")):
        token = auth.create_agent_registration_token(users[name])
        enrolled = auth.enroll_agent(
            registration_token=token.token, hostname=hostname
        )
        agents[name] = str(enrolled.agent["agent_id"])
    notifications = NotificationRepository(settings.state_dir / "notifications.db")
    if populate_notifications:
        for owner, hostname, severity, status in (
            ("viewer-a", "host-a", "high", "sent"),
            ("viewer-b", "host-b", "critical", "failed"),
        ):
            attempt, _ = notifications.create_pending(
                event_id=str(uuid4()),
                agent_id=agents[owner],
                provider="resend",
                recipient="ops@example.test",
                hostname=hostname,
                severity=severity,
            )
            notifications.complete(
                attempt.id,
                provider_message_id="msg" if status == "sent" else None,
                error="failed" if status == "failed" else None,
            )
    app = create_app(
        settings=settings,
        repository=EventRepository(settings.database_file),
        auth_settings=AuthSettings(database_file=auth.database_path),
        auth_repository=auth,
    )
    return TestClient(app), notifications, agents


def login(client, username):
    response = client.post(
        "/auth/login", json={"username": username, "password": TEST_PASSWORD}
    )
    assert response.status_code == 200


def test_notifications_require_session(tmp_path):
    client, _, _ = build_client(tmp_path)
    assert client.get("/notifications").status_code == 401


def test_viewer_scope_and_detail_are_enforced(tmp_path):
    root, notifications, agents = build_client(tmp_path)
    viewer_a, viewer_b = TestClient(root.app), TestClient(root.app)
    login(viewer_a, "viewer-a")
    login(viewer_b, "viewer-b")
    own = viewer_a.get("/notifications")
    other = next(item for item in notifications.list() if item.hostname == "host-b")
    assert [item["hostname"] for item in own.json()] == ["host-a"]
    assert [item["agent_id"] for item in own.json()] == [agents["viewer-a"]]
    assert viewer_b.get(f"/notifications/{other.id}").status_code == 200
    assert viewer_a.get(f"/notifications/{other.id}").status_code == 404


def test_superadmin_filters_and_summary(tmp_path):
    client, _, _ = build_client(tmp_path)
    login(client, "admin")
    assert len(client.get("/notifications").json()) == 2
    assert [
        item["status"]
        for item in client.get("/notifications", params={"status": "failed"}).json()
    ] == ["failed"]
    assert [
        item["hostname"]
        for item in client.get("/notifications", params={"hostname": "host-a"}).json()
    ] == ["host-a"]
    assert client.get("/notifications", params={"limit": 0}).status_code == 422
    assert client.get("/notifications/summary").json() == {
        "total": 2,
        "pending": 0,
        "sent": 1,
        "failed": 1,
        "high": 1,
        "critical": 1,
    }


def test_viewer_empty_scope_and_summary(tmp_path):
    root, _, _ = build_client(tmp_path)
    client = TestClient(root.app)
    login(client, "viewer-empty")
    assert client.get("/notifications").json() == []
    assert client.get("/notifications/summary").json()["total"] == 0


def test_agent_scope_isolated_with_same_hostname_and_legacy_hidden(tmp_path):
    root, notifications, agents = build_client(
        tmp_path, populate_notifications=False
    )
    for owner in ("viewer-a", "viewer-b"):
        attempt, _ = notifications.create_pending(
            event_id=str(uuid4()),
            agent_id=agents[owner],
            provider="resend",
            recipient="ops@example.test",
            hostname="shared-host",
            severity="high",
        )
        notifications.complete(attempt.id, provider_message_id=f"msg-{owner}")
    legacy, _ = notifications.create_pending(
        event_id=str(uuid4()),
        provider="resend",
        recipient="ops@example.test",
        hostname="shared-host",
        severity="high",
    )
    notifications.complete(legacy.id, provider_message_id="msg-legacy")

    viewer_a = TestClient(root.app)
    viewer_b = TestClient(root.app)
    admin = TestClient(root.app)
    login(viewer_a, "viewer-a")
    login(viewer_b, "viewer-b")
    login(admin, "admin")

    own_a = viewer_a.get(
        "/notifications", params={"hostname": "shared-host"}
    ).json()
    own_b = viewer_b.get(
        "/notifications", params={"hostname": "shared-host"}
    ).json()

    assert [item["agent_id"] for item in own_a] == [agents["viewer-a"]]
    assert [item["agent_id"] for item in own_b] == [agents["viewer-b"]]
    assert viewer_a.get(f"/notifications/{legacy.id}").status_code == 404
    assert len(admin.get("/notifications").json()) == 3


def test_api_returns_empty_results_without_notifications_database(tmp_path):
    client, notifications, _ = build_client(
        tmp_path, populate_notifications=False
    )
    assert not notifications.database_path.exists()
    login(client, "admin")

    assert client.get("/notifications").json() == []
    assert client.get("/notifications/summary").json() == {
        "total": 0,
        "pending": 0,
        "sent": 0,
        "failed": 0,
        "high": 0,
        "critical": 0,
    }
    assert client.get("/notifications/1").status_code == 404
    assert not notifications.database_path.exists()


def test_read_only_repository_cannot_modify_existing_database(tmp_path):
    _, writable, _ = build_client(tmp_path)
    before = writable.database_path.read_bytes()
    read_only = NotificationRepository(writable.database_path, read_only=True)

    assert len(read_only.list()) == 2
    with pytest.raises(RuntimeError, match="solo lectura"):
        read_only.initialize()
    with pytest.raises(RuntimeError, match="solo lectura"):
        read_only.complete(1)
    assert writable.database_path.read_bytes() == before


def test_dashboard_notifications_is_authenticated_and_safe(tmp_path):
    client, _, _ = build_client(tmp_path)
    assert (
        client.get("/dashboard/notifications", follow_redirects=False).status_code
        == 303
    )
    login(client, "admin")
    assert client.get("/dashboard/notifications").status_code == 200
