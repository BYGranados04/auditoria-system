from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from app.api.main import create_app
from app.auth.config import AuthSettings
from app.auth.repository import AuthRepository
from app.central.config import CentralSettings
from app.central.repository import CentralEventRepository
from app.core.config import AgentSettings
from app.core.events import SecurityEvent
from tests.api_test_helpers import TEST_PASSWORD, TEST_SCRYPT

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)


def build_application(tmp_path: Path, current: list[datetime]):
    settings = AgentSettings(
        interval=1,
        state_dir=tmp_path / "state",
        log_dir=tmp_path / "logs",
        identity_file=tmp_path / "agent-identity.json",
    )
    auth = AuthRepository(
        tmp_path / "auth" / "auth.db",
        scrypt_parameters=TEST_SCRYPT,
    )
    users = {}
    for username, role in (
        ("admin", "superadmin"),
        ("viewer-a", "viewer"),
        ("viewer-b", "viewer"),
    ):
        users[username] = int(
            auth.create_user(
                username=username,
                password=TEST_PASSWORD,
                role=role,
                now=NOW,
            )["id"]
        )
    identities = {}
    for username in ("viewer-a", "viewer-b"):
        token = auth.create_agent_registration_token(users[username], now=NOW)
        enrolled = auth.enroll_agent(
            registration_token=token.token,
            hostname="shared-host",
            now=NOW,
        )
        identities[username] = {
            "agent_id": str(enrolled.agent["agent_id"]),
            "credential": enrolled.credential,
        }
    central_settings = CentralSettings(
        database_file=tmp_path / "central" / "central.db"
    )
    central = CentralEventRepository(
        central_settings.database_file,
        clock=lambda: current[0],
    )
    app = create_app(
        settings=settings,
        auth_settings=AuthSettings(
            database_file=auth.database_path,
            agent_offline_after_seconds=120,
        ),
        auth_repository=auth,
        central_settings=central_settings,
        central_repository=central,
        clock=lambda: current[0],
    )
    return TestClient(app), central, identities


def login(client: TestClient, username: str) -> None:
    response = client.post(
        "/auth/login",
        json={"username": username, "password": TEST_PASSWORD},
    )
    assert response.status_code == 200


def test_status_agent_scope_and_presence_use_heartbeat_only(tmp_path: Path) -> None:
    current = [NOW]
    root, _, identities = build_application(tmp_path, current)
    viewer_a = TestClient(root.app)
    admin = TestClient(root.app)
    login(viewer_a, "viewer-a")
    login(admin, "admin")
    agent_a = identities["viewer-a"]
    agent_b = identities["viewer-b"]

    unknown = viewer_a.get("/status", params={"agent_id": agent_a["agent_id"]})
    heartbeat = root.post(
        "/agent/heartbeat",
        headers={"Authorization": f"Bearer {agent_a['credential']}"},
        json={},
    )
    online = viewer_a.get("/status", params={"agent_id": agent_a["agent_id"]})
    foreign = viewer_a.get("/status", params={"agent_id": agent_b["agent_id"]})
    missing = viewer_a.get("/status", params={"agent_id": "agt_missing"})
    admin_b = admin.get("/status", params={"agent_id": agent_b["agent_id"]})

    assert unknown.json()["presence"] == "unknown"
    assert heartbeat.status_code == 200
    assert online.json()["presence"] == "online"
    assert online.json()["hostname"] == "shared-host"
    assert online.json()["total_events"] == 0
    assert foreign.status_code == 404
    assert missing.status_code == 404
    assert admin_b.status_code == 200
    assert admin_b.json()["agent_id"] == agent_b["agent_id"]

    current[0] += timedelta(seconds=121)
    offline = viewer_a.get("/status", params={"agent_id": agent_a["agent_id"]})
    assert offline.json()["presence"] == "offline"
    assert offline.json()["total_events"] == 0


def test_status_uses_central_events_and_marks_local_fields_unavailable(
    tmp_path: Path,
) -> None:
    current = [NOW]
    root, central, identities = build_application(tmp_path, current)
    agent_a = identities["viewer-a"]
    central.add_event(
        agent_id=agent_a["agent_id"],
        event=SecurityEvent(
            timestamp=NOW,
            agent_id=agent_a["agent_id"],
            hostname="shared-host",
            source="test",
            category="detection",
            event_type="TEST_DETECTION",
            severity="high",
            description="Evento central.",
            evidence={},
        ),
    )
    viewer = TestClient(root.app)
    login(viewer, "viewer-a")

    body = viewer.get(
        "/status", params={"agent_id": agent_a["agent_id"]}
    ).json()

    assert body["status"] == "ok"
    assert body["service"] == "auditoria-system-api"
    assert body["total_events"] == 1
    assert body["by_severity"]["high"] == 1
    assert body["response_mode"] is None
    assert body["automatic_blocking_enabled"] is None
    assert body["live_response_blocks"] is None


def test_status_does_not_create_missing_central_database(tmp_path: Path) -> None:
    current = [NOW]
    root, central, identities = build_application(tmp_path, current)
    viewer = TestClient(root.app)
    login(viewer, "viewer-a")

    assert not central.database_path.exists()
    response = viewer.get(
        "/status",
        params={"agent_id": identities["viewer-a"]["agent_id"]},
    )

    assert response.status_code == 200
    assert response.json()["total_events"] == 0
    assert not central.database_path.exists()
