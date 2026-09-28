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
from app.storage.event_repository import EventRepository
from tests.api_test_helpers import TEST_PASSWORD, TEST_SCRYPT


def add_host_events(repository: EventRepository, hostname: str) -> None:
    for category, event_type, severity, evidence in (
        ("system", "AGENT_STARTED", "low", {}),
        (
            "detection",
            "SSH_BRUTE_FORCE_ATTEMPT",
            "high",
            {"source_ip": "192.0.2.10"},
        ),
        (
            "response",
            "RESPONSE_DECISION",
            "medium",
            {"target_ip": "192.0.2.10", "action": "block"},
        ),
    ):
        repository.add(
            SecurityEvent(
                hostname=hostname,
                source="test",
                category=category,
                event_type=event_type,
                severity=severity,
                description=f"Evento de {hostname}",
                evidence=evidence,
            )
        )


def build_scoped_application(
    tmp_path: Path,
) -> tuple[TestClient, AuthRepository, Path, dict[str, int]]:
    settings = AgentSettings(
        interval=1,
        state_dir=tmp_path / "state",
        log_dir=tmp_path / "logs",
    )
    settings.state_dir.mkdir(parents=True)
    writable = EventRepository(settings.database_file)
    writable.initialize()
    now = datetime.now(UTC)
    for index, hostname in enumerate(("host-a", "host-b"), start=1):
        add_host_events(writable, hostname)
        writable.create_response_block(
            block_id=f"block-{index}",
            detection_event_id=f"detection-{index}",
            response_event_id=f"response-{index}",
            hostname=hostname,
            target_ip=f"192.0.2.{index}",
            family="ip",
            duration_seconds=3600,
            requested_at=now,
            expires_at=now + timedelta(hours=1),
        )

    auth_database = tmp_path / "auth" / "auth.db"
    auth_repository = AuthRepository(auth_database, scrypt_parameters=TEST_SCRYPT)
    central_settings = CentralSettings(
        database_file=tmp_path / "central" / "central.db"
    )
    central_repository = CentralEventRepository(central_settings.database_file)
    users = {}
    for username, role, hostnames in (
        ("admin", "superadmin", None),
        ("viewer-a", "viewer", ("host-a",)),
        ("viewer-b", "viewer", ("host-b",)),
    ):
        user = auth_repository.create_user(
            username=username,
            password=TEST_PASSWORD,
            role=role,
        )
        users[username] = int(user["id"])
        if hostnames:
            for hostname in hostnames:
                registration = auth_repository.create_agent_registration_token(
                    int(user["id"])
                )
                enrolled = auth_repository.enroll_agent(
                    registration_token=registration.token,
                    hostname=hostname,
                )
                for category, event_type, severity, evidence in (
                    ("system", "AGENT_STARTED", "low", {}),
                    (
                        "detection",
                        "SSH_BRUTE_FORCE_ATTEMPT",
                        "high",
                        {"source_ip": "192.0.2.10"},
                    ),
                    (
                        "response",
                        "RESPONSE_DECISION",
                        "medium",
                        {"target_ip": "192.0.2.10", "action": "block"},
                    ),
                ):
                    central_repository.add_event(
                        agent_id=str(enrolled.agent["agent_id"]),
                        event=SecurityEvent(
                            hostname=hostname,
                            source="test",
                            category=category,
                            event_type=event_type,
                            severity=severity,
                            description=f"Evento central de {hostname}",
                            evidence=evidence,
                        ),
                    )

    application = create_app(
        settings=settings,
        repository=EventRepository(settings.database_file, read_only=True),
        auth_settings=AuthSettings(
            database_file=auth_database,
            central_url="https://central.example",
        ),
        auth_repository=auth_repository,
        central_settings=central_settings,
        central_repository=central_repository,
    )
    return TestClient(application), auth_repository, settings.database_file, users


def login_as(client: TestClient, username: str) -> dict[str, object]:
    response = client.post(
        "/auth/login",
        json={"username": username, "password": TEST_PASSWORD},
    )
    assert response.status_code == 200
    return response.json()


def csrf_headers(login_response: dict[str, object]) -> dict[str, str]:
    return {"X-CSRF-Token": str(login_response["csrf_token"])}


def test_viewer_scope_blocks_cross_host_reads_and_admin_endpoints(tmp_path) -> None:
    root_client, _, _, _ = build_scoped_application(tmp_path)
    viewer = TestClient(root_client.app)
    me = login_as(viewer, "viewer-a")

    assert me["hostnames"] == ["host-a"]
    for endpoint, expected_count in (
        ("/events", 3),
        ("/detections", 1),
        ("/responses", 1),
    ):
        response = viewer.get(endpoint)
        assert response.status_code == 200
        assert len(response.json()) == expected_count
        assert {event["hostname"] for event in response.json()} == {"host-a"}
        assert viewer.get(endpoint, params={"hostname": "host-a"}).status_code == 200
        other_hostname = viewer.get(endpoint, params={"hostname": "host-b"})
        assert other_hostname.status_code == 200
        assert other_hostname.json() == []

    status = viewer.get("/status")
    assert status.status_code == 200
    assert status.json()["total_events"] == 3
    assert status.json()["live_response_blocks"] is None
    assert status.json()["hostname"] == "host-a"

    agents = viewer.get("/agents")
    assert agents.status_code == 200
    assert [agent["hostname"] for agent in agents.json()] == ["host-a"]
    assert viewer.get("/admin/users").status_code == 403

def test_superadmin_sees_all_agents_and_new_viewer_starts_empty(
    tmp_path,
) -> None:
    admin, _, _, _ = build_scoped_application(tmp_path)
    admin_login = login_as(admin, "admin")
    headers = csrf_headers(admin_login)

    assert len(admin.get("/events").json()) == 6

    agents = admin.get("/agents")
    assert agents.status_code == 200
    assert {agent["hostname"] for agent in agents.json()} == {"host-a", "host-b"}

    created = admin.post(
        "/admin/users",
        headers=headers,
        json={
            "username": "new-viewer",
            "password": TEST_PASSWORD,
            "role": "viewer",
        },
    )
    assert created.status_code == 201
    assert created.json()["server_count"] == 0

    viewer = TestClient(admin.app)
    me = login_as(viewer, "new-viewer")
    assert me["hostnames"] == []
    assert viewer.get("/agents").json() == []
    assert viewer.get("/events").json() == []

def test_agent_enrollment_adds_hostname_to_its_owner_scope(tmp_path) -> None:
    root_client, _, _, _ = build_scoped_application(tmp_path)
    viewer = TestClient(root_client.app)
    signed_in = login_as(viewer, "viewer-a")

    registration = viewer.post(
        "/agents/registration-token",
        headers=csrf_headers(signed_in),
        json={},
    )
    assert registration.status_code == 200

    enrolled = root_client.post(
        "/agent/enroll",
        json={
            "registration_token": registration.json()["token"],
            "hostname": "host-a-extra",
        },
    )
    assert enrolled.status_code == 200

    assert [agent["hostname"] for agent in viewer.get("/agents").json()] == [
        "host-a",
        "host-a-extra",
    ]
    assert viewer.get("/auth/me").json()["hostnames"] == [
        "host-a",
        "host-a-extra",
    ]


def test_superadmin_demotion_invalidates_session(tmp_path) -> None:
    admin, _, _, _ = build_scoped_application(tmp_path)
    signed_in = login_as(admin, "admin")
    headers = csrf_headers(signed_in)
    created = admin.post(
        "/admin/users",
        headers=headers,
        json={
            "username": "secondary-admin",
            "password": TEST_PASSWORD,
            "role": "superadmin",
        },
    )
    user_id = created.json()["id"]
    secondary = TestClient(admin.app)
    login_as(secondary, "secondary-admin")

    changed = admin.post(
        f"/admin/users/{user_id}/role",
        headers=headers,
        json={"role": "viewer"},
    )

    assert changed.status_code == 200
    assert changed.json()["server_count"] == 0
    assert secondary.get("/status").status_code == 401


def test_viewer_without_agents_receives_no_audit_information(tmp_path) -> None:
    admin, _, _, _ = build_scoped_application(tmp_path)
    admin_login = login_as(admin, "admin")
    created = admin.post(
        "/admin/users",
        headers=csrf_headers(admin_login),
        json={
            "username": "viewer-without-agents",
            "password": TEST_PASSWORD,
            "role": "viewer",
        },
    )
    assert created.status_code == 201

    viewer = TestClient(admin.app)
    login_as(viewer, "viewer-without-agents")
    assert viewer.get("/events").json() == []
    assert viewer.get("/detections").json() == []
    assert viewer.get("/responses").json() == []
    assert viewer.get("/status").json()["total_events"] == 0
    filtered = viewer.get("/events", params={"hostname": "host-a"})
    assert filtered.status_code == 200
    assert filtered.json() == []


def test_auth_and_agent_operations_leave_audit_database_unchanged(tmp_path) -> None:
    admin, _, audit_database, _ = build_scoped_application(tmp_path)
    before = audit_database.read_bytes()
    signed_in = login_as(admin, "admin")

    registration = admin.post(
        "/agents/registration-token",
        headers=csrf_headers(signed_in),
        json={},
    )
    assert registration.status_code == 200
    enrolled = admin.post(
        "/agent/enroll",
        json={
            "registration_token": registration.json()["token"],
            "hostname": "admin-host",
        },
    )

    assert enrolled.status_code == 200
    assert audit_database.read_bytes() == before
