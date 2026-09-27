import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from app.api.main import create_app
from app.auth.config import AuthSettings
from app.auth.repository import AuthRepository
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
            hostnames=hostnames,
        )
        users[username] = int(user["id"])

    application = create_app(
        settings=settings,
        repository=EventRepository(settings.database_file, read_only=True),
        auth_settings=AuthSettings(database_file=auth_database),
        auth_repository=auth_repository,
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
        assert viewer.get(endpoint, params={"hostname": "host-b"}).status_code == 403

    status = viewer.get("/status")
    assert status.status_code == 200
    assert status.json()["total_events"] == 3
    assert status.json()["live_response_blocks"] == 1
    assert status.json()["hostname"] == "host-a"

    assert viewer.get("/admin/hosts").status_code == 403
    assert viewer.get("/admin/users").status_code == 403
    assert viewer.post(
        "/admin/users/1/hosts",
        headers=csrf_headers(me),
        json={"hostnames": ["host-a"]},
    ).status_code == 403


def test_superadmin_manages_scopes_and_changes_take_effect_immediately(
    tmp_path,
) -> None:
    admin, _, _, users = build_scoped_application(tmp_path)
    admin_login = login_as(admin, "admin")
    headers = csrf_headers(admin_login)
    viewer = TestClient(admin.app)
    login_as(viewer, "viewer-a")

    assert len(admin.get("/events").json()) == 6
    assert admin.get("/admin/hosts").json() == [
        {"hostname": "host-a"},
        {"hostname": "host-b"},
    ]

    created = admin.post(
        "/admin/users",
        headers=headers,
        json={
            "username": "new-viewer",
            "password": TEST_PASSWORD,
            "role": "viewer",
            "hostnames": ["host-a", "host-b"],
        },
    )
    assert created.status_code == 201
    assert created.json()["hostnames"] == ["host-a", "host-b"]

    changed = admin.post(
        f"/admin/users/{users['viewer-a']}/hosts",
        headers=headers,
        json={"hostnames": ["host-b"]},
    )
    assert changed.status_code == 200
    assert changed.json()["hostnames"] == ["host-b"]
    assert viewer.get("/events").status_code == 401

    me = login_as(viewer, "viewer-a")
    assert me["hostnames"] == ["host-b"]
    assert {event["hostname"] for event in viewer.get("/events").json()} == {
        "host-b"
    }


def test_viewer_creation_and_assignment_require_known_nonempty_hosts(tmp_path) -> None:
    admin, _, _, users = build_scoped_application(tmp_path)
    signed_in = login_as(admin, "admin")
    headers = csrf_headers(signed_in)
    base_payload = {
        "password": TEST_PASSWORD,
        "role": "viewer",
    }

    empty = admin.post(
        "/admin/users",
        headers=headers,
        json={**base_payload, "username": "empty-viewer", "hostnames": []},
    )
    unknown = admin.post(
        "/admin/users",
        headers=headers,
        json={
            **base_payload,
            "username": "unknown-viewer",
            "hostnames": ["host-z"],
        },
    )
    invalid_update = admin.post(
        f"/admin/users/{users['viewer-a']}/hosts",
        headers=headers,
        json={"hostnames": ["host-z"]},
    )

    assert empty.status_code == 422
    assert unknown.status_code == 422
    assert invalid_update.status_code == 422


def test_superadmin_demotion_requires_scope_and_invalidates_session(tmp_path) -> None:
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
            "hostnames": [],
        },
    )
    user_id = created.json()["id"]
    secondary = TestClient(admin.app)
    login_as(secondary, "secondary-admin")

    rejected = admin.post(
        f"/admin/users/{user_id}/role",
        headers=headers,
        json={"role": "viewer"},
    )
    changed = admin.post(
        f"/admin/users/{user_id}/role",
        headers=headers,
        json={"role": "viewer", "hostnames": ["host-a"]},
    )

    assert rejected.status_code == 409
    assert changed.status_code == 200
    assert changed.json()["hostnames"] == ["host-a"]
    assert secondary.get("/status").status_code == 401


def test_empty_scope_returns_no_information_and_role_change_ends_session(
    tmp_path,
) -> None:
    admin, repository, _, users = build_scoped_application(tmp_path)
    with sqlite3.connect(repository.database_path) as connection:
        connection.execute(
            "DELETE FROM user_host_access WHERE user_id = ?",
            (users["viewer-b"],),
        )

    viewer = TestClient(admin.app)
    login_as(viewer, "viewer-b")
    assert viewer.get("/events").json() == []
    assert viewer.get("/detections").json() == []
    assert viewer.get("/responses").json() == []
    assert viewer.get("/status").json()["total_events"] == 0
    assert viewer.get("/events", params={"hostname": "host-b"}).status_code == 403

    admin_login = login_as(admin, "admin")
    promoted = admin.post(
        f"/admin/users/{users['viewer-b']}/role",
        headers=csrf_headers(admin_login),
        json={"role": "superadmin"},
    )
    assert promoted.status_code == 200
    assert promoted.json()["hostnames"] is None
    assert viewer.get("/status").status_code == 401


def test_scope_operations_leave_audit_database_unchanged(tmp_path) -> None:
    admin, _, audit_database, users = build_scoped_application(tmp_path)
    before = audit_database.read_bytes()
    signed_in = login_as(admin, "admin")

    assert admin.get("/events", params={"hostname": "host-a"}).status_code == 200
    assert admin.get("/admin/hosts").status_code == 200
    response = admin.post(
        f"/admin/users/{users['viewer-a']}/hosts",
        headers=csrf_headers(signed_in),
        json={"hostnames": ["host-a", "host-b"]},
    )

    assert response.status_code == 200
    assert audit_database.read_bytes() == before
