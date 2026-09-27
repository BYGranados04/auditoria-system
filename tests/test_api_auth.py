from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from app.api.main import create_app
from app.auth.config import AuthSettings
from app.auth.repository import AuthRepository
from app.core.config import AgentSettings
from app.storage.event_repository import EventRepository
from tests.api_test_helpers import TEST_PASSWORD, TEST_SCRYPT


def build_application(
    tmp_path: Path,
    *,
    role: str = "superadmin",
    cookie_secure: bool = False,
    clock=None,
) -> tuple[TestClient, AuthRepository, Path]:
    settings = AgentSettings(
        interval=1,
        state_dir=tmp_path / "state",
        log_dir=tmp_path / "logs",
    )
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    event_repository = EventRepository(settings.database_file)
    event_repository.initialize()
    auth_database = tmp_path / "auth" / "auth.db"
    auth_repository = AuthRepository(auth_database, scrypt_parameters=TEST_SCRYPT)
    auth_repository.create_user(
        username="primary-user",
        password=TEST_PASSWORD,
        role=role,
    )
    application = create_app(
        settings=settings,
        repository=event_repository,
        auth_settings=AuthSettings(
            database_file=auth_database,
            session_seconds=28_800,
            cookie_secure=cookie_secure,
        ),
        auth_repository=auth_repository,
        clock=clock,
    )
    return TestClient(application), auth_repository, settings.database_file


def login(client: TestClient, password: str = TEST_PASSWORD):
    return client.post(
        "/auth/login",
        json={"username": "primary-user", "password": password},
    )


def csrf_headers(login_response) -> dict[str, str]:
    return {"X-CSRF-Token": login_response.json()["csrf_token"]}


def test_public_health_and_protected_routes(tmp_path: Path) -> None:
    client, _, _ = build_application(tmp_path)

    assert client.get("/health").status_code == 200
    dashboard = client.get("/dashboard", follow_redirects=False)
    assert dashboard.status_code == 303
    assert dashboard.headers["location"] == "/login"
    for path in ("/status", "/events", "/detections", "/responses"):
        assert client.get(path).status_code == 401


def test_login_success_failure_and_cookie_flags(tmp_path: Path) -> None:
    client, _, _ = build_application(tmp_path)

    assert login(client, "incorrect password").status_code == 401
    response = login(client)

    assert response.status_code == 200
    cookies = response.headers.get_list("set-cookie")
    session_cookie = next(
        value for value in cookies if value.startswith("auditoria_session=")
    )
    assert "HttpOnly" in session_cookie
    assert "SameSite=strict" in session_cookie
    assert "Path=/" in session_cookie
    assert "Max-Age=28800" in session_cookie
    assert "Secure" not in session_cookie


def test_secure_cookie_can_be_enabled(tmp_path: Path) -> None:
    client, _, _ = build_application(tmp_path, cookie_secure=True)
    response = login(client)
    session_cookie = next(
        value
        for value in response.headers.get_list("set-cookie")
        if value.startswith("auditoria_session=")
    )
    assert "Secure" in session_cookie


def test_authenticated_viewer_can_read_but_cannot_administer(tmp_path: Path) -> None:
    client, _, _ = build_application(tmp_path, role="viewer")
    response = login(client)
    assert response.status_code == 200

    for path in ("/dashboard", "/status", "/events", "/detections", "/responses"):
        assert client.get(path).status_code == 200
    assert client.get("/admin/users").status_code == 403
    assert client.get("/dashboard/users").status_code == 403


def test_superadmin_can_list_and_create_both_roles_without_secrets(
    tmp_path: Path,
) -> None:
    client, _, _ = build_application(tmp_path)
    signed_in = login(client)
    headers = csrf_headers(signed_in)
    assert client.get("/dashboard/users").status_code == 200

    for username, role in (("new-viewer", "viewer"), ("new-admin", "superadmin")):
        response = client.post(
            "/admin/users",
            headers=headers,
            json={"username": username, "password": TEST_PASSWORD, "role": role},
        )
        assert response.status_code == 201
        assert response.json()["role"] == role

    response = client.get("/admin/users")
    assert response.status_code == 200
    assert len(response.json()) == 3
    for user in response.json():
        assert "password_hash" not in user
        assert "password_salt" not in user
        assert "token" not in user


def test_user_creation_rejects_seven_and_accepts_eight_character_passwords(
    tmp_path: Path,
) -> None:
    client, _, _ = build_application(tmp_path)
    signed_in = login(client)
    headers = csrf_headers(signed_in)

    rejected = client.post(
        "/admin/users",
        headers=headers,
        json={
            "username": "seven-chars",
            "password": "1234567",
            "role": "viewer",
        },
    )
    accepted = client.post(
        "/admin/users",
        headers=headers,
        json={
            "username": "eight-chars",
            "password": "12345678",
            "role": "viewer",
        },
    )

    assert rejected.status_code == 422
    assert accepted.status_code == 201


def test_csrf_and_origin_are_required_for_admin_mutations(tmp_path: Path) -> None:
    client, _, _ = build_application(tmp_path)
    signed_in = login(client)
    payload = {"username": "new-viewer", "password": TEST_PASSWORD, "role": "viewer"}

    assert client.post("/admin/users", json=payload).status_code == 403
    assert (
        client.post(
            "/admin/users",
            headers={**csrf_headers(signed_in), "Origin": "https://evil.example"},
            json=payload,
        ).status_code
        == 403
    )


def test_disabled_user_loses_existing_session(tmp_path: Path) -> None:
    admin_client, repository, _ = build_application(tmp_path)
    admin_login = login(admin_client)
    viewer = repository.create_user(
        username="secondary-viewer",
        password=TEST_PASSWORD,
        role="viewer",
    )
    viewer_client = TestClient(admin_client.app)
    viewer_login = viewer_client.post(
        "/auth/login",
        json={"username": "secondary-viewer", "password": TEST_PASSWORD},
    )
    assert viewer_login.status_code == 200
    assert viewer_client.get("/status").status_code == 200

    response = admin_client.post(
        f"/admin/users/{viewer['id']}/status",
        headers=csrf_headers(admin_login),
        json={"active": False},
    )
    assert response.status_code == 200
    assert response.json()["active"] is False
    assert viewer_client.get("/status").status_code == 401


def test_last_superadmin_and_self_deactivation_are_protected(tmp_path: Path) -> None:
    client, _, _ = build_application(tmp_path)
    signed_in = login(client)
    user_id = signed_in.json()["id"]
    headers = csrf_headers(signed_in)

    disable = client.post(
        f"/admin/users/{user_id}/status",
        headers=headers,
        json={"active": False},
    )
    downgrade = client.post(
        f"/admin/users/{user_id}/role",
        headers=headers,
        json={"role": "viewer"},
    )
    assert disable.status_code == 409
    assert downgrade.status_code == 409


def test_logout_invalidates_session_and_clears_cookie(tmp_path: Path) -> None:
    client, _, _ = build_application(tmp_path)
    signed_in = login(client)

    response = client.post("/auth/logout", headers=csrf_headers(signed_in))

    assert response.status_code == 204
    assert client.get("/status").status_code == 401
    assert "auditoria_session=" in response.headers["set-cookie"]


def test_session_expiration_is_enforced(tmp_path: Path) -> None:
    current = [datetime(2026, 1, 1, tzinfo=UTC)]
    client, _, _ = build_application(tmp_path, clock=lambda: current[0])
    assert login(client).status_code == 200
    assert client.get("/status").status_code == 200

    current[0] += timedelta(hours=8, seconds=1)

    assert client.get("/status").status_code == 401


def test_auth_operations_do_not_modify_audit_database(tmp_path: Path) -> None:
    client, _, audit_database = build_application(tmp_path)
    before = audit_database.read_bytes()
    signed_in = login(client)

    client.post(
        "/admin/users",
        headers=csrf_headers(signed_in),
        json={"username": "new-viewer", "password": TEST_PASSWORD, "role": "viewer"},
    )
    client.post("/auth/logout", headers=csrf_headers(signed_in))

    assert audit_database.read_bytes() == before
