import sqlite3
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
    clock=None,
) -> tuple[TestClient, AuthRepository, dict[str, int]]:
    settings = AgentSettings(
        interval=1,
        state_dir=tmp_path / "state",
        log_dir=tmp_path / "logs",
    )
    settings.state_dir.mkdir(parents=True)
    event_repository = EventRepository(settings.database_file)
    event_repository.initialize()

    auth_repository = AuthRepository(
        tmp_path / "auth" / "auth.db",
        scrypt_parameters=TEST_SCRYPT,
    )
    users = {}
    for username, role in (
        ("admin", "superadmin"),
        ("viewer-a", "viewer"),
        ("viewer-b", "viewer"),
        ("viewer-empty", "viewer"),
    ):
        user = auth_repository.create_user(
            username=username,
            password=TEST_PASSWORD,
            role=role,
        )
        users[username] = int(user["id"])

    application = create_app(
        settings=settings,
        repository=event_repository,
        auth_settings=AuthSettings(database_file=auth_repository.database_path),
        auth_repository=auth_repository,
        clock=clock,
    )
    return TestClient(application), auth_repository, users


def login_as(client: TestClient, username: str) -> dict[str, object]:
    response = client.post(
        "/auth/login",
        json={"username": username, "password": TEST_PASSWORD},
    )
    assert response.status_code == 200
    return response.json()


def csrf_headers(login_response: dict[str, object]) -> dict[str, str]:
    return {"X-CSRF-Token": str(login_response["csrf_token"])}


def create_registration_token(
    client: TestClient,
    login_response: dict[str, object],
) -> str:
    response = client.post(
        "/agents/registration-token",
        headers=csrf_headers(login_response),
        json={},
    )
    assert response.status_code == 200
    return str(response.json()["token"])


def enroll_agent(client: TestClient, token: str, hostname: str) -> dict[str, object]:
    response = client.post(
        "/agent/enroll",
        json={"registration_token": token, "hostname": hostname},
    )
    assert response.status_code == 200
    return response.json()


def test_authenticated_user_generates_registration_token(tmp_path: Path) -> None:
    client, _, _ = build_application(tmp_path)
    login = login_as(client, "viewer-a")

    token = create_registration_token(client, login)

    assert token.startswith("reg_")


def test_registration_token_is_stored_only_as_digest(tmp_path: Path) -> None:
    client, repository, _ = build_application(tmp_path)
    token = create_registration_token(client, login_as(client, "viewer-a"))

    with sqlite3.connect(repository.database_path) as connection:
        digest = connection.execute(
            "SELECT token_digest FROM agent_registration_tokens"
        ).fetchone()[0]

    assert isinstance(digest, bytes)
    assert token.encode() not in digest


def test_registration_token_expires(tmp_path: Path) -> None:
    current = [datetime(2026, 1, 1, tzinfo=UTC)]
    client, _, _ = build_application(tmp_path, clock=lambda: current[0])
    token = create_registration_token(client, login_as(client, "viewer-a"))
    current[0] += timedelta(minutes=15, seconds=1)

    response = client.post(
        "/agent/enroll",
        json={"registration_token": token, "hostname": "expired-host"},
    )

    assert response.status_code == 401


def test_registration_token_can_only_be_used_once(tmp_path: Path) -> None:
    client, _, _ = build_application(tmp_path)
    token = create_registration_token(client, login_as(client, "viewer-a"))
    enroll_agent(client, token, "viewer-a-host")

    repeated = client.post(
        "/agent/enroll",
        json={"registration_token": token, "hostname": "second-host"},
    )

    assert repeated.status_code == 401


def test_enrollment_links_agent_to_token_owner(tmp_path: Path) -> None:
    client, repository, users = build_application(tmp_path)
    token = create_registration_token(client, login_as(client, "viewer-a"))
    enrolled = enroll_agent(client, token, "viewer-a-host")

    with sqlite3.connect(repository.database_path) as connection:
        owner_user_id = connection.execute(
            "SELECT owner_user_id FROM agents WHERE agent_id = ?",
            (enrolled["agent_id"],),
        ).fetchone()[0]

    assert owner_user_id == users["viewer-a"]


def test_agent_id_is_stable_after_enrollment(tmp_path: Path) -> None:
    client, _, _ = build_application(tmp_path)
    login = login_as(client, "viewer-a")
    enrolled = enroll_agent(
        client,
        create_registration_token(client, login),
        "viewer-a-host",
    )

    listed = client.get("/agents")
    fetched = client.get(f"/agents/{enrolled['agent_id']}")

    assert listed.status_code == 200
    assert listed.json()[0]["agent_id"] == enrolled["agent_id"]
    assert fetched.status_code == 200
    assert fetched.json()["agent_id"] == enrolled["agent_id"]


def test_enrollment_credential_is_stored_only_as_digest(tmp_path: Path) -> None:
    client, repository, _ = build_application(tmp_path)
    credential = enroll_agent(
        client,
        create_registration_token(client, login_as(client, "viewer-a")),
        "viewer-a-host",
    )["credential"]

    with sqlite3.connect(repository.database_path) as connection:
        digest = connection.execute(
            "SELECT credential_digest FROM agent_credentials"
        ).fetchone()[0]

    assert isinstance(digest, bytes)
    assert str(credential).encode() not in digest


def test_valid_heartbeat_marks_agent_online_and_updates_last_seen_at(
    tmp_path: Path,
) -> None:
    current = [datetime(2026, 1, 1, tzinfo=UTC)]
    client, _, _ = build_application(tmp_path, clock=lambda: current[0])
    enrolled = enroll_agent(
        client,
        create_registration_token(client, login_as(client, "viewer-a")),
        "viewer-a-host",
    )
    current[0] += timedelta(seconds=1)

    response = client.post(
        "/agent/heartbeat",
        headers={"Authorization": f"Bearer {enrolled['credential']}"},
        json={"agent_id": enrolled["agent_id"]},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "online"
    assert response.json()["last_seen_at"] == current[0].isoformat().replace(
        "+00:00", "Z"
    )


def test_invalid_credential_does_not_update_last_seen_at(tmp_path: Path) -> None:
    client, repository, _ = build_application(tmp_path)
    enrolled = enroll_agent(
        client,
        create_registration_token(client, login_as(client, "viewer-a")),
        "viewer-a-host",
    )

    response = client.post(
        "/agent/heartbeat",
        headers={"Authorization": "Bearer agc_invalid"},
        json={"agent_id": enrolled["agent_id"]},
    )
    with sqlite3.connect(repository.database_path) as connection:
        last_seen_at = connection.execute(
            "SELECT last_seen_at FROM agents WHERE agent_id = ?",
            (enrolled["agent_id"],),
        ).fetchone()[0]

    assert response.status_code == 401
    assert last_seen_at is None


def test_viewer_only_sees_own_agents(tmp_path: Path) -> None:
    root_client, _, _ = build_application(tmp_path)
    viewer_a = TestClient(root_client.app)
    viewer_b = TestClient(root_client.app)
    login_a = login_as(viewer_a, "viewer-a")
    login_b = login_as(viewer_b, "viewer-b")
    enroll_agent(
        root_client,
        create_registration_token(viewer_a, login_a),
        "viewer-a-host",
    )
    enroll_agent(
        root_client,
        create_registration_token(viewer_b, login_b),
        "viewer-b-host",
    )

    response = viewer_a.get("/agents")

    assert response.status_code == 200
    assert [agent["hostname"] for agent in response.json()] == ["viewer-a-host"]


def test_viewer_cannot_access_another_users_agent(tmp_path: Path) -> None:
    root_client, _, _ = build_application(tmp_path)
    viewer_a = TestClient(root_client.app)
    viewer_b = TestClient(root_client.app)
    enrolled = enroll_agent(
        root_client,
        create_registration_token(viewer_a, login_as(viewer_a, "viewer-a")),
        "viewer-a-host",
    )
    login_as(viewer_b, "viewer-b")

    assert viewer_b.get(f"/agents/{enrolled['agent_id']}").status_code == 404


def test_superadmin_sees_all_agents(tmp_path: Path) -> None:
    root_client, _, _ = build_application(tmp_path)
    viewer_a = TestClient(root_client.app)
    viewer_b = TestClient(root_client.app)
    enroll_agent(
        root_client,
        create_registration_token(viewer_a, login_as(viewer_a, "viewer-a")),
        "viewer-a-host",
    )
    enroll_agent(
        root_client,
        create_registration_token(viewer_b, login_as(viewer_b, "viewer-b")),
        "viewer-b-host",
    )
    login_as(root_client, "admin")

    response = root_client.get("/agents")

    assert response.status_code == 200
    assert {agent["hostname"] for agent in response.json()} == {
        "viewer-a-host",
        "viewer-b-host",
    }


def test_viewer_without_agents_receives_empty_list(tmp_path: Path) -> None:
    client, _, _ = build_application(tmp_path)
    login_as(client, "viewer-empty")

    assert client.get("/agents").json() == []


def test_enrollment_cannot_choose_or_modify_owner_user_id(tmp_path: Path) -> None:
    client, repository, users = build_application(tmp_path)
    token = create_registration_token(client, login_as(client, "viewer-a"))

    rejected = client.post(
        "/agent/enroll",
        json={
            "registration_token": token,
            "hostname": "viewer-a-host",
            "owner_user_id": users["viewer-b"],
        },
    )
    enrolled = enroll_agent(client, token, "viewer-a-host")
    with sqlite3.connect(repository.database_path) as connection:
        owner_user_id = connection.execute(
            "SELECT owner_user_id FROM agents WHERE agent_id = ?",
            (enrolled["agent_id"],),
        ).fetchone()[0]

    assert rejected.status_code == 422
    assert owner_user_id == users["viewer-a"]
