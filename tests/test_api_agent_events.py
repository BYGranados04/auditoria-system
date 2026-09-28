import sqlite3
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
from app.storage.event_repository import EventRepository
from tests.api_test_helpers import TEST_PASSWORD, TEST_SCRYPT

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)


def build_application(
    tmp_path: Path,
    *,
    batch_max: int = 100,
    future_seconds: int = 300,
    evidence_max_bytes: int = 65_536,
) -> tuple[
    TestClient,
    AuthRepository,
    CentralEventRepository,
    dict[str, int],
]:
    agent_settings = AgentSettings(
        interval=1,
        state_dir=tmp_path / "state",
        log_dir=tmp_path / "logs",
        identity_file=tmp_path / "agent-identity.json",
    )
    agent_settings.state_dir.mkdir(parents=True)
    local_repository = EventRepository(agent_settings.database_file)
    local_repository.initialize()

    auth_repository = AuthRepository(
        tmp_path / "auth" / "auth.db",
        scrypt_parameters=TEST_SCRYPT,
    )
    users: dict[str, int] = {}
    for username, role in (
        ("admin", "superadmin"),
        ("owner-a", "viewer"),
        ("owner-b", "viewer"),
    ):
        user = auth_repository.create_user(
            username=username,
            password=TEST_PASSWORD,
            role=role,
        )
        users[username] = int(user["id"])

    central_settings = CentralSettings(
        database_file=tmp_path / "central" / "central.db",
        agent_event_batch_max=batch_max,
        event_max_future_seconds=future_seconds,
        event_evidence_max_bytes=evidence_max_bytes,
    )
    central_repository = CentralEventRepository(
        central_settings.database_file,
        clock=lambda: NOW,
    )
    application = create_app(
        settings=agent_settings,
        repository=local_repository,
        auth_settings=AuthSettings(
            database_file=auth_repository.database_path,
            central_url="https://central.example",
        ),
        auth_repository=auth_repository,
        central_settings=central_settings,
        central_repository=central_repository,
        clock=lambda: NOW,
    )
    return TestClient(application), auth_repository, central_repository, users


def enroll(
    repository: AuthRepository,
    owner_user_id: int,
    hostname: str,
) -> dict[str, object]:
    registration = repository.create_agent_registration_token(
        owner_user_id,
        now=NOW,
    )
    enrolled = repository.enroll_agent(
        registration_token=registration.token,
        hostname=hostname,
        now=NOW,
    )
    return {
        "agent_id": str(enrolled.agent["agent_id"]),
        "credential": enrolled.credential,
    }


def event_payload(**updates: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "event_id": str(uuid4()),
        "timestamp": NOW.isoformat(),
        "hostname": "metadata-host",
        "source": "detection-engine",
        "category": "detection",
        "event_type": "SSH_BRUTE_FORCE_ATTEMPT",
        "severity": "high",
        "description": "Detección recibida del agente",
        "evidence": {"attempts": 12, "source_ip": "192.0.2.10"},
    }
    payload.update(updates)
    return payload


def authorization(credential: object) -> dict[str, str]:
    return {"Authorization": f"Bearer {credential}"}


def post_batch(
    client: TestClient,
    credential: object,
    events: list[dict[str, object]],
):
    return client.post(
        "/agent/events/batch",
        headers=authorization(credential),
        json={"events": events},
    )


def test_valid_credential_ingests_under_authenticated_agent(tmp_path: Path) -> None:
    client, auth, central, users = build_application(tmp_path)
    identity = enroll(auth, users["owner-a"], "owner-a-host")
    payload = event_payload(hostname="untrusted-metadata-host")

    response = post_batch(client, identity["credential"], [payload])
    stored = central.list_events(agent_id=str(identity["agent_id"]))

    assert response.status_code == 200
    assert response.json() == {"accepted": 1, "inserted": 1, "duplicates": 0}
    assert str(identity["credential"]) not in response.text
    assert len(stored) == 1
    assert stored[0]["agent_id"] == identity["agent_id"]
    assert stored[0]["hostname"] == "untrusted-metadata-host"
    assert stored[0]["received_at"] == "2026-09-27T12:00:00.000000Z"


@pytest.mark.parametrize("identity_field", ["agent_id", "owner_user_id"])
def test_http_payload_cannot_control_identity(
    tmp_path: Path,
    identity_field: str,
) -> None:
    client, auth, central, users = build_application(tmp_path)
    identity = enroll(auth, users["owner-a"], "owner-a-host")
    payload = event_payload(**{identity_field: "spoofed-identity"})

    response = post_batch(client, identity["credential"], [payload])

    assert response.status_code == 422
    assert not central.database_path.exists()


@pytest.mark.parametrize(
    ("headers", "credential_fragment"),
    [
        ({}, None),
        ({"Authorization": "Basic abc"}, None),
        ({"Authorization": "Bearer "}, None),
        ({"Authorization": "Bearer agc_invalid_secret"}, "agc_invalid_secret"),
    ],
)
def test_missing_malformed_and_invalid_credentials_return_401_without_leaking(
    tmp_path: Path,
    headers: dict[str, str],
    credential_fragment: str | None,
) -> None:
    client, _, central, _ = build_application(tmp_path)

    response = client.post(
        "/agent/events/batch",
        headers=headers,
        json={"events": [event_payload()]},
    )

    assert response.status_code == 401
    if credential_fragment is not None:
        assert credential_fragment not in response.text
    assert not central.database_path.exists()


def test_revoked_credential_is_denied(tmp_path: Path) -> None:
    client, auth, central, users = build_application(tmp_path)
    identity = enroll(auth, users["owner-a"], "owner-a-host")
    with sqlite3.connect(auth.database_path) as connection:
        connection.execute(
            """
            UPDATE agent_credentials
            SET revoked_at = ?
            WHERE agent_id = ?
            """,
            (NOW.isoformat(), identity["agent_id"]),
        )

    response = post_batch(client, identity["credential"], [event_payload()])

    assert response.status_code == 401
    assert str(identity["credential"]) not in response.text
    assert not central.database_path.exists()


def test_inactive_owner_credential_is_denied(tmp_path: Path) -> None:
    client, auth, central, users = build_application(tmp_path)
    identity = enroll(auth, users["owner-a"], "owner-a-host")
    auth.set_user_active(
        users["owner-a"],
        active=False,
        actor_user_id=users["admin"],
        now=NOW,
    )

    response = post_batch(client, identity["credential"], [event_payload()])

    assert response.status_code == 401
    assert not central.database_path.exists()


def test_empty_batch_is_rejected(tmp_path: Path) -> None:
    client, auth, central, users = build_application(tmp_path)
    identity = enroll(auth, users["owner-a"], "owner-a-host")

    response = post_batch(client, identity["credential"], [])

    assert response.status_code == 422
    assert not central.database_path.exists()


def test_batch_at_configured_limit_is_accepted(tmp_path: Path) -> None:
    client, auth, central, users = build_application(tmp_path)
    identity = enroll(auth, users["owner-a"], "owner-a-host")
    events = [event_payload() for _ in range(100)]

    response = post_batch(client, identity["credential"], events)

    assert response.status_code == 200
    assert response.json() == {"accepted": 100, "inserted": 100, "duplicates": 0}
    assert len(central.list_events(agent_id=str(identity["agent_id"]))) == 100


def test_batch_above_configured_limit_is_rejected_without_inserts(
    tmp_path: Path,
) -> None:
    client, auth, central, users = build_application(tmp_path)
    identity = enroll(auth, users["owner-a"], "owner-a-host")

    response = post_batch(
        client,
        identity["credential"],
        [event_payload() for _ in range(101)],
    )

    assert response.status_code == 422
    assert not central.database_path.exists()


def test_identical_duplicate_is_accepted_without_duplication(tmp_path: Path) -> None:
    client, auth, central, users = build_application(tmp_path)
    identity = enroll(auth, users["owner-a"], "owner-a-host")
    payload = event_payload()

    first = post_batch(client, identity["credential"], [payload])
    duplicate = post_batch(client, identity["credential"], [payload])

    assert first.json() == {"accepted": 1, "inserted": 1, "duplicates": 0}
    assert duplicate.status_code == 200
    assert duplicate.json() == {"accepted": 1, "inserted": 0, "duplicates": 1}
    assert len(central.list_events(agent_id=str(identity["agent_id"]))) == 1


def test_same_event_id_is_allowed_for_two_authenticated_agents(tmp_path: Path) -> None:
    client, auth, central, users = build_application(tmp_path)
    first = enroll(auth, users["owner-a"], "owner-a-host")
    second = enroll(auth, users["owner-b"], "owner-b-host")
    payload = event_payload(hostname="shared-payload-hostname")

    first_response = post_batch(client, first["credential"], [payload])
    second_response = post_batch(client, second["credential"], [payload])

    assert first_response.status_code == second_response.status_code == 200
    assert len(central.list_events(agent_id=str(first["agent_id"]))) == 1
    assert len(central.list_events(agent_id=str(second["agent_id"]))) == 1


def test_conflicting_payload_returns_409_and_preserves_original(tmp_path: Path) -> None:
    client, auth, central, users = build_application(tmp_path)
    identity = enroll(auth, users["owner-a"], "owner-a-host")
    event_id = str(uuid4())
    original = event_payload(event_id=event_id, description="Original")
    changed = event_payload(event_id=event_id, description="Alterado")
    post_batch(client, identity["credential"], [original])

    response = post_batch(client, identity["credential"], [changed])
    stored = central.list_events(agent_id=str(identity["agent_id"]))

    assert response.status_code == 409
    assert len(stored) == 1
    assert stored[0]["description"] == "Original"


def test_conflict_in_middle_rolls_back_entire_batch(tmp_path: Path) -> None:
    client, auth, central, users = build_application(tmp_path)
    identity = enroll(auth, users["owner-a"], "owner-a-host")
    conflicting_id = str(uuid4())
    original = event_payload(event_id=conflicting_id, description="Original")
    post_batch(client, identity["credential"], [original])
    batch = [
        event_payload(description="Nuevo antes del conflicto"),
        event_payload(event_id=conflicting_id, description="Conflictivo"),
        event_payload(description="Nuevo después del conflicto"),
    ]

    response = post_batch(client, identity["credential"], batch)
    stored = central.list_events(agent_id=str(identity["agent_id"]))

    assert response.status_code == 409
    assert len(stored) == 1
    assert stored[0]["description"] == "Original"


def test_structurally_invalid_batch_leaves_zero_rows(tmp_path: Path) -> None:
    client, auth, central, users = build_application(tmp_path)
    identity = enroll(auth, users["owner-a"], "owner-a-host")
    invalid = event_payload(severity="extreme")

    response = post_batch(
        client,
        identity["credential"],
        [event_payload(), invalid],
    )

    assert response.status_code == 422
    assert not central.database_path.exists()


def test_malformed_json_is_rejected_without_creating_central_database(
    tmp_path: Path,
) -> None:
    client, auth, central, users = build_application(tmp_path)
    identity = enroll(auth, users["owner-a"], "owner-a-host")

    response = client.post(
        "/agent/events/batch",
        headers={
            **authorization(identity["credential"]),
            "Content-Type": "application/json",
        },
        content=b'{"events": [',
    )

    assert response.status_code == 422
    assert not central.database_path.exists()


@pytest.mark.parametrize(
    ("timestamp", "expected_status"),
    [
        (NOW - timedelta(days=365), 200),
        (NOW + timedelta(seconds=300), 200),
        (NOW + timedelta(seconds=301), 422),
    ],
)
def test_timestamp_window(
    tmp_path: Path,
    timestamp: datetime,
    expected_status: int,
) -> None:
    client, auth, central, users = build_application(tmp_path)
    identity = enroll(auth, users["owner-a"], "owner-a-host")

    response = post_batch(
        client,
        identity["credential"],
        [event_payload(timestamp=timestamp.isoformat())],
    )

    assert response.status_code == expected_status
    expected_count = 1 if expected_status == 200 else 0
    if expected_count:
        assert len(central.list_events(agent_id=str(identity["agent_id"]))) == 1
    else:
        assert not central.database_path.exists()


def test_complex_evidence_is_accepted_and_size_limit_is_enforced(
    tmp_path: Path,
) -> None:
    client, auth, central, users = build_application(
        tmp_path,
        evidence_max_bytes=1_024,
    )
    identity = enroll(auth, users["owner-a"], "owner-a-host")
    complex_evidence = {
        "connections": [
            {"ip": "192.0.2.10", "ports": [22, 80], "blocked": False},
            {"ip": "2001:db8::10", "ports": [443], "blocked": True},
        ],
        "metadata": {"labels": ["ssh", "brute-force"], "count": 2},
        "optional": None,
    }

    accepted = post_batch(
        client,
        identity["credential"],
        [event_payload(evidence=complex_evidence)],
    )
    rejected = post_batch(
        client,
        identity["credential"],
        [event_payload(evidence={"large": "x" * 2_000})],
    )

    assert accepted.status_code == 200
    assert rejected.status_code == 422
    assert len(central.list_events(agent_id=str(identity["agent_id"]))) == 1


def test_distinct_owner_cannot_spoof_agent_by_hostname(tmp_path: Path) -> None:
    client, auth, central, users = build_application(tmp_path)
    first = enroll(auth, users["owner-a"], "owner-a-host")
    second = enroll(auth, users["owner-b"], "owner-b-host")

    response = post_batch(
        client,
        first["credential"],
        [event_payload(hostname="owner-b-host")],
    )

    assert response.status_code == 200
    assert len(central.list_events(agent_id=str(first["agent_id"]))) == 1
    assert central.list_events(agent_id=str(second["agent_id"])) == []


def test_existing_health_login_events_and_heartbeat_still_work(tmp_path: Path) -> None:
    client, auth, _, users = build_application(tmp_path)
    identity = enroll(auth, users["owner-a"], "owner-a-host")

    health = client.get("/health")
    login = client.post(
        "/auth/login",
        json={"username": "owner-a", "password": TEST_PASSWORD},
    )
    events = client.get("/events")
    heartbeat = client.post(
        "/agent/heartbeat",
        headers=authorization(identity["credential"]),
        json={"agent_id": identity["agent_id"]},
    )

    assert health.status_code == 200
    assert login.status_code == 200
    assert events.status_code == 200
    assert heartbeat.status_code == 200
