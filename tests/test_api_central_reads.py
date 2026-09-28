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

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)


def build_application(
    tmp_path: Path,
    *,
    populate_central: bool = True,
) -> tuple[TestClient, AuthRepository, CentralEventRepository, dict[str, object]]:
    settings = AgentSettings(
        interval=1,
        state_dir=tmp_path / "state",
        log_dir=tmp_path / "logs",
    )
    settings.state_dir.mkdir(parents=True)
    local = EventRepository(settings.database_file)
    local.initialize()
    local.add(
        SecurityEvent(
            timestamp=NOW,
            hostname="shared-host",
            source="legacy-local",
            category="detection",
            event_type="LEGACY_LOCAL_EVENT",
            severity="critical",
            description="No tiene identidad central demostrable.",
            evidence={},
        )
    )

    auth = AuthRepository(
        tmp_path / "auth" / "auth.db",
        scrypt_parameters=TEST_SCRYPT,
    )
    users: dict[str, int] = {}
    for username, role in (
        ("admin", "superadmin"),
        ("viewer-a", "viewer"),
        ("viewer-b", "viewer"),
        ("viewer-empty", "viewer"),
    ):
        users[username] = int(
            auth.create_user(
                username=username,
                password=TEST_PASSWORD,
                role=role,
                now=NOW,
            )["id"]
        )

    identities: dict[str, dict[str, str]] = {}
    for owner, hostname in (("viewer-a", "registered-a"), ("viewer-b", "registered-b")):
        token = auth.create_agent_registration_token(users[owner], now=NOW)
        enrolled = auth.enroll_agent(
            registration_token=token.token,
            hostname=hostname,
            now=NOW,
        )
        identities[owner] = {
            "agent_id": str(enrolled.agent["agent_id"]),
            "credential": enrolled.credential,
        }

    central_settings = CentralSettings(
        database_file=tmp_path / "central" / "central.db"
    )
    central = CentralEventRepository(
        central_settings.database_file,
        clock=lambda: NOW,
    )
    if populate_central:
        for owner, offset in (("viewer-a", 0), ("viewer-b", 1)):
            for category, event_type, severity in (
                ("system", "AGENT_STARTED", "low"),
                ("detection", "SSH_BRUTE_FORCE_ATTEMPT", "high"),
                ("response", "RESPONSE_DECISION", "medium"),
            ):
                central.add_event(
                    agent_id=identities[owner]["agent_id"],
                    event=SecurityEvent(
                        timestamp=NOW + timedelta(seconds=offset),
                        hostname="shared-host",
                        source="test-central",
                        category=category,
                        event_type=event_type,
                        severity=severity,
                        description=f"{owner}: {category}",
                        evidence={"owner": owner},
                    ),
                )

    application = create_app(
        settings=settings,
        repository=EventRepository(settings.database_file, read_only=True),
        auth_settings=AuthSettings(database_file=auth.database_path),
        auth_repository=auth,
        central_settings=central_settings,
        central_repository=central,
        clock=lambda: NOW,
    )
    context: dict[str, object] = {
        "users": users,
        "identities": identities,
        "local_database": settings.database_file,
    }
    return TestClient(application), auth, central, context


def login(client: TestClient, username: str) -> None:
    response = client.post(
        "/auth/login",
        json={"username": username, "password": TEST_PASSWORD},
    )
    assert response.status_code == 200


def test_viewers_are_isolated_by_agent_id_even_with_shared_hostname(
    tmp_path: Path,
) -> None:
    root, _, _, context = build_application(tmp_path)
    identities = context["identities"]
    assert isinstance(identities, dict)
    viewer_a = TestClient(root.app)
    viewer_b = TestClient(root.app)
    login(viewer_a, "viewer-a")
    login(viewer_b, "viewer-b")

    events_a = viewer_a.get("/events").json()
    events_b = viewer_b.get("/events").json()

    assert len(events_a) == 3
    assert len(events_b) == 3
    assert {item["agent_id"] for item in events_a} == {
        identities["viewer-a"]["agent_id"]
    }
    assert {item["agent_id"] for item in events_b} == {
        identities["viewer-b"]["agent_id"]
    }
    assert {item["hostname"] for item in events_a + events_b} == {"shared-host"}
    assert all(item["event_type"] != "LEGACY_LOCAL_EVENT" for item in events_a)


def test_agent_id_filter_enforces_ownership_and_existence(tmp_path: Path) -> None:
    root, _, _, context = build_application(tmp_path)
    identities = context["identities"]
    assert isinstance(identities, dict)
    viewer = TestClient(root.app)
    login(viewer, "viewer-a")
    own_id = identities["viewer-a"]["agent_id"]
    other_id = identities["viewer-b"]["agent_id"]

    own = viewer.get("/events", params={"agent_id": own_id})
    other = viewer.get("/events", params={"agent_id": other_id})
    missing = viewer.get("/events", params={"agent_id": "agt_missing"})

    assert own.status_code == 200
    assert {item["agent_id"] for item in own.json()} == {own_id}
    assert other.status_code == 404
    assert missing.status_code == 404
    assert other.json()["detail"] == "Servidor no encontrado."
    assert missing.json()["detail"] == "Servidor no encontrado."


def test_superadmin_and_empty_viewer_have_distinct_scope_semantics(
    tmp_path: Path,
) -> None:
    root, _, _, context = build_application(tmp_path)
    identities = context["identities"]
    assert isinstance(identities, dict)
    admin = TestClient(root.app)
    empty = TestClient(root.app)
    login(admin, "admin")
    login(empty, "viewer-empty")

    all_events = admin.get("/events")
    filtered = admin.get(
        "/events",
        params={"agent_id": identities["viewer-b"]["agent_id"]},
    )

    assert len(all_events.json()) == 6
    assert {item["agent_id"] for item in filtered.json()} == {
        identities["viewer-b"]["agent_id"]
    }
    assert admin.get("/events", params={"agent_id": "agt_missing"}).status_code == 404
    assert empty.get("/events").json() == []


def test_filters_apply_inside_agent_scope_and_preserve_response_shape(
    tmp_path: Path,
) -> None:
    root, _, _, context = build_application(tmp_path)
    identities = context["identities"]
    assert isinstance(identities, dict)
    viewer = TestClient(root.app)
    login(viewer, "viewer-a")

    detections = viewer.get("/detections").json()
    responses = viewer.get("/responses").json()
    high = viewer.get("/events", params={"severity": "high"}).json()
    hostname = viewer.get("/events", params={"hostname": "shared-host"}).json()
    other_hostname = viewer.get(
        "/events", params={"hostname": "registered-b"}
    ).json()
    limited = viewer.get("/events", params={"limit": 1}).json()

    assert [item["category"] for item in detections] == ["detection"]
    assert [item["category"] for item in responses] == ["response"]
    assert [item["severity"] for item in high] == ["high"]
    assert len(hostname) == 3
    assert other_hostname == []
    assert len(limited) == 1
    assert set(limited[0]) == {
        "agent_id",
        "event_id",
        "timestamp",
        "hostname",
        "source",
        "category",
        "event_type",
        "severity",
        "description",
        "evidence",
    }
    assert limited[0]["agent_id"] == identities["viewer-a"]["agent_id"]
    assert limited[0]["timestamp"] == "2026-09-27T12:00:00Z"


def test_response_recovery_events_keep_agent_scope_with_shared_hostname(
    tmp_path: Path,
) -> None:
    root, _, central, context = build_application(tmp_path)
    identities = context["identities"]
    assert isinstance(identities, dict)
    central.add_event(
        agent_id=identities["viewer-b"]["agent_id"],
        event=SecurityEvent(
            timestamp=NOW + timedelta(seconds=2),
            hostname="shared-host",
            source="response-recovery",
            category="response",
            event_type="RESPONSE_RECOVERY_ERROR",
            severity="high",
            description="La recuperación defensiva falló.",
            evidence={},
        ),
    )
    viewer_a = TestClient(root.app)
    admin = TestClient(root.app)
    login(viewer_a, "viewer-a")
    login(admin, "admin")

    own = viewer_a.get("/responses")
    foreign = viewer_a.get(
        "/responses",
        params={"agent_id": identities["viewer-b"]["agent_id"]},
    )
    recovery = admin.get(
        "/responses",
        params={"event_type": "RESPONSE_RECOVERY_ERROR"},
    )

    assert own.status_code == 200
    assert {item["agent_id"] for item in own.json()} == {
        identities["viewer-a"]["agent_id"]
    }
    assert foreign.status_code == 404
    assert [item["agent_id"] for item in recovery.json()] == [
        identities["viewer-b"]["agent_id"]
    ]


def test_missing_central_database_returns_empty_without_creating_it(
    tmp_path: Path,
) -> None:
    root, _, central, _ = build_application(tmp_path, populate_central=False)
    viewer = TestClient(root.app)
    login(viewer, "viewer-a")

    assert not central.database_path.exists()
    assert viewer.get("/events").json() == []
    assert viewer.get("/detections").json() == []
    assert viewer.get("/responses").json() == []
    assert not central.database_path.exists()
