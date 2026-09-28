from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from app.api.main import create_app
from app.central.config import CentralSettings
from app.central.repository import CentralEventRepository
from app.core.config import AgentSettings
from app.core.events import SecurityEvent
from app.storage.event_repository import EventRepository
from tests.api_test_helpers import create_test_auth_repository, login_test_user


def build_client(
    tmp_path: Path,
) -> tuple[TestClient, CentralEventRepository]:
    settings = AgentSettings(
        interval=1,
        state_dir=tmp_path / "state",
        log_dir=tmp_path / "logs",
    )

    settings.state_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    local_repository = EventRepository(settings.database_file)
    local_repository.initialize()
    central_settings = CentralSettings(
        database_file=tmp_path / "central" / "central.db"
    )
    repository = CentralEventRepository(central_settings.database_file)

    application = create_app(
        settings=settings,
        repository=local_repository,
        auth_repository=create_test_auth_repository(tmp_path),
        central_settings=central_settings,
        central_repository=repository,
    )

    client = TestClient(application)
    login_test_user(client)

    return (
        client,
        repository,
    )


def add_event(
    repository: CentralEventRepository,
    *,
    timestamp: datetime,
    severity: str,
    category: str,
    event_type: str,
    hostname: str = "server-test",
) -> SecurityEvent:
    event = SecurityEvent(
        timestamp=timestamp,
        hostname=hostname,
        source="test",
        category=category,
        event_type=event_type,
        severity=severity,
        description="Evento de prueba.",
        evidence={
            "source_ip": "192.0.2.10",
        },
    )

    repository.add_event(agent_id="agt_test", event=event)

    return event


def test_events_returns_clean_event_models(
    tmp_path: Path,
) -> None:
    client, repository = build_client(tmp_path)

    event = add_event(
        repository,
        timestamp=datetime(
            2026,
            9,
            24,
            12,
            0,
            tzinfo=UTC,
        ),
        severity="high",
        category="detection",
        event_type="TEST_DETECTION",
    )

    response = client.get("/events")

    assert response.status_code == 200

    body = response.json()

    assert len(body) == 1

    result = body[0]

    assert result["event_id"] == str(event.event_id)

    assert result["severity"] == "high"
    assert result["category"] == "detection"
    assert result["event_type"] == "TEST_DETECTION"

    assert result["evidence"] == {
        "source_ip": "192.0.2.10",
    }

    assert "evidence_json" not in result


def test_events_supports_filters(
    tmp_path: Path,
) -> None:
    client, repository = build_client(tmp_path)

    add_event(
        repository,
        timestamp=datetime(
            2026,
            9,
            24,
            10,
            0,
            tzinfo=UTC,
        ),
        severity="low",
        category="authentication",
        event_type="SSH_AUTH_SUCCESS",
    )

    matching = add_event(
        repository,
        timestamp=datetime(
            2026,
            9,
            24,
            11,
            0,
            tzinfo=UTC,
        ),
        severity="high",
        category="detection",
        event_type="SSH_BRUTE_FORCE_ATTEMPT",
    )

    response = client.get(
        "/events",
        params={
            "severity": "high",
            "category": "detection",
            "event_type": ("SSH_BRUTE_FORCE_ATTEMPT"),
            "since": ("2026-09-24T10:30:00Z"),
            "until": ("2026-09-24T11:30:00Z"),
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert len(body) == 1
    assert body[0]["event_id"] == str(matching.event_id)


def test_events_rejects_invalid_limit(
    tmp_path: Path,
) -> None:
    client, _ = build_client(tmp_path)

    too_low = client.get(
        "/events",
        params={"limit": 0},
    )

    too_high = client.get(
        "/events",
        params={"limit": 1001},
    )

    assert too_low.status_code == 422
    assert too_high.status_code == 422


def test_events_rejects_naive_datetime(
    tmp_path: Path,
) -> None:
    client, _ = build_client(tmp_path)

    response = client.get(
        "/events",
        params={"since": ("2026-09-24T10:00:00")},
    )

    assert response.status_code == 422

    assert response.json() == {"detail": ("since debe incluir zona horaria.")}


def test_events_rejects_reversed_range(
    tmp_path: Path,
) -> None:
    client, _ = build_client(tmp_path)

    response = client.get(
        "/events",
        params={
            "since": ("2026-09-24T12:00:00Z"),
            "until": ("2026-09-24T11:00:00Z"),
        },
    )

    assert response.status_code == 422

    assert response.json() == {"detail": ("since no puede ser posterior a until.")}
