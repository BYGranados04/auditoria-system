from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from app.api.main import create_app
from app.core.config import AgentSettings
from app.core.events import SecurityEvent
from app.storage.event_repository import EventRepository
from tests.api_test_helpers import create_test_auth_repository, login_test_user


def build_client(
    tmp_path: Path,
) -> tuple[TestClient, EventRepository]:
    settings = AgentSettings(
        interval=1,
        state_dir=tmp_path / "state",
        log_dir=tmp_path / "logs",
    )

    settings.state_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    repository = EventRepository(settings.database_file)
    repository.initialize()

    application = create_app(
        settings=settings,
        repository=repository,
        auth_repository=create_test_auth_repository(tmp_path),
    )

    client = TestClient(application)
    login_test_user(client)

    return (
        client,
        repository,
    )


def add_response_event(
    repository: EventRepository,
    *,
    event_type: str,
    timestamp: datetime,
    evidence: dict,
) -> SecurityEvent:
    event = SecurityEvent(
        timestamp=timestamp,
        hostname="server-test",
        source="response-test",
        category="response",
        event_type=event_type,
        severity="low",
        description="Evento de respuesta.",
        evidence=evidence,
    )

    repository.add(event)

    return event


def test_responses_returns_decisions_and_executions_only(
    tmp_path: Path,
) -> None:
    client, repository = build_client(tmp_path)

    decision = add_response_event(
        repository,
        event_type="RESPONSE_DECISION",
        timestamp=datetime(
            2026,
            9,
            24,
            10,
            0,
            tzinfo=UTC,
        ),
        evidence={
            "detection_event_id": "detection-1",
            "action": "NO_ACTION",
        },
    )

    execution = add_response_event(
        repository,
        event_type="RESPONSE_EXECUTION",
        timestamp=datetime(
            2026,
            9,
            24,
            10,
            1,
            tzinfo=UTC,
        ),
        evidence={
            "detection_event_id": "detection-1",
            "response_event_id": str(decision.event_id),
            "status": "SKIPPED",
        },
    )

    add_response_event(
        repository,
        event_type="RESPONSE_RECOVERY",
        timestamp=datetime(
            2026,
            9,
            24,
            10,
            2,
            tzinfo=UTC,
        ),
        evidence={
            "restored_count": 0,
        },
    )

    response = client.get("/responses")

    assert response.status_code == 200

    body = response.json()

    assert len(body) == 2

    event_ids = {item["event_id"] for item in body}

    assert event_ids == {
        str(decision.event_id),
        str(execution.event_id),
    }

    assert all(item["category"] == "response" for item in body)

    assert {item["event_type"] for item in body} == {
        "RESPONSE_DECISION",
        "RESPONSE_EXECUTION",
    }


def test_responses_can_filter_execution_events(
    tmp_path: Path,
) -> None:
    client, repository = build_client(tmp_path)

    add_response_event(
        repository,
        event_type="RESPONSE_DECISION",
        timestamp=datetime(
            2026,
            9,
            24,
            11,
            0,
            tzinfo=UTC,
        ),
        evidence={
            "action": "NO_ACTION",
        },
    )

    execution = add_response_event(
        repository,
        event_type="RESPONSE_EXECUTION",
        timestamp=datetime(
            2026,
            9,
            24,
            11,
            1,
            tzinfo=UTC,
        ),
        evidence={
            "status": "SKIPPED",
        },
    )

    response = client.get(
        "/responses",
        params={"event_type": ("RESPONSE_EXECUTION")},
    )

    assert response.status_code == 200

    body = response.json()

    assert len(body) == 1
    assert body[0]["event_id"] == str(execution.event_id)


def test_responses_rejects_recovery_as_public_type(
    tmp_path: Path,
) -> None:
    client, _ = build_client(tmp_path)

    response = client.get(
        "/responses",
        params={"event_type": ("RESPONSE_RECOVERY")},
    )

    assert response.status_code == 422


def test_responses_rejects_invalid_limit(
    tmp_path: Path,
) -> None:
    client, _ = build_client(tmp_path)

    assert (
        client.get(
            "/responses",
            params={"limit": 0},
        ).status_code
        == 422
    )

    assert (
        client.get(
            "/responses",
            params={"limit": 1001},
        ).status_code
        == 422
    )


def test_responses_rejects_naive_datetime(
    tmp_path: Path,
) -> None:
    client, _ = build_client(tmp_path)

    response = client.get(
        "/responses",
        params={"since": ("2026-09-24T10:00:00")},
    )

    assert response.status_code == 422

    assert response.json() == {"detail": ("since debe incluir zona horaria.")}
