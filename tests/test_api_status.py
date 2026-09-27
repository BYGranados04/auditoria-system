from pathlib import Path

from fastapi.testclient import TestClient

from app.api.main import create_app
from app.core.config import AgentSettings
from app.core.events import SecurityEvent
from app.storage.event_repository import EventRepository
from tests.api_test_helpers import create_test_auth_repository, login_test_user


def build_settings(
    tmp_path: Path,
) -> AgentSettings:
    return AgentSettings(
        interval=1,
        state_dir=tmp_path / "state",
        log_dir=tmp_path / "logs",
        response_mode="audit_only",
        allow_temporary_ip_block=False,
    )


def test_status_reports_runtime_and_repository_state(
    tmp_path: Path,
) -> None:
    settings = build_settings(tmp_path)

    settings.state_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    repository = EventRepository(settings.database_file)
    repository.initialize()

    repository.add(
        SecurityEvent(
            hostname="server-test",
            source="test",
            category="detection",
            event_type="TEST_DETECTION",
            severity="high",
            description="Evento de prueba.",
            evidence={
                "source_ip": "192.0.2.10",
            },
        )
    )

    application = create_app(
        settings=settings,
        repository=repository,
        auth_repository=create_test_auth_repository(tmp_path),
    )

    client = TestClient(application)
    login_test_user(client)

    response = client.get("/status")

    assert response.status_code == 200

    body = response.json()

    assert body["status"] == "ok"
    assert body["service"] == "auditoria-system-api"

    assert body["response_mode"] == "audit_only"

    assert body["automatic_blocking_enabled"] is False

    assert body["total_events"] == 1
    assert body["live_response_blocks"] == 0

    assert body["by_severity"] == {
        "high": 1,
    }

    assert body["hostname"]


def test_status_does_not_create_missing_database(
    tmp_path: Path,
) -> None:
    settings = build_settings(tmp_path)

    database_file = settings.database_file

    assert database_file.exists() is False

    application = create_app(
        settings=settings,
        auth_repository=create_test_auth_repository(tmp_path),
    )

    client = TestClient(application)
    login_test_user(client)

    health = client.get("/health")

    status = client.get("/status")

    assert health.status_code == 200

    assert status.status_code == 503
    assert status.json() == {"detail": ("Base de datos no disponible.")}

    assert database_file.exists() is False
