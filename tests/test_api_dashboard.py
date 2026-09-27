from pathlib import Path

from fastapi.testclient import TestClient

from app.api.main import create_app
from app.core.config import AgentSettings
from app.storage.event_repository import EventRepository


def build_client(tmp_path: Path) -> TestClient:
    settings = AgentSettings(
        interval=1,
        state_dir=tmp_path / "state",
        log_dir=tmp_path / "logs",
    )
    settings.state_dir.mkdir(parents=True, exist_ok=True)

    repository = EventRepository(settings.database_file)
    repository.initialize()

    return TestClient(
        create_app(
            settings=settings,
            repository=repository,
        )
    )


def test_dashboard_returns_html(tmp_path: Path) -> None:
    response = build_client(tmp_path).get("/dashboard")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    csp = response.headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "'unsafe-inline'" not in csp
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "Auditoria System" in response.text
    assert 'id="events-body"' in response.text
    assert "<script src=" in response.text
    assert "<script>" not in response.text
    assert "onclick=" not in response.text


def test_dashboard_local_assets_are_accessible(tmp_path: Path) -> None:
    client = build_client(tmp_path)

    css = client.get("/dashboard/assets/styles.css")
    script = client.get("/dashboard/assets/dashboard.js")

    assert css.status_code == 200
    assert css.headers["content-type"].startswith("text/css")
    assert ".metric-grid" in css.text

    assert script.status_code == 200
    assert script.headers["content-type"].startswith("text/javascript")
    assert 'fetchJson("/status")' in script.text
    assert "innerHTML" not in script.text
    assert "eval(" not in script.text
    assert "setInterval" not in script.text
    assert "visibilitychange" in script.text
    assert "clearTimeout" in script.text


def test_existing_endpoints_work_with_dashboard(tmp_path: Path) -> None:
    client = build_client(tmp_path)

    assert client.get("/health").status_code == 200
    assert client.get("/status").status_code == 200
    assert client.get("/events").status_code == 200
    assert client.get("/detections").status_code == 200
    assert client.get("/responses").status_code == 200


def test_dashboard_supports_empty_repository(tmp_path: Path) -> None:
    client = build_client(tmp_path)

    assert client.get("/dashboard").status_code == 200
    assert client.get("/status").json()["total_events"] == 0
    assert client.get("/events").json() == []
    assert client.get("/detections").json() == []
    assert client.get("/responses").json() == []


def test_application_exposes_no_mutating_operations(tmp_path: Path) -> None:
    application = build_client(tmp_path).app
    forbidden_methods = {"POST", "PUT", "PATCH", "DELETE"}

    for route in application.routes:
        methods = getattr(route, "methods", set())
        assert forbidden_methods.isdisjoint(methods)


def test_dashboard_uses_local_assets_and_relative_api_paths(tmp_path: Path) -> None:
    client = build_client(tmp_path)
    html = client.get("/dashboard").text
    script = client.get("/dashboard/assets/dashboard.js").text

    assert "https://" not in html
    assert "http://" not in html
    assert 'fetchJson("/health")' in script
    assert 'fetchJson("/status")' in script
    assert "textContent" in script


def test_dashboard_assets_are_included_as_package_data() -> None:
    project_configuration = Path("pyproject.toml").read_text(encoding="utf-8")

    assert '[tool.setuptools.package-data]' in project_configuration
    assert '"app.api" = ["dashboard/*"]' in project_configuration
