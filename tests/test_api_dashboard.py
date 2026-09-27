from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.main import create_app
from app.core.config import AgentSettings
from app.storage.event_repository import EventRepository
from tests.api_test_helpers import create_test_auth_repository, login_test_user


def build_client(tmp_path: Path) -> TestClient:
    settings = AgentSettings(
        interval=1,
        state_dir=tmp_path / "state",
        log_dir=tmp_path / "logs",
    )
    settings.state_dir.mkdir(parents=True, exist_ok=True)

    repository = EventRepository(settings.database_file)
    repository.initialize()

    client = TestClient(
        create_app(
            settings=settings,
            repository=repository,
            auth_repository=create_test_auth_repository(tmp_path),
        )
    )
    login_test_user(client)
    return client


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


@pytest.mark.parametrize(
    "path",
    [
        "/dashboard",
        "/dashboard/events",
        "/dashboard/detections",
        "/dashboard/responses",
    ],
)
def test_dashboard_module_routes_return_shared_shell(
    tmp_path: Path,
    path: str,
) -> None:
    response = build_client(tmp_path).get(path)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "Auditoria System" in response.text
    assert "/dashboard/assets/styles.css" in response.text
    assert "/dashboard/assets/dashboard.js" in response.text


def test_dashboard_sidebar_links_to_real_modules(tmp_path: Path) -> None:
    html = build_client(tmp_path).get("/dashboard").text

    assert 'href="/dashboard"' in html
    assert 'href="/dashboard/events"' in html
    assert 'href="/dashboard/detections"' in html
    assert 'href="/dashboard/responses"' in html
    assert 'data-module="overview"' in html
    assert 'data-module="events"' in html
    assert 'data-module="detections"' in html
    assert 'data-module="responses"' in html
    assert 'data-module="users"' in html
    assert (
        'data-module="users" href="/dashboard/users" '
        'aria-label="Usuarios" title="Usuarios" hidden'
    ) in html
    assert 'id="sidebar-collapse"' in html
    assert 'aria-label="Contraer menú"' in html
    assert 'id="mobile-menu-toggle"' in html
    assert 'id="sidebar-backdrop"' in html


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
    assert '"/dashboard/events"' in script.text
    assert '"/dashboard/detections"' in script.text
    assert '"/dashboard/responses"' in script.text
    assert '"auditoria-sidebar-collapsed"' in script.text
    assert "window.localStorage" in script.text
    assert 'event.key === "Escape"' in script.text
    assert 'setAttribute("inert"' in script.text


def test_public_login_uses_csp_and_local_script(tmp_path: Path) -> None:
    public_client = TestClient(build_client(tmp_path).app)

    login = public_client.get("/login")
    script = public_client.get("/dashboard/assets/login.js")

    assert login.status_code == 200
    assert "script-src 'self'" in login.headers["content-security-policy"]
    assert "'unsafe-inline'" not in login.headers["content-security-policy"]
    assert "/dashboard/assets/login.js" in login.text
    assert 'type="password"' in login.text
    assert 'data-password-toggle' in login.text
    assert 'type="button"' in login.text
    assert 'aria-label="Mostrar contraseña"' in login.text
    assert 'aria-pressed="false"' in login.text
    assert script.status_code == 200
    assert "innerHTML" not in script.text
    assert 'input.type = visible ? "text" : "password"' in script.text
    assert 'visible ? "Ocultar contraseña" : "Mostrar contraseña"' in script.text


def test_user_form_has_accessible_password_toggle(tmp_path: Path) -> None:
    client = build_client(tmp_path)
    html = client.get("/dashboard/users").text
    script = client.get("/dashboard/assets/dashboard.js").text

    assert 'id="create-user-password"' in html
    assert 'aria-controls="create-user-password"' in html
    assert 'data-password-toggle' in html
    assert 'aria-pressed="false"' in html
    assert "configurePasswordToggles" in script


def test_dashboard_uses_supported_filters_and_overview_limits(tmp_path: Path) -> None:
    client = build_client(tmp_path)
    html = client.get("/dashboard").text
    script = client.get("/dashboard/assets/dashboard.js").text

    assert 'name="severity"' in html
    assert 'name="category"' in html
    assert 'name="event_type"' in html
    assert 'name="hostname"' in html
    assert "Mis servidores" in html
    assert "Conectar servidor" in html
    assert 'fetchJson("/events?limit=5")' in script
    assert 'fetchJson("/detections?limit=4")' in script
    assert 'endpointWithFilters("/events"' in script
    assert 'endpointWithFilters("/detections"' in script
    assert 'endpointWithFilters("/responses"' in script


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


def test_mutating_operations_are_limited_to_authentication_and_users(
    tmp_path: Path,
) -> None:
    application = build_client(tmp_path).app
    allowed_post_paths = {
        "/auth/login",
        "/auth/logout",
        "/admin/users",
        "/admin/users/{user_id}/status",
        "/admin/users/{user_id}/role",
        "/admin/users/{user_id}/hosts",
    }

    for route in application.routes:
        methods = getattr(route, "methods", set())
        assert {"PUT", "PATCH", "DELETE"}.isdisjoint(methods)
        if "POST" in methods:
            assert route.path in allowed_post_paths


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

    assert "[tool.setuptools.package-data]" in project_configuration
    assert '"app.api" = ["dashboard/*"]' in project_configuration
