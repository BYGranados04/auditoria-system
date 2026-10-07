from pathlib import Path

DASHBOARD_DIR = Path(__file__).resolve().parents[1] / "app" / "api" / "dashboard"


def read_asset(name: str) -> str:
    return (DASHBOARD_DIR / name).read_text(encoding="utf-8")


def test_dashboard_uses_agent_id_as_multiserver_identity() -> None:
    html = read_asset("index.html")
    javascript = read_asset("dashboard.js")

    assert 'id="agent-selector"' in html
    assert "selectedAgentId" in javascript
    assert "knownAgents" in javascript
    assert "knownHosts" not in javascript
    assert "selectedHostname" not in javascript
    assert "data-hostname-filter" not in html


def test_dashboard_distinguishes_presence_states() -> None:
    javascript = read_asset("dashboard.js")

    assert 'online: "En línea"' in javascript
    assert 'offline: "Sin conexión"' in javascript
    assert 'unknown: "Desconocido"' in javascript
    assert "agent.presence" in javascript


def test_dashboard_scopes_central_reads_by_selected_agent() -> None:
    javascript = read_asset("dashboard.js")

    assert 'params.set("agent_id", selectedAgentId)' in javascript
    assert 'appendAgentParam("/status")' in javascript
    assert 'endpointWithFilters("/events"' in javascript
    assert 'endpointWithFilters("/detections"' in javascript
    assert 'endpointWithFilters("/responses"' in javascript


def test_dashboard_does_not_close_response_event_type_list() -> None:
    html = read_asset("index.html")

    assert 'name="event_type" type="text"' in html
    assert '<option value="RESPONSE_DECISION">' not in html
    assert '<option value="RESPONSE_EXECUTION">' not in html


def test_dashboard_marks_notifications_as_local_scope() -> None:
    html = read_asset("index.html")

    assert "almacenamiento local de este nodo central" in html
    assert "sincronización de notificaciones de agentes remotos" in html


def test_dashboard_protects_against_stale_requests() -> None:
    javascript = read_asset("dashboard.js")

    assert "AbortController" in javascript
    assert "refreshGeneration" in javascript
    assert "generation !== refreshGeneration" in javascript


def test_dashboard_handles_noncentral_status_fields_explicitly() -> None:
    javascript = read_asset("dashboard.js")

    assert "No disponible centralmente" in javascript
    assert "status.live_response_blocks === null" in javascript
