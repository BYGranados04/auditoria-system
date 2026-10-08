"""Control plane v1.1: display_name, modo deseado/efectivo, revisión y ACK."""

from __future__ import annotations

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
from tests.api_test_helpers import TEST_PASSWORD, TEST_SCRYPT

NOW = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)
DASHBOARD_DIR = Path(__file__).resolve().parents[1] / "app" / "api" / "dashboard"


class Environment:
    def __init__(self, tmp_path: Path) -> None:
        self.current = [NOW]
        settings = AgentSettings(
            interval=1,
            state_dir=tmp_path / "state",
            log_dir=tmp_path / "logs",
            identity_file=tmp_path / "agent-identity.json",
        )
        self.auth = AuthRepository(
            tmp_path / "auth" / "auth.db",
            scrypt_parameters=TEST_SCRYPT,
        )
        self.users = {
            name: int(
                self.auth.create_user(
                    username=name,
                    password=TEST_PASSWORD,
                    role=role,
                    now=NOW,
                )["id"]
            )
            for name, role in (("admin", "superadmin"), ("viewer-a", "viewer"))
        }
        central_settings = CentralSettings(
            database_file=tmp_path / "central" / "central.db"
        )
        self.central = CentralEventRepository(
            central_settings.database_file,
            clock=lambda: self.current[0],
        )
        self.app = create_app(
            settings=settings,
            auth_settings=AuthSettings(
                database_file=self.auth.database_path,
                central_url="https://central.example",
                agent_offline_after_seconds=120,
            ),
            auth_repository=self.auth,
            central_settings=central_settings,
            central_repository=self.central,
            clock=lambda: self.current[0],
        )
        self.agent_client = TestClient(self.app)

    def enroll(self, owner: str = "viewer-a", hostname: str = "srv-web-01") -> dict:
        token = self.auth.create_agent_registration_token(self.users[owner], now=NOW)
        enrolled = self.auth.enroll_agent(
            registration_token=token.token,
            hostname=hostname,
            now=NOW,
        )
        return {
            "agent_id": str(enrolled.agent["agent_id"]),
            "credential": enrolled.credential,
        }

    def session(self, username: str) -> tuple[TestClient, dict[str, str]]:
        client = TestClient(self.app)
        response = client.post(
            "/auth/login",
            json={"username": username, "password": TEST_PASSWORD},
        )
        assert response.status_code == 200
        return client, {"X-CSRF-Token": str(response.json()["csrf_token"])}

    def bearer(self, credential: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {credential}"}

    def agent_config(self, credential: str):
        return self.agent_client.get("/agent/config", headers=self.bearer(credential))

    def report(self, credential: str, **overrides: object):
        body: dict[str, object] = {
            "applied_revision": 0,
            "effective_response_mode": "audit_only",
            "config_source": "central",
            "blocking_enabled": False,
            "status": "applied",
        }
        body.update(overrides)
        return self.agent_client.post(
            "/agent/config/state",
            headers=self.bearer(credential),
            json=body,
        )

    def set_mode(
        self,
        client: TestClient,
        headers: dict[str, str],
        agent_id: str,
        mode: str,
        expected_revision: int,
    ):
        return client.put(
            f"/agents/{agent_id}/response-mode",
            headers=headers,
            json={"response_mode": mode, "expected_revision": expected_revision},
        )

    def history(self) -> list[tuple]:
        with sqlite3.connect(self.auth.database_path) as connection:
            return connection.execute(
                """
                SELECT agent_id, revision, field, old_value, new_value,
                       changed_by_user_id, changed_by_username
                FROM agent_config_changes
                ORDER BY id
                """
            ).fetchall()


@pytest.fixture
def env(tmp_path: Path) -> Environment:
    return Environment(tmp_path)


# ------------------------------------------------------------- heartbeat


def test_heartbeat_records_agent_version_and_exposes_config_revision(
    env: Environment,
) -> None:
    agent = env.enroll()

    response = env.agent_client.post(
        "/agent/heartbeat",
        headers=env.bearer(agent["credential"]),
        json={"hostname": "srv-web-01", "agent_version": "1.1.0"},
    )

    assert response.status_code == 200
    assert response.json()["agent_version"] == "1.1.0"
    assert response.json()["config_revision"] == 0
    assert env.auth.get_agent(agent["agent_id"])["agent_version"] == "1.1.0"


def test_invalid_agent_version_is_rejected_without_updating_last_seen(
    env: Environment,
) -> None:
    agent = env.enroll()

    response = env.agent_client.post(
        "/agent/heartbeat",
        headers=env.bearer(agent["credential"]),
        json={"agent_version": "1.1.0\n<script>"},
    )

    assert response.status_code == 422
    stored = env.auth.get_agent(agent["agent_id"])
    assert stored["last_seen_at"] is None
    assert stored["agent_version"] is None


def test_invalid_credential_does_not_update_last_seen(env: Environment) -> None:
    agent = env.enroll()

    response = env.agent_client.post(
        "/agent/heartbeat",
        headers=env.bearer("agc_not_valid"),
        json={"agent_version": "1.1.0"},
    )

    assert response.status_code == 401
    assert env.auth.get_agent(agent["agent_id"])["last_seen_at"] is None


def test_presence_online_then_offline_after_threshold(env: Environment) -> None:
    agent = env.enroll()
    assert env.agent_client.post(
        "/agent/heartbeat", headers=env.bearer(agent["credential"]), json={}
    ).json()["presence"] == "online"

    admin, _ = env.session("admin")
    env.current[0] += timedelta(seconds=120)
    assert admin.get(f"/agents/{agent['agent_id']}").json()["presence"] == "online"
    env.current[0] += timedelta(seconds=1)
    assert admin.get(f"/agents/{agent['agent_id']}").json()["presence"] == "offline"


def test_agent_v1_0_heartbeat_and_event_sync_keep_working(env: Environment) -> None:
    """Un agente v1.0 no envía versión ni conoce /agent/config."""

    agent = env.enroll()

    heartbeat = env.agent_client.post(
        "/agent/heartbeat",
        headers=env.bearer(agent["credential"]),
        json={"agent_id": agent["agent_id"]},
    )
    batch = env.agent_client.post(
        "/agent/events/batch",
        headers=env.bearer(agent["credential"]),
        json={
            "events": [
                {
                    "event_id": str(uuid4()),
                    "timestamp": NOW.isoformat(),
                    "hostname": "srv-web-01",
                    "source": "continuous-agent",
                    "category": "agent",
                    "event_type": "AGENT_STARTED",
                    "severity": "low",
                    "description": "Agente v1.0.",
                    "evidence": {},
                }
            ]
        },
    )

    assert heartbeat.status_code == 200
    assert batch.status_code == 200
    assert batch.json()["inserted"] == 1
    stored = env.auth.get_agent(agent["agent_id"])
    assert stored["agent_version"] is None
    assert stored["config_protocol"] is None
    assert stored["effective_response_mode"] is None


# ---------------------------------------------------------- display_name


def test_superadmin_sets_display_name_without_touching_hostname(
    env: Environment,
) -> None:
    agent = env.enroll()
    admin, headers = env.session("admin")

    response = admin.patch(
        f"/agents/{agent['agent_id']}",
        headers=headers,
        json={"display_name": "  Servidor Producción Web  "},
    )

    assert response.status_code == 200
    assert response.json()["display_name"] == "Servidor Producción Web"
    assert response.json()["hostname"] == "srv-web-01"
    assert env.history() == [
        (
            agent["agent_id"],
            0,
            "display_name",
            None,
            "Servidor Producción Web",
            env.users["admin"],
            "admin",
        )
    ]


def test_display_name_accepts_exactly_64_characters(env: Environment) -> None:
    agent = env.enroll()
    admin, headers = env.session("admin")

    response = admin.patch(
        f"/agents/{agent['agent_id']}",
        headers=headers,
        json={"display_name": "á" * 64},
    )

    assert response.status_code == 200
    assert response.json()["display_name"] == "á" * 64


@pytest.mark.parametrize(
    "value",
    [
        "x" * 65,
        "Producción\nWeb",
        "Producción\tWeb",
        "Servidor\x07",
        "abc‮dcba",  # override bidireccional
        "zero​width",  # carácter de formato invisible
    ],
)
def test_invalid_display_name_is_rejected(env: Environment, value: str) -> None:
    agent = env.enroll()
    admin, headers = env.session("admin")

    response = admin.patch(
        f"/agents/{agent['agent_id']}",
        headers=headers,
        json={"display_name": value},
    )

    assert response.status_code == 422
    assert env.auth.get_agent(agent["agent_id"])["display_name"] is None
    assert env.history() == []


def test_empty_display_name_falls_back_to_hostname(env: Environment) -> None:
    agent = env.enroll()
    admin, headers = env.session("admin")
    admin.patch(
        f"/agents/{agent['agent_id']}",
        headers=headers,
        json={"display_name": "Producción"},
    )

    response = admin.patch(
        f"/agents/{agent['agent_id']}",
        headers=headers,
        json={"display_name": "   "},
    )

    assert response.status_code == 200
    assert response.json()["display_name"] is None
    assert response.json()["hostname"] == "srv-web-01"
    javascript = (DASHBOARD_DIR / "dashboard.js").read_text(encoding="utf-8")
    fallback = "displayValue(agent?.display_name, displayValue(agent?.hostname))"
    assert fallback in javascript


def test_display_names_do_not_need_to_be_unique(env: Environment) -> None:
    first = env.enroll(hostname="srv-a")
    second = env.enroll(hostname="srv-b")
    admin, headers = env.session("admin")

    for agent in (first, second):
        assert (
            admin.patch(
                f"/agents/{agent['agent_id']}",
                headers=headers,
                json={"display_name": "Web"},
            ).status_code
            == 200
        )


# ------------------------------------------------------------- permisos


def test_viewer_cannot_change_display_name_or_mode_even_for_own_agent(
    env: Environment,
) -> None:
    agent = env.enroll(owner="viewer-a")
    env.agent_config(agent["credential"])
    viewer, headers = env.session("viewer-a")

    rename = viewer.patch(
        f"/agents/{agent['agent_id']}",
        headers=headers,
        json={"display_name": "Mío"},
    )
    mode = env.set_mode(viewer, headers, agent["agent_id"], "automatic", 0)

    assert rename.status_code == 403
    assert mode.status_code == 403
    stored = env.auth.get_agent(agent["agent_id"])
    assert stored["display_name"] is None
    assert stored["desired_response_mode"] is None
    assert env.history() == []


def test_admin_changes_require_session_csrf_and_same_origin(env: Environment) -> None:
    agent = env.enroll()
    env.agent_config(agent["credential"])
    anonymous = TestClient(env.app)
    admin, headers = env.session("admin")
    path = f"/agents/{agent['agent_id']}"

    assert anonymous.patch(path, json={"display_name": "x"}).status_code == 401
    assert admin.patch(path, json={"display_name": "x"}).status_code == 403
    assert (
        admin.patch(
            path,
            headers={**headers, "Origin": "https://attacker.example"},
            json={"display_name": "x"},
        ).status_code
        == 403
    )
    assert (
        admin.put(
            f"{path}/response-mode",
            json={"response_mode": "automatic", "expected_revision": 0},
        ).status_code
        == 403
    )
    assert (
        admin.put(
            f"{path}/response-mode",
            headers={**headers, "Origin": "https://attacker.example"},
            json={"response_mode": "automatic", "expected_revision": 0},
        ).status_code
        == 403
    )
    assert env.history() == []


def test_unknown_agent_returns_404(env: Environment) -> None:
    admin, headers = env.session("admin")

    assert (
        admin.patch("/agents/agt_missing", headers=headers, json={"display_name": "x"})
        .status_code
        == 404
    )
    assert env.set_mode(admin, headers, "agt_missing", "assisted", 0).status_code == 404


# ------------------------------------------------------ modo deseado


def test_mode_change_requires_agent_with_central_config_support(
    env: Environment,
) -> None:
    """config_protocol NULL (agente v1.0) => 409 y selector deshabilitado."""

    agent = env.enroll()
    admin, headers = env.session("admin")

    response = env.set_mode(admin, headers, agent["agent_id"], "automatic", 0)

    assert response.status_code == 409
    assert env.auth.get_agent(agent["agent_id"])["config_revision"] == 0
    javascript = (DASHBOARD_DIR / "dashboard.js").read_text(encoding="utf-8")
    # Agente sin protocolo central: administración local y selector deshabilitado.
    local_rule = (
        'return agent.config_source === "local" || !centralControlAvailable(agent);'
    )
    assert local_rule in javascript
    assert "const canEdit = isAdmin && !local;" in javascript
    assert "button.disabled = !canEdit" in javascript


def test_valid_mode_change_increments_revision_and_records_history(
    env: Environment,
) -> None:
    agent = env.enroll()
    assert env.agent_config(agent["credential"]).json() == {
        "revision": 0,
        "response_mode": None,
    }
    admin, headers = env.session("admin")

    first = env.set_mode(admin, headers, agent["agent_id"], "assisted", 0)
    second = env.set_mode(admin, headers, agent["agent_id"], "automatic", 1)

    assert first.status_code == 200
    assert second.status_code == 200
    body = second.json()
    assert body["desired_response_mode"] == "automatic"
    assert body["config_revision"] == 2
    assert body["applied_config_revision"] == 0
    assert body["config_pending"] is True
    assert body["config_protocol"] == 1
    assert env.history() == [
        (
            agent["agent_id"],
            1,
            "response_mode",
            None,
            "assisted",
            env.users["admin"],
            "admin",
        ),
        (
            agent["agent_id"],
            2,
            "response_mode",
            "assisted",
            "automatic",
            env.users["admin"],
            "admin",
        ),
    ]


@pytest.mark.parametrize("mode", ["disabled", "AUTOMATIC", "", "audit"])
def test_invalid_desired_mode_is_rejected(env: Environment, mode: str) -> None:
    agent = env.enroll()
    env.agent_config(agent["credential"])
    admin, headers = env.session("admin")

    response = env.set_mode(admin, headers, agent["agent_id"], mode, 0)

    assert response.status_code == 422
    assert env.auth.get_agent(agent["agent_id"])["config_revision"] == 0


def test_stale_expected_revision_is_a_conflict(env: Environment) -> None:
    agent = env.enroll()
    env.agent_config(agent["credential"])
    admin, headers = env.session("admin")
    first = env.set_mode(admin, headers, agent["agent_id"], "assisted", 0)
    assert first.status_code == 200

    response = env.set_mode(admin, headers, agent["agent_id"], "automatic", 0)

    assert response.status_code == 409
    stored = env.auth.get_agent(agent["agent_id"])
    assert stored["desired_response_mode"] == "assisted"
    assert stored["config_revision"] == 1


def test_config_stays_pending_while_agent_is_offline(env: Environment) -> None:
    agent = env.enroll()
    env.agent_config(agent["credential"])
    env.report(agent["credential"], effective_response_mode="assisted")
    admin, headers = env.session("admin")

    env.set_mode(admin, headers, agent["agent_id"], "automatic", 0)
    env.current[0] += timedelta(minutes=10)
    stored = admin.get(f"/agents/{agent['agent_id']}").json()

    assert stored["presence"] in {"offline", "unknown"}
    assert stored["desired_response_mode"] == "automatic"
    assert stored["effective_response_mode"] == "assisted"
    assert stored["config_pending"] is True


# ------------------------------------------------ canal del agente


def test_agent_config_is_scoped_to_the_credential_owner(env: Environment) -> None:
    first = env.enroll(hostname="srv-a")
    second = env.enroll(hostname="srv-b")
    env.agent_config(first["credential"])
    env.agent_config(second["credential"])
    admin, headers = env.session("admin")
    env.set_mode(admin, headers, first["agent_id"], "automatic", 0)

    assert env.agent_config(first["credential"]).json() == {
        "revision": 1,
        "response_mode": "automatic",
    }
    assert env.agent_config(second["credential"]).json() == {
        "revision": 0,
        "response_mode": None,
    }


def test_agent_config_requires_valid_unrevoked_credential(env: Environment) -> None:
    agent = env.enroll()

    assert env.agent_config("agc_invalid").status_code == 401
    assert env.agent_client.get("/agent/config").status_code == 401
    with sqlite3.connect(env.auth.database_path) as connection:
        connection.execute(
            "UPDATE agent_credentials SET revoked_at = ? WHERE agent_id = ?",
            (NOW.isoformat(), agent["agent_id"]),
        )
    assert env.agent_config(agent["credential"]).status_code == 401
    assert env.report(agent["credential"]).status_code == 401
    assert env.auth.get_agent(agent["agent_id"])["config_protocol"] is None


def test_correct_ack_clears_pending_and_sets_effective_mode(env: Environment) -> None:
    agent = env.enroll()
    env.agent_config(agent["credential"])
    admin, headers = env.session("admin")
    env.set_mode(admin, headers, agent["agent_id"], "automatic", 0)

    response = env.report(
        agent["credential"],
        applied_revision=1,
        effective_response_mode="automatic",
        blocking_enabled=True,
    )

    assert response.status_code == 200
    assert response.json() == {"accepted": True, "stale": False}
    stored = admin.get(f"/agents/{agent['agent_id']}").json()
    assert stored["applied_config_revision"] == 1
    assert stored["effective_response_mode"] == "automatic"
    assert stored["config_source"] == "central"
    assert stored["blocking_enabled"] is True
    assert stored["config_pending"] is False
    assert stored["config_reported_at"] is not None


def test_stale_ack_is_ignored(env: Environment) -> None:
    agent = env.enroll()
    env.agent_config(agent["credential"])
    admin, headers = env.session("admin")
    env.set_mode(admin, headers, agent["agent_id"], "assisted", 0)
    env.set_mode(admin, headers, agent["agent_id"], "automatic", 1)
    env.report(
        agent["credential"],
        applied_revision=2,
        effective_response_mode="automatic",
    )

    response = env.report(
        agent["credential"],
        applied_revision=1,
        effective_response_mode="assisted",
    )

    assert response.status_code == 200
    assert response.json() == {"accepted": False, "stale": True}
    stored = env.auth.get_agent(agent["agent_id"])
    assert stored["applied_config_revision"] == 2
    assert stored["effective_response_mode"] == "automatic"


def test_future_ack_is_a_conflict(env: Environment) -> None:
    agent = env.enroll()
    env.agent_config(agent["credential"])

    response = env.report(
        agent["credential"],
        applied_revision=5,
        effective_response_mode="automatic",
    )

    assert response.status_code == 409
    assert env.auth.get_agent(agent["agent_id"])["effective_response_mode"] is None


def test_ack_with_mode_not_matching_revision_is_a_conflict(env: Environment) -> None:
    agent = env.enroll()
    env.agent_config(agent["credential"])
    admin, headers = env.session("admin")
    env.set_mode(admin, headers, agent["agent_id"], "assisted", 0)

    response = env.report(
        agent["credential"],
        applied_revision=1,
        effective_response_mode="automatic",
    )

    assert response.status_code == 409
    assert env.auth.get_agent(agent["agent_id"])["applied_config_revision"] == 0


def _status(env: Environment, agent_id: str) -> tuple:
    stored = env.auth.get_agent(agent_id)
    return (
        stored["config_status"],
        stored["config_status_revision"],
        stored["config_status_reason"],
        stored["config_pending"],
    )


def _prepare_pending(env: Environment, mode: str = "automatic"):
    agent = env.enroll()
    env.agent_config(agent["credential"])
    env.report(agent["credential"], effective_response_mode="audit_only")
    admin, headers = env.session("admin")
    response = env.set_mode(admin, headers, agent["agent_id"], mode, 0)
    assert response.status_code == 200
    return agent, admin, headers


def test_config_status_is_null_until_a_central_revision_exists(
    env: Environment,
) -> None:
    agent = env.enroll()
    env.agent_config(agent["credential"])

    env.report(agent["credential"], effective_response_mode="assisted")

    assert _status(env, agent["agent_id"]) == (None, None, None, False)


def test_new_revision_is_pending(env: Environment) -> None:
    agent, admin, _ = _prepare_pending(env)

    body = admin.get(f"/agents/{agent['agent_id']}").json()

    assert body["config_status"] == "pending"
    assert body["config_status_revision"] == 1
    assert body["config_status_reason"] is None
    assert body["config_pending"] is True
    assert body["desired_response_mode"] == "automatic"
    assert body["effective_response_mode"] == "audit_only"


def test_applied_ack_moves_pending_to_applied(env: Environment) -> None:
    agent, _, _ = _prepare_pending(env)

    env.report(
        agent["credential"], applied_revision=1, effective_response_mode="automatic"
    )

    assert _status(env, agent["agent_id"]) == ("applied", 1, None, False)
    stored = env.auth.get_agent(agent["agent_id"])
    assert stored["applied_config_revision"] == 1
    assert stored["effective_response_mode"] == "automatic"


def test_rejected_ack_moves_pending_to_rejected_without_touching_applied_state(
    env: Environment,
) -> None:
    agent, _, _ = _prepare_pending(env)
    before = env.auth.get_agent(agent["agent_id"])

    response = env.report(
        agent["credential"],
        applied_revision=1,
        effective_response_mode="automatic",
        config_source="local",
        blocking_enabled=True,
        status="rejected",
        reason="Gestión del modo configurada localmente",
    )

    assert response.status_code == 200
    assert response.json() == {"accepted": True, "stale": False}
    stored = env.auth.get_agent(agent["agent_id"])
    assert _status(env, agent["agent_id"]) == (
        "rejected",
        1,
        "Gestión del modo configurada localmente",
        False,
    )
    # El rechazo no avanza la revisión aplicada ni cambia el modo efectivo.
    assert stored["applied_config_revision"] == before["applied_config_revision"] == 0
    assert stored["effective_response_mode"] == "audit_only"
    assert stored["config_source"] == before["config_source"]
    assert stored["blocking_enabled"] == before["blocking_enabled"]
    assert stored["config_revision"] == 1


def test_rejected_reason_is_sanitized(env: Environment) -> None:
    agent, _, _ = _prepare_pending(env)

    env.report(
        agent["credential"],
        applied_revision=1,
        status="rejected",
        reason="   Gestión   del modo    configurada localmente  ",
    )

    assert _status(env, agent["agent_id"])[2] == (
        "Gestión del modo configurada localmente"
    )


def test_repository_strips_control_characters_and_limits_reason(
    env: Environment,
) -> None:
    agent, _, _ = _prepare_pending(env)

    env.auth.report_agent_config_state(
        credential=agent["credential"],
        applied_revision=1,
        effective_response_mode="audit_only",
        config_source="central",
        blocking_enabled=False,
        status="rejected",
        reason="Traceback\n\x1b[31m" + "x" * 500,
    )

    reason = _status(env, agent["agent_id"])[2]
    assert "\n" not in reason and "\x1b" not in reason
    assert len(reason) <= 160
    assert reason.startswith("Traceback [31m")


def test_rejected_without_reason_uses_generic_message(env: Environment) -> None:
    agent, _, _ = _prepare_pending(env)

    env.report(agent["credential"], applied_revision=1, status="rejected")

    assert _status(env, agent["agent_id"])[2] == "El agente rechazó la configuración."


def test_reason_longer_than_limit_is_rejected_by_api(env: Environment) -> None:
    agent, _, _ = _prepare_pending(env)

    response = env.report(
        agent["credential"],
        applied_revision=1,
        status="rejected",
        reason="x" * 161,
    )

    assert response.status_code == 422
    assert _status(env, agent["agent_id"])[0] == "pending"


def test_rejecting_revision_zero_is_a_conflict(env: Environment) -> None:
    agent = env.enroll()
    env.agent_config(agent["credential"])

    response = env.report(agent["credential"], applied_revision=0, status="rejected")

    assert response.status_code == 409
    assert _status(env, agent["agent_id"])[0] is None


def test_stale_rejected_report_does_not_overwrite_newer_pending(
    env: Environment,
) -> None:
    agent, admin, headers = _prepare_pending(env, "assisted")
    second = env.set_mode(admin, headers, agent["agent_id"], "automatic", 1)
    assert second.status_code == 200

    response = env.report(
        agent["credential"],
        applied_revision=1,
        status="rejected",
        reason="Gestión del modo configurada localmente",
    )

    assert response.status_code == 200
    assert response.json() == {"accepted": False, "stale": True}
    assert _status(env, agent["agent_id"]) == ("pending", 2, None, True)


def test_stale_applied_report_does_not_overwrite_newer_pending(
    env: Environment,
) -> None:
    agent, admin, headers = _prepare_pending(env, "assisted")
    env.set_mode(admin, headers, agent["agent_id"], "automatic", 1)

    response = env.report(
        agent["credential"], applied_revision=1, effective_response_mode="assisted"
    )

    assert response.json() == {"accepted": False, "stale": True}
    assert _status(env, agent["agent_id"]) == ("pending", 2, None, True)
    assert env.auth.get_agent(agent["agent_id"])["applied_config_revision"] == 0


def test_future_rejected_report_is_a_conflict(env: Environment) -> None:
    agent, _, _ = _prepare_pending(env)

    response = env.report(agent["credential"], applied_revision=2, status="rejected")

    assert response.status_code == 409
    assert _status(env, agent["agent_id"]) == ("pending", 1, None, True)


def test_new_revision_after_rejection_is_pending_again(env: Environment) -> None:
    agent, admin, headers = _prepare_pending(env)
    env.report(
        agent["credential"],
        applied_revision=1,
        status="rejected",
        reason="Gestión del modo configurada localmente",
    )

    env.set_mode(admin, headers, agent["agent_id"], "assisted", 1)

    assert _status(env, agent["agent_id"]) == ("pending", 2, None, True)


@pytest.mark.parametrize(
    "overrides",
    [
        {"agent_id": "agt_otro"},
        {"effective_response_mode": "yolo"},
        {"config_source": "remote"},
        {"status": "partial"},
        {"applied_revision": -1},
        {"applied_revision": True},
        {"reason": "linea\nnueva"},
        {"reason": "x" * 201},
    ],
)
def test_malformed_reports_are_rejected(env: Environment, overrides: dict) -> None:
    agent = env.enroll()
    env.agent_config(agent["credential"])

    response = env.report(agent["credential"], **overrides)

    assert response.status_code == 422
    assert env.auth.get_agent(agent["agent_id"])["config_reported_at"] is None


def test_agent_cannot_report_state_for_another_agent(env: Environment) -> None:
    first = env.enroll(hostname="srv-a")
    second = env.enroll(hostname="srv-b")
    env.agent_config(first["credential"])

    env.report(first["credential"], effective_response_mode="assisted")

    reported = env.auth.get_agent(first["agent_id"])
    assert reported["effective_response_mode"] == "assisted"
    assert env.auth.get_agent(second["agent_id"])["effective_response_mode"] is None


def test_history_never_contains_secrets(env: Environment) -> None:
    agent = env.enroll()
    env.agent_config(agent["credential"])
    admin, headers = env.session("admin")
    admin.patch(
        f"/agents/{agent['agent_id']}", headers=headers, json={"display_name": "Web"}
    )
    env.set_mode(admin, headers, agent["agent_id"], "automatic", 0)

    with sqlite3.connect(env.auth.database_path) as connection:
        rows = connection.execute("SELECT * FROM agent_config_changes").fetchall()
    flattened = " ".join(str(value) for row in rows for value in row)

    assert len(rows) == 2
    assert agent["credential"] not in flattened
    assert headers["X-CSRF-Token"] not in flattened
    assert "password" not in flattened.casefold()


# ------------------------------------------------------------- /status


def test_status_response_mode_reflects_reported_effective_mode(
    env: Environment,
) -> None:
    agent = env.enroll()
    viewer, _ = env.session("viewer-a")
    params = {"agent_id": agent["agent_id"]}

    assert viewer.get("/status", params=params).json()["response_mode"] is None
    env.agent_config(agent["credential"])
    env.report(agent["credential"], effective_response_mode="assisted")

    body = viewer.get("/status", params=params).json()
    assert body["response_mode"] == "assisted"
    assert body["automatic_blocking_enabled"] is None
    assert body["live_response_blocks"] is None


# ------------------------------------------------------------- dashboard


def test_dashboard_exposes_mode_controls_only_through_authorized_api() -> None:
    html = (DASHBOARD_DIR / "index.html").read_text(encoding="utf-8")
    javascript = (DASHBOARD_DIR / "dashboard.js").read_text(encoding="utf-8")

    assert 'id="server-mode-options"' in html
    assert 'data-mode="audit_only"' in html
    assert 'data-mode="assisted"' in html
    assert 'data-mode="automatic"' in html
    servers_view = html[html.index('data-view="servers"') :]
    assert "Bloqueos activos" not in servers_view
    assert 'authContext?.role === "superadmin"' in javascript
    assert '"X-CSRF-Token": authContext.csrf_token' in javascript
    assert "/response-mode" in javascript
    assert "expected_revision: agent.config_revision" in javascript
    assert "limitada por configuración local" in javascript
    # Estados traducidos para el usuario.
    assert 'pending: "Aplicando…"' in javascript
    assert 'applied: "Sincronizado"' in javascript
    assert 'rejected: "No aplicado"' in javascript
    assert "Este servidor utiliza administración local." in javascript
    assert "Este servidor administra su política de respuesta localmente." in html
    # El nombre de la variable de entorno no se muestra al usuario.
    assert "AUDITORIA_RESPONSE_MODE_SOURCE" not in javascript
    assert "AUDITORIA_RESPONSE_MODE_SOURCE" not in html
    # Confirmación explícita antes de solicitar automático.
    confirmation = (
        'serverModeSelection === "automatic" && !(await confirmAutomaticMode(agent))'
    )
    assert confirmation in javascript
    # El rechazo por gestión local no usa el estilo rojo de error.
    assert 'statusBadge("RECHAZADO"' not in javascript
    assert "innerHTML" not in javascript
