from __future__ import annotations

from pathlib import Path

import pytest

from app.agent.continuous_agent import ContinuousAgent
from app.core.config import AgentSettings, load_agent_settings

NEW_ENV_VARS = (
    "AUDITORIA_RESPONSE_BLOCK_SCOPE",
    "AUDITORIA_ALLOW_TEMPORARY_IP_PORT_BLOCK",
    "AUDITORIA_SSH_PORT",
    "AUDITORIA_RESPONSE_ESCALATION_ENABLED",
    "AUDITORIA_RESPONSE_ESCALATION_SECONDS",
    "AUDITORIA_RESPONSE_ESCALATION_WINDOW_SECONDS",
    "AUDITORIA_INCIDENTS_ENABLED",
    "AUDITORIA_INCIDENT_GROUPING_SECONDS",
    "AUDITORIA_EVIDENCE_ENABLED",
    "AUDITORIA_EVIDENCE_RETENTION_DAYS",
    "AUDITORIA_EVIDENCE_MAX_BYTES",
    "AUDITORIA_EVIDENCE_MAX_TOTAL_BYTES",
    "AUDITORIA_EVIDENCE_COMMAND_TIMEOUT_SECONDS",
    "AUDITORIA_APPROVAL_TTL_SECONDS",
)


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for name in (
        *NEW_ENV_VARS,
        "AUDITORIA_RESPONSE_MODE",
        "AUDITORIA_ALLOW_TEMPORARY_IP_BLOCK",
        "AUDITORIA_STATE_DIR",
    ):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_existing_installations_keep_safe_defaults(clean_env) -> None:
    settings = load_agent_settings()

    assert settings.response_block_scope == "ip"
    assert settings.allow_temporary_ip_port_block is False
    assert settings.ssh_port == 22
    assert settings.response_escalation_enabled is False
    assert settings.response_escalation_seconds == (120, 600, 3600)
    assert settings.response_escalation_window_seconds == 86400
    assert settings.incidents_enabled is True
    assert settings.incident_grouping_seconds == 3600
    assert settings.evidence_enabled is False
    assert settings.evidence_retention_days == 7
    assert settings.evidence_max_bytes == 262_144
    assert settings.evidence_max_total_bytes == 52_428_800
    assert settings.evidence_command_timeout_seconds == 5
    assert settings.evidence_dir == Path("/var/lib/auditoria-system/evidence")


def test_new_settings_are_loaded_from_environment(clean_env) -> None:
    values = {
        "AUDITORIA_RESPONSE_BLOCK_SCOPE": "IP_PORT",
        "AUDITORIA_ALLOW_TEMPORARY_IP_PORT_BLOCK": "true",
        "AUDITORIA_SSH_PORT": "2222",
        "AUDITORIA_RESPONSE_ESCALATION_ENABLED": "yes",
        "AUDITORIA_RESPONSE_ESCALATION_SECONDS": "60, 300, 1800, 7200",
        "AUDITORIA_RESPONSE_ESCALATION_WINDOW_SECONDS": "43200",
        "AUDITORIA_INCIDENTS_ENABLED": "false",
        "AUDITORIA_INCIDENT_GROUPING_SECONDS": "900",
        "AUDITORIA_EVIDENCE_ENABLED": "true",
        "AUDITORIA_EVIDENCE_RETENTION_DAYS": "3",
        "AUDITORIA_EVIDENCE_MAX_BYTES": "65536",
        "AUDITORIA_EVIDENCE_MAX_TOTAL_BYTES": "10485760",
        "AUDITORIA_EVIDENCE_COMMAND_TIMEOUT_SECONDS": "2",
    }
    for name, value in values.items():
        clean_env.setenv(name, value)

    settings = load_agent_settings()

    assert settings.response_block_scope == "ip_port"
    assert settings.allow_temporary_ip_port_block is True
    assert settings.ssh_port == 2222
    assert settings.response_escalation_enabled is True
    assert settings.response_escalation_seconds == (60, 300, 1800, 7200)
    assert settings.response_escalation_window_seconds == 43200
    assert settings.incidents_enabled is False
    assert settings.incident_grouping_seconds == 900
    assert settings.evidence_enabled is True
    assert settings.evidence_retention_days == 3
    assert settings.evidence_max_bytes == 65536
    assert settings.evidence_max_total_bytes == 10_485_760
    assert settings.evidence_command_timeout_seconds == 2


@pytest.mark.parametrize(
    ("name", "value", "attribute", "expected"),
    [
        ("AUDITORIA_RESPONSE_BLOCK_SCOPE", "everything", "response_block_scope", "ip"),
        ("AUDITORIA_SSH_PORT", "70000", "ssh_port", 22),
        ("AUDITORIA_EVIDENCE_MAX_BYTES", "999999999", "evidence_max_bytes", 262_144),
        ("AUDITORIA_EVIDENCE_RETENTION_DAYS", "0", "evidence_retention_days", 7),
        (
            "AUDITORIA_RESPONSE_ESCALATION_WINDOW_SECONDS",
            "10",
            "response_escalation_window_seconds",
            86400,
        ),
        ("AUDITORIA_EVIDENCE_ENABLED", "quizas", "evidence_enabled", False),
    ],
)
def test_invalid_values_fall_back_to_safe_defaults(
    clean_env,
    name: str,
    value: str,
    attribute: str,
    expected: object,
) -> None:
    clean_env.setenv(name, value)

    assert getattr(load_agent_settings(), attribute) == expected


def test_real_execution_is_enabled_only_in_automatic_with_authorization(
    tmp_path: Path,
) -> None:
    def agent(**overrides: object) -> ContinuousAgent:
        return ContinuousAgent(
            interval=1,
            settings=AgentSettings(
                interval=1,
                state_dir=tmp_path / "state",
                log_dir=tmp_path / "logs",
                identity_file=tmp_path / "agent-identity.json",
                **overrides,  # type: ignore[arg-type]
            ),
        )

    assert agent(response_mode="audit_only").response_executor.dry_run is True
    assert (
        agent(
            response_mode="audit_only",
            allow_temporary_ip_port_block=True,
        ).response_executor.dry_run
        is True
    )
    assert (
        agent(
            response_mode="assisted",
            allow_temporary_ip_port_block=True,
        ).response_executor.dry_run
        is True
    )
    assert (
        agent(
            response_mode="automatic",
            allow_temporary_ip_port_block=True,
        ).response_executor.dry_run
        is False
    )
    assert agent(response_mode="automatic").response_executor.dry_run is True


def test_approval_ttl_is_bounded(clean_env) -> None:
    assert load_agent_settings().approval_ttl_seconds == 3600
    clean_env.setenv("AUDITORIA_APPROVAL_TTL_SECONDS", "900")
    assert load_agent_settings().approval_ttl_seconds == 900
    clean_env.setenv("AUDITORIA_APPROVAL_TTL_SECONDS", "10")
    assert load_agent_settings().approval_ttl_seconds == 3600
