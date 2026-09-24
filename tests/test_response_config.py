from __future__ import annotations

import pytest

from app.core.config import load_agent_settings

RESPONSE_ENV_VARS = [
    "AUDITORIA_RESPONSE_MODE",
    "AUDITORIA_TRUSTED_ADMIN_IPS",
    "AUDITORIA_ALLOW_TEMPORARY_IP_BLOCK",
    "AUDITORIA_TEMPORARY_BLOCK_SECONDS",
]


def clear_response_env(monkeypatch) -> None:
    for name in RESPONSE_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def test_response_settings_are_safe_by_default(
    monkeypatch,
) -> None:
    clear_response_env(monkeypatch)

    settings = load_agent_settings()

    assert settings.response_mode == "audit_only"
    assert settings.trusted_admin_ips == ()
    assert settings.allow_temporary_ip_block is False
    assert settings.temporary_block_seconds == 900


def test_response_settings_are_loaded_from_environment(
    monkeypatch,
) -> None:
    clear_response_env(monkeypatch)

    monkeypatch.setenv(
        "AUDITORIA_RESPONSE_MODE",
        "automatic",
    )
    monkeypatch.setenv(
        "AUDITORIA_TRUSTED_ADMIN_IPS",
        "192.168.1.25, 2001:db8::25",
    )
    monkeypatch.setenv(
        "AUDITORIA_ALLOW_TEMPORARY_IP_BLOCK",
        "true",
    )
    monkeypatch.setenv(
        "AUDITORIA_TEMPORARY_BLOCK_SECONDS",
        "1200",
    )

    settings = load_agent_settings()

    assert settings.response_mode == "automatic"
    assert settings.trusted_admin_ips == (
        "192.168.1.25",
        "2001:db8::25",
    )
    assert settings.allow_temporary_ip_block is True
    assert settings.temporary_block_seconds == 1200


def test_invalid_response_configuration_falls_back_safely(
    monkeypatch,
) -> None:
    clear_response_env(monkeypatch)

    monkeypatch.setenv(
        "AUDITORIA_RESPONSE_MODE",
        "dangerous-mode",
    )
    monkeypatch.setenv(
        "AUDITORIA_ALLOW_TEMPORARY_IP_BLOCK",
        "maybe",
    )

    settings = load_agent_settings()

    assert settings.response_mode == "audit_only"
    assert settings.allow_temporary_ip_block is False


@pytest.mark.parametrize(
    "value",
    [
        "30",
        "90000",
        "not-a-number",
    ],
)
def test_invalid_temporary_block_duration_uses_default(
    monkeypatch,
    value: str,
) -> None:
    clear_response_env(monkeypatch)

    monkeypatch.setenv(
        "AUDITORIA_TEMPORARY_BLOCK_SECONDS",
        value,
    )

    settings = load_agent_settings()

    assert settings.temporary_block_seconds == 900
