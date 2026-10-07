from pathlib import Path

import pytest

from app.core.config import load_agent_settings


def test_agent_settings_defaults(monkeypatch) -> None:
    monkeypatch.delenv("AUDITORIA_INTERVAL", raising=False)
    monkeypatch.delenv("AUDITORIA_STATE_DIR", raising=False)
    monkeypatch.delenv("AUDITORIA_LOG_DIR", raising=False)
    monkeypatch.delenv("AUDITORIA_AGENT_IDENTITY_FILE", raising=False)
    monkeypatch.delenv("AUDITORIA_SYNC_INTERVAL", raising=False)
    monkeypatch.delenv("AUDITORIA_SYNC_TIMEOUT_SECONDS", raising=False)
    monkeypatch.delenv("AUDITORIA_SYNC_BATCH_SIZE", raising=False)
    monkeypatch.delenv("AUDITORIA_SYNC_RETRY_BASE_SECONDS", raising=False)
    monkeypatch.delenv("AUDITORIA_SYNC_RETRY_MAX_SECONDS", raising=False)
    monkeypatch.delenv("AUDITORIA_HEARTBEAT_INTERVAL", raising=False)
    monkeypatch.delenv("AUDITORIA_AGENT_OFFLINE_AFTER_SECONDS", raising=False)

    settings = load_agent_settings()

    assert settings.interval == 10
    assert settings.state_dir == Path("/var/lib/auditoria-system")
    assert settings.log_dir == Path("/var/log/auditoria-system")
    assert settings.identity_file == Path(
        "/etc/auditoria-system/agent-identity.json"
    )
    assert settings.sync_interval == 10
    assert settings.sync_timeout_seconds == 5
    assert settings.sync_batch_size == 50
    assert settings.sync_retry_base_seconds == 5
    assert settings.sync_retry_max_seconds == 300
    assert settings.heartbeat_interval == 30
    assert settings.agent_offline_after_seconds == 120


def test_agent_settings_from_environment(monkeypatch) -> None:
    monkeypatch.setenv("AUDITORIA_INTERVAL", "5")
    monkeypatch.setenv(
        "AUDITORIA_STATE_DIR",
        "/tmp/auditoria-state",
    )
    monkeypatch.setenv(
        "AUDITORIA_LOG_DIR",
        "/tmp/auditoria-log",
    )
    monkeypatch.setenv("AUDITORIA_AGENT_IDENTITY_FILE", "/tmp/identity.json")
    monkeypatch.setenv("AUDITORIA_SYNC_INTERVAL", "20")
    monkeypatch.setenv("AUDITORIA_SYNC_TIMEOUT_SECONDS", "8")
    monkeypatch.setenv("AUDITORIA_SYNC_BATCH_SIZE", "25")
    monkeypatch.setenv("AUDITORIA_SYNC_RETRY_BASE_SECONDS", "7")
    monkeypatch.setenv("AUDITORIA_SYNC_RETRY_MAX_SECONDS", "120")
    monkeypatch.setenv("AUDITORIA_HEARTBEAT_INTERVAL", "45")
    monkeypatch.setenv("AUDITORIA_AGENT_OFFLINE_AFTER_SECONDS", "180")

    settings = load_agent_settings()

    assert settings.interval == 5
    assert settings.state_dir == Path("/tmp/auditoria-state")
    assert settings.log_dir == Path("/tmp/auditoria-log")
    assert settings.identity_file == Path("/tmp/identity.json")
    assert settings.sync_interval == 20
    assert settings.sync_timeout_seconds == 8
    assert settings.sync_batch_size == 25
    assert settings.sync_retry_base_seconds == 7
    assert settings.sync_retry_max_seconds == 120
    assert settings.heartbeat_interval == 45
    assert settings.agent_offline_after_seconds == 180


def test_invalid_interval_uses_default(monkeypatch) -> None:
    monkeypatch.setenv("AUDITORIA_INTERVAL", "invalid")

    settings = load_agent_settings()

    assert settings.interval == 10


def test_non_positive_interval_uses_default(monkeypatch) -> None:
    monkeypatch.setenv("AUDITORIA_INTERVAL", "0")

    settings = load_agent_settings()

    assert settings.interval == 10


def test_invalid_sync_settings_use_safe_defaults(monkeypatch) -> None:
    monkeypatch.setenv("AUDITORIA_SYNC_INTERVAL", "0")
    monkeypatch.setenv("AUDITORIA_SYNC_TIMEOUT_SECONDS", "61")
    monkeypatch.setenv("AUDITORIA_SYNC_BATCH_SIZE", "101")
    monkeypatch.setenv("AUDITORIA_SYNC_RETRY_BASE_SECONDS", "invalid")
    monkeypatch.setenv("AUDITORIA_SYNC_RETRY_MAX_SECONDS", "90000")

    loaded = load_agent_settings()

    assert loaded.sync_interval == 10
    assert loaded.sync_timeout_seconds == 5
    assert loaded.sync_batch_size == 50
    assert loaded.sync_retry_base_seconds == 5
    assert loaded.sync_retry_max_seconds == 300


@pytest.mark.parametrize(
    ("interval", "offline_after"),
    [("invalid", "120"), ("4", "120"), ("30", "30"), ("30", "invalid")],
)
def test_invalid_heartbeat_settings_fail_fast(
    monkeypatch,
    interval: str,
    offline_after: str,
) -> None:
    monkeypatch.setenv("AUDITORIA_HEARTBEAT_INTERVAL", interval)
    monkeypatch.setenv("AUDITORIA_AGENT_OFFLINE_AFTER_SECONDS", offline_after)

    with pytest.raises(ValueError):
        load_agent_settings()


def test_database_file_uses_state_directory(
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        "AUDITORIA_STATE_DIR",
        "/tmp/auditoria-state",
    )

    settings = load_agent_settings()

    assert settings.database_file == Path("/tmp/auditoria-state/auditoria.db")
