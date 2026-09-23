from pathlib import Path

from app.core.config import load_agent_settings


def test_agent_settings_defaults(monkeypatch) -> None:
    monkeypatch.delenv("AUDITORIA_INTERVAL", raising=False)
    monkeypatch.delenv("AUDITORIA_STATE_DIR", raising=False)
    monkeypatch.delenv("AUDITORIA_LOG_DIR", raising=False)

    settings = load_agent_settings()

    assert settings.interval == 10
    assert settings.state_dir == Path("/var/lib/auditoria-system")
    assert settings.log_dir == Path("/var/log/auditoria-system")


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

    settings = load_agent_settings()

    assert settings.interval == 5
    assert settings.state_dir == Path("/tmp/auditoria-state")
    assert settings.log_dir == Path("/tmp/auditoria-log")


def test_invalid_interval_uses_default(monkeypatch) -> None:
    monkeypatch.setenv("AUDITORIA_INTERVAL", "invalid")

    settings = load_agent_settings()

    assert settings.interval == 10


def test_non_positive_interval_uses_default(monkeypatch) -> None:
    monkeypatch.setenv("AUDITORIA_INTERVAL", "0")

    settings = load_agent_settings()

    assert settings.interval == 10


def test_database_file_uses_state_directory(
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        "AUDITORIA_STATE_DIR",
        "/tmp/auditoria-state",
    )

    settings = load_agent_settings()

    assert settings.database_file == Path("/tmp/auditoria-state/auditoria.db")
