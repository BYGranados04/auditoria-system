from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_api_service_prepares_central_state_directory() -> None:
    unit = (
        ROOT / "deploy" / "systemd" / "auditoria-api.service"
    ).read_text(encoding="utf-8")

    assert "StateDirectory=auditoria-system-auth" in unit
    assert "StateDirectory=auditoria-system-central" in unit
    assert "StateDirectoryMode=0700" in unit


def test_example_config_matches_central_database_default() -> None:
    config = (
        ROOT / "deploy" / "agent.env.example"
    ).read_text(encoding="utf-8")

    assert (
        "AUDITORIA_CENTRAL_DB="
        "/var/lib/auditoria-system-central/central.db"
        in config
    )
