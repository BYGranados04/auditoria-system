"""Migración auth.db v3 -> v4 (control plane v1.1)."""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

from app.auth.repository import AuthRepository
from app.central.repository import CentralEventRepository
from app.storage.event_repository import EventRepository
from tests.api_test_helpers import TEST_SCRYPT

TIMESTAMP = "2026-10-01T00:00:00+00:00"
NEW_AGENT_COLUMNS = {
    "display_name",
    "agent_version",
    "config_protocol",
    "desired_response_mode",
    "config_revision",
    "config_updated_at",
    "applied_config_revision",
    "effective_response_mode",
    "config_source",
    "blocking_enabled",
    "config_reported_at",
    "config_status",
    "config_status_revision",
    "config_status_reason",
}


def _digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def build_v3_database(path: Path) -> None:
    """Base de datos idéntica a la que deja Nexora v1.0.0 (esquema 3)."""

    with sqlite3.connect(path) as connection:
        AuthRepository._migrate_to_v1(connection)
        AuthRepository._migrate_to_v2(connection)
        AuthRepository._migrate_to_v3(connection)
        connection.execute("PRAGMA user_version = 3")
        connection.execute(
            """
            INSERT INTO users (
                username, password_hash, password_salt,
                scrypt_n, scrypt_r, scrypt_p, scrypt_dklen,
                role, active, created_at, updated_at
            ) VALUES ('legacy-admin', ?, ?, 1024, 8, 1, 32, 'superadmin', 1, ?, ?)
            """,
            (b"legacy-hash", b"legacy-salt", TIMESTAMP, TIMESTAMP),
        )
        connection.execute(
            """
            INSERT INTO agents (
                agent_id, owner_user_id, hostname, status,
                registered_at, last_seen_at, created_at, updated_at
            ) VALUES ('agt_legacy', 1, 'srv-web-01', 'offline', ?, ?, ?, ?)
            """,
            (TIMESTAMP, TIMESTAMP, TIMESTAMP, TIMESTAMP),
        )
        connection.execute(
            """
            INSERT INTO agent_credentials (
                agent_id, credential_digest, created_at, revoked_at
            ) VALUES ('agt_legacy', ?, ?, NULL)
            """,
            (_digest("agc_legacy_credential"), TIMESTAMP),
        )
        connection.execute(
            """
            INSERT INTO agent_registration_tokens (
                owner_user_id, token_digest, created_at, expires_at, used_at
            ) VALUES (1, ?, ?, ?, NULL)
            """,
            (_digest("reg_legacy_token"), TIMESTAMP, "2099-01-01T00:00:00+00:00"),
        )


def table_columns(path: Path, table: str) -> set[str]:
    with sqlite3.connect(path) as connection:
        return {
            str(row[1])
            for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
        }


def test_v3_migrates_to_v4_preserving_agents_credentials_and_tokens(
    tmp_path: Path,
) -> None:
    database = tmp_path / "auth.db"
    build_v3_database(database)

    repository = AuthRepository(database, scrypt_parameters=TEST_SCRYPT)
    repository.initialize()

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 4
        agent = connection.execute(
            """
            SELECT agent_id, owner_user_id, hostname, registered_at, last_seen_at,
                   display_name, agent_version, config_protocol,
                   desired_response_mode, config_revision, applied_config_revision,
                   effective_response_mode, config_source, blocking_enabled,
                   config_status, config_status_revision, config_status_reason
            FROM agents
            """
        ).fetchone()
        credentials = connection.execute(
            "SELECT agent_id, credential_digest, revoked_at FROM agent_credentials"
        ).fetchall()
        tokens = connection.execute(
            "SELECT token_digest, used_at FROM agent_registration_tokens"
        ).fetchall()

    assert agent == (
        "agt_legacy",
        1,
        "srv-web-01",
        TIMESTAMP,
        TIMESTAMP,
        None,
        None,
        None,
        None,
        0,
        0,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    assert credentials == [("agt_legacy", _digest("agc_legacy_credential"), None)]
    assert tokens == [(_digest("reg_legacy_token"), None)]
    assert NEW_AGENT_COLUMNS <= table_columns(database, "agents")
    assert {
        "id",
        "agent_id",
        "revision",
        "field",
        "old_value",
        "new_value",
        "changed_by_user_id",
        "changed_by_username",
        "changed_at",
    } == table_columns(database, "agent_config_changes")


def test_existing_agent_keeps_identity_after_migration(tmp_path: Path) -> None:
    database = tmp_path / "auth.db"
    build_v3_database(database)
    repository = AuthRepository(database, scrypt_parameters=TEST_SCRYPT)

    authenticated = repository.authenticate_agent_credential("agc_legacy_credential")
    public = repository.get_agent("agt_legacy")

    assert authenticated is not None
    assert authenticated["agent_id"] == "agt_legacy"
    assert public is not None
    assert public["hostname"] == "srv-web-01"
    assert public["display_name"] is None
    assert public["config_protocol"] is None
    assert public["config_pending"] is False


def test_v4_initialize_is_idempotent(tmp_path: Path) -> None:
    database = tmp_path / "auth.db"
    build_v3_database(database)

    AuthRepository(database, scrypt_parameters=TEST_SCRYPT).initialize()
    AuthRepository(database, scrypt_parameters=TEST_SCRYPT).initialize()

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 4
        assert connection.execute("SELECT COUNT(*) FROM agents").fetchone()[0] == 1


def test_interrupted_v4_migration_can_be_retried(tmp_path: Path) -> None:
    """Columnas ya agregadas pero user_version todavía en 3."""

    database = tmp_path / "auth.db"
    build_v3_database(database)
    with sqlite3.connect(database) as connection:
        connection.execute("ALTER TABLE agents ADD COLUMN display_name TEXT")
        connection.execute("ALTER TABLE agents ADD COLUMN agent_version TEXT")

    AuthRepository(database, scrypt_parameters=TEST_SCRYPT).initialize()

    assert NEW_AGENT_COLUMNS <= table_columns(database, "agents")
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 4


@pytest.mark.parametrize("future", [5, 99])
def test_future_auth_schema_is_rejected(tmp_path: Path, future: int) -> None:
    database = tmp_path / "auth.db"
    with sqlite3.connect(database) as connection:
        connection.execute(f"PRAGMA user_version = {future}")

    with pytest.raises(RuntimeError, match="esquema más nuevo"):
        AuthRepository(database, scrypt_parameters=TEST_SCRYPT).initialize()


def test_new_columns_enforce_allowed_values(tmp_path: Path) -> None:
    database = tmp_path / "auth.db"
    build_v3_database(database)
    AuthRepository(database, scrypt_parameters=TEST_SCRYPT).initialize()

    for statement in (
        "UPDATE agents SET desired_response_mode = 'disabled'",
        "UPDATE agents SET effective_response_mode = 'yolo'",
        "UPDATE agents SET config_source = 'remote'",
        "UPDATE agents SET blocking_enabled = 2",
        "UPDATE agents SET config_status = 'unknown'",
        """
        INSERT INTO agent_config_changes (
            agent_id, revision, field, changed_by_username, changed_at
        ) VALUES ('agt_legacy', 1, 'credential', 'admin', 'now')
        """,
    ):
        with sqlite3.connect(database) as connection:
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(statement)


def test_auth_migration_does_not_touch_central_or_local_databases(
    tmp_path: Path,
) -> None:
    central = CentralEventRepository(tmp_path / "central.db")
    central.initialize()
    local = EventRepository(tmp_path / "auditoria.db")
    local.initialize()
    before = {
        name: (tmp_path / name).read_bytes() for name in ("central.db", "auditoria.db")
    }

    database = tmp_path / "auth.db"
    build_v3_database(database)
    AuthRepository(database, scrypt_parameters=TEST_SCRYPT).initialize()

    assert CentralEventRepository.SCHEMA_VERSION == 3
    for name, content in before.items():
        assert (tmp_path / name).read_bytes() == content
