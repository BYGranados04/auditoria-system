import hashlib
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from app.auth.repository import AuthConflictError, AuthRepository, AuthValidationError
from tests.api_test_helpers import TEST_PASSWORD, TEST_SCRYPT


def test_password_with_seven_characters_is_rejected(tmp_path) -> None:
    repository = AuthRepository(tmp_path / "auth.db", scrypt_parameters=TEST_SCRYPT)

    with pytest.raises(AuthValidationError, match="al menos 8 caracteres"):
        repository.create_user(
            username="short-password",
            password="1234567",
            role="viewer",
        )


def test_password_with_eight_characters_is_accepted(tmp_path) -> None:
    repository = AuthRepository(tmp_path / "auth.db", scrypt_parameters=TEST_SCRYPT)

    user = repository.create_user(
        username="minimum-password",
        password="12345678",
        role="viewer",
    )

    assert repository.authenticate("minimum-password", "12345678") == user


def test_auth_database_is_separate_and_password_is_not_plaintext(tmp_path) -> None:
    audit_database = tmp_path / "state" / "auditoria.db"
    audit_database.parent.mkdir(parents=True)
    audit_database.write_bytes(b"audit-evidence")
    auth_database = tmp_path / "auth" / "auth.db"
    repository = AuthRepository(auth_database, scrypt_parameters=TEST_SCRYPT)

    repository.create_user(
        username="security-admin",
        password=TEST_PASSWORD,
        role="superadmin",
    )

    assert auth_database != audit_database
    assert audit_database.read_bytes() == b"audit-evidence"
    assert TEST_PASSWORD.encode() not in auth_database.read_bytes()

    with sqlite3.connect(auth_database) as connection:
        stored = connection.execute(
            "SELECT password_hash, password_salt, scrypt_n, scrypt_r, scrypt_p "
            "FROM users"
        ).fetchone()
    assert stored[0] != TEST_PASSWORD.encode()
    assert len(stored[1]) == 16
    assert stored[2:5] == (TEST_SCRYPT.n, TEST_SCRYPT.r, TEST_SCRYPT.p)


def test_session_database_stores_only_token_digests(tmp_path) -> None:
    repository = AuthRepository(tmp_path / "auth.db", scrypt_parameters=TEST_SCRYPT)
    user = repository.create_user(
        username="admin-user",
        password=TEST_PASSWORD,
        role="superadmin",
    )
    session = repository.create_session(int(user["id"]), session_seconds=28_800)

    with sqlite3.connect(repository.database_path) as connection:
        row = connection.execute(
            "SELECT token_digest, csrf_digest FROM sessions"
        ).fetchone()

    assert session.token.encode() not in repository.database_path.read_bytes()
    assert session.csrf_token.encode() not in repository.database_path.read_bytes()
    assert len(row[0]) == 32
    assert len(row[1]) == 32


def test_expired_session_is_rejected(tmp_path) -> None:
    repository = AuthRepository(tmp_path / "auth.db", scrypt_parameters=TEST_SCRYPT)
    user = repository.create_user(
        username="viewer-user",
        password=TEST_PASSWORD,
        role="viewer",
    )
    start = datetime(2026, 1, 1, tzinfo=UTC)
    session = repository.create_session(
        int(user["id"]),
        session_seconds=60,
        now=start,
    )

    assert repository.get_session(session.token, now=start) is not None
    assert (
        repository.get_session(
            session.token,
            now=start + timedelta(seconds=61),
        )
        is None
    )


def test_last_active_superadmin_cannot_be_disabled_or_downgraded(tmp_path) -> None:
    repository = AuthRepository(tmp_path / "auth.db", scrypt_parameters=TEST_SCRYPT)
    admin = repository.create_user(
        username="only-admin",
        password=TEST_PASSWORD,
        role="superadmin",
    )
    admin_id = int(admin["id"])

    with pytest.raises(AuthConflictError):
        repository.set_user_active(
            admin_id,
            active=False,
            actor_user_id=999,
        )
    with pytest.raises(AuthConflictError):
        repository.set_user_role(
            admin_id,
            role="viewer",
            actor_user_id=999,
        )


def test_migrates_v1_auth_database_without_losing_users_or_sessions(tmp_path) -> None:
    database = tmp_path / "auth.db"
    with sqlite3.connect(database) as connection:
        AuthRepository._migrate_to_v1(connection)
        connection.execute("PRAGMA user_version = 1")
        connection.execute(
            """
            INSERT INTO users (
                username, password_hash, password_salt,
                scrypt_n, scrypt_r, scrypt_p, scrypt_dklen,
                role, active, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (
                "legacy-admin",
                b"legacy-hash",
                b"legacy-salt",
                1024,
                8,
                1,
                32,
                "superadmin",
                "2026-09-26T00:00:00+00:00",
                "2026-09-26T00:00:00+00:00",
            ),
        )
        connection.execute(
            """
            INSERT INTO sessions (
                user_id, token_digest, csrf_digest, created_at, expires_at
            ) VALUES (1, ?, ?, ?, ?)
            """,
            (
                hashlib.sha256(b"legacy-token").digest(),
                hashlib.sha256(b"legacy-csrf").digest(),
                "2026-09-26T00:00:00+00:00",
                "2027-09-26T00:00:00+00:00",
            ),
        )

    repository = AuthRepository(database, scrypt_parameters=TEST_SCRYPT)
    repository.initialize()
    preserved_session = repository.get_session(
        "legacy-token",
        now=datetime(2026, 9, 26, tzinfo=UTC),
    )
    AuthRepository(database, scrypt_parameters=TEST_SCRYPT).initialize()

    assert preserved_session is not None
    assert preserved_session.username == "legacy-admin"
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 4
        assert connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1
        assert connection.execute(
            "SELECT password_hash FROM users WHERE username = 'legacy-admin'"
        ).fetchone()[0] == b"legacy-hash"
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE name = 'user_host_access'"
        ).fetchone() == ("user_host_access",)


def test_migrates_v2_legacy_host_access_without_using_it_for_ownership(
    tmp_path,
) -> None:
    database = tmp_path / "auth.db"
    timestamp = "2026-09-26T00:00:00+00:00"
    with sqlite3.connect(database) as connection:
        AuthRepository._migrate_to_v1(connection)
        AuthRepository._migrate_to_v2(connection)
        connection.execute("PRAGMA user_version = 2")
        connection.execute(
            """
            INSERT INTO users (
                username, password_hash, password_salt,
                scrypt_n, scrypt_r, scrypt_p, scrypt_dklen,
                role, active, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (
                "legacy-viewer",
                b"legacy-hash",
                b"legacy-salt",
                1024,
                8,
                1,
                32,
                "viewer",
                timestamp,
                timestamp,
            ),
        )
        connection.execute(
            """
            INSERT INTO user_host_access (user_id, hostname, created_at)
            VALUES (1, 'legacy-host', ?)
            """,
            (timestamp,),
        )

    repository = AuthRepository(database, scrypt_parameters=TEST_SCRYPT)
    repository.initialize()
    registration = repository.create_agent_registration_token(1)
    repository.enroll_agent(
        registration_token=registration.token,
        hostname="agent-host",
    )

    with sqlite3.connect(database) as connection:
        table_names = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        legacy_hostnames = connection.execute(
            "SELECT hostname FROM user_host_access WHERE user_id = 1"
        ).fetchall()
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 4

    assert legacy_hostnames == [("legacy-host",)]
    assert {
        "agents",
        "agent_registration_tokens",
        "agent_credentials",
    } <= table_names
    assert repository.get_owned_agent_hostnames(1) == ("agent-host",)


def test_valid_agent_credential_resolves_agent_and_owner(tmp_path) -> None:
    repository = AuthRepository(tmp_path / "auth.db", scrypt_parameters=TEST_SCRYPT)
    owner = repository.create_user(
        username="agent-owner",
        password=TEST_PASSWORD,
        role="viewer",
    )
    registration = repository.create_agent_registration_token(int(owner["id"]))
    enrolled = repository.enroll_agent(
        registration_token=registration.token,
        hostname="credential-host",
    )

    authenticated = repository.authenticate_agent_credential(
        enrolled.credential
    )

    assert authenticated is not None
    assert authenticated["agent_id"] == enrolled.agent["agent_id"]
    assert authenticated["owner_user_id"] == owner["id"]
    assert "credential" not in authenticated
    assert "credential_digest" not in authenticated


def test_invalid_and_revoked_agent_credentials_are_rejected(tmp_path) -> None:
    repository = AuthRepository(tmp_path / "auth.db", scrypt_parameters=TEST_SCRYPT)
    owner = repository.create_user(
        username="credential-owner",
        password=TEST_PASSWORD,
        role="viewer",
    )
    registration = repository.create_agent_registration_token(int(owner["id"]))
    enrolled = repository.enroll_agent(
        registration_token=registration.token,
        hostname="revoked-host",
    )

    assert repository.authenticate_agent_credential("agc_invalid") is None

    with sqlite3.connect(repository.database_path) as connection:
        connection.execute(
            """
            UPDATE agent_credentials
            SET revoked_at = ?
            WHERE agent_id = ?
            """,
            (
                "2026-09-27T00:00:00+00:00",
                enrolled.agent["agent_id"],
            ),
        )

    assert repository.authenticate_agent_credential(enrolled.credential) is None


def test_agent_credential_is_rejected_when_owner_is_inactive(tmp_path) -> None:
    repository = AuthRepository(tmp_path / "auth.db", scrypt_parameters=TEST_SCRYPT)
    repository.create_user(
        username="remaining-admin",
        password=TEST_PASSWORD,
        role="superadmin",
    )
    owner = repository.create_user(
        username="inactive-owner",
        password=TEST_PASSWORD,
        role="viewer",
    )
    registration = repository.create_agent_registration_token(int(owner["id"]))
    enrolled = repository.enroll_agent(
        registration_token=registration.token,
        hostname="inactive-owner-host",
    )
    repository.set_user_active(
        int(owner["id"]),
        active=False,
        actor_user_id=1,
    )

    assert repository.authenticate_agent_credential(enrolled.credential) is None


def test_owned_agent_ids_come_from_agents_not_legacy_host_access(tmp_path) -> None:
    repository = AuthRepository(tmp_path / "auth.db", scrypt_parameters=TEST_SCRYPT)
    owner = repository.create_user(
        username="scope-owner",
        password=TEST_PASSWORD,
        role="viewer",
    )
    other = repository.create_user(
        username="scope-other",
        password=TEST_PASSWORD,
        role="viewer",
    )
    expected_ids = []
    for hostname in ("scope-b", "scope-a"):
        registration = repository.create_agent_registration_token(int(owner["id"]))
        enrolled = repository.enroll_agent(
            registration_token=registration.token,
            hostname=hostname,
        )
        expected_ids.append(str(enrolled.agent["agent_id"]))
    other_registration = repository.create_agent_registration_token(int(other["id"]))
    repository.enroll_agent(
        registration_token=other_registration.token,
        hostname="other-host",
    )
    with sqlite3.connect(repository.database_path) as connection:
        connection.execute(
            """
            INSERT INTO user_host_access (user_id, hostname, created_at)
            VALUES (?, ?, ?)
            """,
            (
                owner["id"],
                "legacy-only-host",
                "2026-09-27T00:00:00+00:00",
            ),
        )

    assert repository.owned_agent_ids(int(owner["id"])) == tuple(
        sorted(expected_ids)
    )
