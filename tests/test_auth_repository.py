import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from app.auth.repository import AuthConflictError, AuthRepository
from tests.api_test_helpers import TEST_PASSWORD, TEST_SCRYPT


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
