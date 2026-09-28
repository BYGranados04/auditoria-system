from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import threading
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

Role = Literal["superadmin", "viewer"]
USERNAME_PATTERN = re.compile(r"^[a-z0-9._-]{3,64}$")
MINIMUM_PASSWORD_LENGTH = 8
MAXIMUM_PASSWORD_BYTES = 1024


class AuthValidationError(ValueError):
    pass


class AuthConflictError(RuntimeError):
    pass


class AuthNotFoundError(LookupError):
    pass


@dataclass(frozen=True)
class ScryptParameters:
    n: int = 2**15
    r: int = 8
    p: int = 3
    dklen: int = 64
    maxmem: int = 256 * 1024 * 1024


@dataclass(frozen=True)
class AuthenticatedSession:
    session_id: int
    user_id: int
    username: str
    role: Role
    expires_at: datetime


@dataclass(frozen=True)
class NewSession:
    token: str
    csrf_token: str
    expires_at: datetime


@dataclass(frozen=True)
class AgentRegistrationToken:
    token: str
    expires_at: datetime


@dataclass(frozen=True)
class EnrolledAgent:
    agent: dict[str, object]
    credential: str


def normalize_username(username: str) -> str:
    normalized = username.strip().casefold()
    if not USERNAME_PATTERN.fullmatch(normalized):
        raise AuthValidationError(
            "El usuario debe tener entre 3 y 64 caracteres y usar solo "
            "letras, números, punto, guion o guion bajo."
        )
    return normalized


def validate_password(password: str) -> bytes:
    if len(password) < MINIMUM_PASSWORD_LENGTH:
        raise AuthValidationError(
            f"La contraseña debe tener al menos {MINIMUM_PASSWORD_LENGTH} caracteres."
        )
    encoded = password.encode("utf-8")
    if len(encoded) > MAXIMUM_PASSWORD_BYTES:
        raise AuthValidationError("La contraseña es demasiado larga.")
    return encoded


def validate_role(role: str) -> Role:
    if role not in {"superadmin", "viewer"}:
        raise AuthValidationError("Rol no válido.")
    return role


def normalize_hostnames(
    hostnames: Iterable[str] | None,
    *,
    required: bool,
) -> tuple[str, ...]:
    normalized: list[str] = []
    for hostname in hostnames or ():
        value = hostname.strip()
        if not value or len(value) > 255:
            raise AuthValidationError("Hostname no válido.")
        if value not in normalized:
            normalized.append(value)
    if required and not normalized:
        raise AuthValidationError(
            "Un viewer activo debe tener al menos un servidor asignado."
        )
    return tuple(normalized)


def _utc(value: datetime | None = None) -> datetime:
    current = value or datetime.now(UTC)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("La fecha debe incluir zona horaria.")
    return current.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return _utc(value).isoformat()


def derive_agent_presence(
    agent: Mapping[str, object],
    *,
    now: datetime,
    offline_after_seconds: int,
) -> Literal["unknown", "online", "offline"]:
    if offline_after_seconds <= 0:
        raise ValueError("offline_after_seconds debe ser positivo.")
    last_seen_at = agent["last_seen_at"]
    if last_seen_at is None:
        return "unknown"
    seen_at = _utc(datetime.fromisoformat(str(last_seen_at)))
    if _utc(now) - seen_at <= timedelta(seconds=offline_after_seconds):
        return "online"
    return "offline"


def _digest_token(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


class AuthRepository:
    SCHEMA_VERSION = 3

    def __init__(
        self,
        database_path: Path,
        *,
        scrypt_parameters: ScryptParameters | None = None,
    ) -> None:
        self.database_path = database_path
        self.scrypt_parameters = scrypt_parameters or ScryptParameters()
        self._initialized = False
        self._initialize_lock = threading.Lock()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.database_path, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        if self._initialized:
            return
        with self._initialize_lock:
            if self._initialized:
                return
            self.database_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if os.name != "nt":
                self.database_path.parent.chmod(0o700)
            with self._connection() as connection:
                version = int(connection.execute("PRAGMA user_version").fetchone()[0])
                if version > self.SCHEMA_VERSION:
                    raise RuntimeError("auth.db usa un esquema más nuevo.")
                migrations = {
                    1: self._migrate_to_v1,
                    2: self._migrate_to_v2,
                    3: self._migrate_to_v3,
                }
                while version < self.SCHEMA_VERSION:
                    next_version = version + 1
                    migrations[next_version](connection)
                    connection.execute(f"PRAGMA user_version = {next_version}")
                    version = next_version
            if os.name != "nt":
                self.database_path.chmod(0o600)
            self._initialized = True

    @staticmethod
    def _migrate_to_v1(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash BLOB NOT NULL,
                password_salt BLOB NOT NULL,
                scrypt_n INTEGER NOT NULL,
                scrypt_r INTEGER NOT NULL,
                scrypt_p INTEGER NOT NULL,
                scrypt_dklen INTEGER NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('superadmin', 'viewer')),
                active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_digest BLOB NOT NULL UNIQUE,
                csrf_digest BLOB NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );

            CREATE INDEX idx_sessions_expires_at ON sessions (expires_at);
            CREATE INDEX idx_sessions_user_id ON sessions (user_id);
            """
        )

    @staticmethod
    def _migrate_to_v2(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS user_host_access (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL
                    REFERENCES users(id) ON DELETE CASCADE,
                hostname TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE (user_id, hostname)
            );

            CREATE INDEX IF NOT EXISTS idx_user_host_access_user
                ON user_host_access (user_id);
            CREATE INDEX IF NOT EXISTS idx_user_host_access_hostname
                ON user_host_access (hostname);
            """
        )

    @staticmethod
    def _migrate_to_v3(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS agents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL UNIQUE,
                owner_user_id INTEGER NOT NULL
                    REFERENCES users(id) ON DELETE CASCADE,
                hostname TEXT NOT NULL,
                status TEXT NOT NULL
                    CHECK (status IN ('online', 'offline')),
                registered_at TEXT NOT NULL,
                last_seen_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_agents_owner
                ON agents (owner_user_id);
            CREATE INDEX IF NOT EXISTS idx_agents_status
                ON agents (status);

            CREATE TABLE IF NOT EXISTS agent_registration_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_user_id INTEGER NOT NULL
                    REFERENCES users(id) ON DELETE CASCADE,
                token_digest BLOB NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_agent_registration_owner
                ON agent_registration_tokens (owner_user_id);
            CREATE INDEX IF NOT EXISTS idx_agent_registration_expires
                ON agent_registration_tokens (expires_at);

            CREATE TABLE IF NOT EXISTS agent_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL
                    REFERENCES agents(agent_id) ON DELETE CASCADE,
                credential_digest BLOB NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                revoked_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_agent_credentials_agent
                ON agent_credentials (agent_id);
            """
        )

    def _hash_password(
        self,
        password: bytes,
        salt: bytes,
        parameters: ScryptParameters,
    ) -> bytes:
        return hashlib.scrypt(
            password,
            salt=salt,
            n=parameters.n,
            r=parameters.r,
            p=parameters.p,
            maxmem=parameters.maxmem,
            dklen=parameters.dklen,
        )

    @staticmethod
    def _user_hostnames(
        connection: sqlite3.Connection,
        user_id: int,
    ) -> list[str]:
        rows = connection.execute(
            """
            SELECT hostname
            FROM user_host_access
            WHERE user_id = ?
            ORDER BY hostname
            """,
            (user_id,),
        ).fetchall()
        return [str(row["hostname"]) for row in rows]

    @classmethod
    def _public_user(
        cls,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> dict[str, object]:
        role = str(row["role"])
        return {
            "id": int(row["id"]),
            "username": str(row["username"]),
            "role": role,
            "active": bool(row["active"]),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
            "server_count": (
                None
                if role == "superadmin"
                else int(
                    connection.execute(
                        "SELECT COUNT(*) FROM agents WHERE owner_user_id = ?",
                        (int(row["id"]),),
                    ).fetchone()[0]
                )
            ),
        }

    def create_user(
        self,
        *,
        username: str,
        password: str,
        role: str,
        now: datetime | None = None,
    ) -> dict[str, object]:
        self.initialize()
        normalized_username = normalize_username(username)
        encoded_password = validate_password(password)
        validated_role = validate_role(role)
        salt = secrets.token_bytes(16)
        password_hash = self._hash_password(
            encoded_password,
            salt,
            self.scrypt_parameters,
        )
        timestamp = _timestamp(_utc(now))
        try:
            with self._connection() as connection:
                cursor = connection.execute(
                    """
                    INSERT INTO users (
                        username, password_hash, password_salt,
                        scrypt_n, scrypt_r, scrypt_p, scrypt_dklen,
                        role, active, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                    """,
                    (
                        normalized_username,
                        password_hash,
                        salt,
                        self.scrypt_parameters.n,
                        self.scrypt_parameters.r,
                        self.scrypt_parameters.p,
                        self.scrypt_parameters.dklen,
                        validated_role,
                        timestamp,
                        timestamp,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM users WHERE id = ?",
                    (cursor.lastrowid,),
                ).fetchone()
                result = self._public_user(connection, row)
        except sqlite3.IntegrityError as exc:
            raise AuthConflictError("El usuario ya existe.") from exc
        return result

    def authenticate(self, username: str, password: str) -> dict[str, object] | None:
        self.initialize()
        try:
            normalized_username = normalize_username(username)
            encoded_password = validate_password(password)
        except AuthValidationError:
            return None
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE username = ?",
                (normalized_username,),
            ).fetchone()
            if row is None or not bool(row["active"]):
                return None
            parameters = ScryptParameters(
                n=int(row["scrypt_n"]),
                r=int(row["scrypt_r"]),
                p=int(row["scrypt_p"]),
                dklen=int(row["scrypt_dklen"]),
                maxmem=self.scrypt_parameters.maxmem,
            )
            candidate = self._hash_password(
                encoded_password,
                bytes(row["password_salt"]),
                parameters,
            )
            if not hmac.compare_digest(candidate, bytes(row["password_hash"])):
                return None
            return self._public_user(connection, row)

    def create_session(
        self,
        user_id: int,
        *,
        session_seconds: int,
        now: datetime | None = None,
    ) -> NewSession:
        self.initialize()
        current = _utc(now)
        expires_at = current + timedelta(seconds=session_seconds)
        token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        with self._connection() as connection:
            connection.execute(
                "DELETE FROM sessions WHERE expires_at <= ?", (_timestamp(current),)
            )
            connection.execute(
                """
                INSERT INTO sessions (
                    user_id, token_digest, csrf_digest, created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    _digest_token(token),
                    _digest_token(csrf_token),
                    _timestamp(current),
                    _timestamp(expires_at),
                ),
            )
        return NewSession(token=token, csrf_token=csrf_token, expires_at=expires_at)

    def get_session(
        self,
        token: str,
        *,
        now: datetime | None = None,
    ) -> AuthenticatedSession | None:
        self.initialize()
        current = _utc(now)
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT
                    sessions.id AS session_id,
                    sessions.user_id,
                    sessions.expires_at,
                    users.username,
                    users.role
                FROM sessions
                JOIN users ON users.id = sessions.user_id
                WHERE sessions.token_digest = ?
                  AND sessions.expires_at > ?
                  AND users.active = 1
                """,
                (_digest_token(token), _timestamp(current)),
            ).fetchone()
        if row is None:
            return None
        return AuthenticatedSession(
            session_id=int(row["session_id"]),
            user_id=int(row["user_id"]),
            username=str(row["username"]),
            role=validate_role(str(row["role"])),
            expires_at=datetime.fromisoformat(str(row["expires_at"])),
        )

    def verify_csrf(self, session_id: int, csrf_token: str) -> bool:
        self.initialize()
        with self._connection() as connection:
            row = connection.execute(
                "SELECT csrf_digest FROM sessions WHERE id = ?",
                (session_id,),
            ).fetchone()
        return row is not None and hmac.compare_digest(
            bytes(row["csrf_digest"]),
            _digest_token(csrf_token),
        )

    def delete_session(self, token: str) -> None:
        self.initialize()
        with self._connection() as connection:
            connection.execute(
                "DELETE FROM sessions WHERE token_digest = ?",
                (_digest_token(token),),
            )

    def list_users(self) -> list[dict[str, object]]:
        self.initialize()
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM users ORDER BY username"
            ).fetchall()
            return [self._public_user(connection, row) for row in rows]

    def get_user_hostnames(self, user_id: int) -> tuple[str, ...]:
        self.initialize()
        with self._connection() as connection:
            return tuple(self._user_hostnames(connection, user_id))

    def get_owned_agent_hostnames(self, user_id: int) -> tuple[str, ...]:
        self.initialize()
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT DISTINCT hostname
                FROM agents
                WHERE owner_user_id = ?
                ORDER BY hostname
                """,
                (user_id,),
            ).fetchall()
        return tuple(str(row["hostname"]) for row in rows)

    def owned_agent_ids(self, user_id: int) -> tuple[str, ...]:
        self.initialize()
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT agent_id
                FROM agents
                WHERE owner_user_id = ?
                ORDER BY agent_id
                """,
                (user_id,),
            ).fetchall()
        return tuple(str(row["agent_id"]) for row in rows)

    def replace_user_hostnames(
        self,
        user_id: int,
        *,
        hostnames: Iterable[str],
        now: datetime | None = None,
    ) -> dict[str, object]:
        self.initialize()
        timestamp = _timestamp(_utc(now))
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            if row is None:
                raise AuthNotFoundError("Usuario no encontrado.")
            if str(row["role"]) != "viewer":
                raise AuthConflictError(
                    "Las asignaciones de servidores solo aplican a viewers."
                )
            validated = normalize_hostnames(
                hostnames,
                required=bool(row["active"]),
            )
            connection.execute(
                "DELETE FROM user_host_access WHERE user_id = ?", (user_id,)
            )
            connection.executemany(
                """
                INSERT INTO user_host_access (user_id, hostname, created_at)
                VALUES (?, ?, ?)
                """,
                ((user_id, hostname, timestamp) for hostname in validated),
            )
            connection.execute(
                "UPDATE users SET updated_at = ? WHERE id = ?",
                (timestamp, user_id),
            )
            connection.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            updated = connection.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            return self._public_user(connection, updated)

    def set_user_active(
        self,
        user_id: int,
        *,
        active: bool,
        actor_user_id: int,
        now: datetime | None = None,
    ) -> dict[str, object]:
        self.initialize()
        if user_id == actor_user_id and not active:
            raise AuthConflictError("No puede desactivar su propia cuenta.")
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            if row is None:
                raise AuthNotFoundError("Usuario no encontrado.")
            if not active and row["role"] == "superadmin" and bool(row["active"]):
                active_admins = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM users "
                        "WHERE role = 'superadmin' AND active = 1"
                    ).fetchone()[0]
                )
                if active_admins <= 1:
                    raise AuthConflictError(
                        "No se puede desactivar al último superadmin activo."
                    )
            connection.execute(
                "UPDATE users SET active = ?, updated_at = ? WHERE id = ?",
                (int(active), _timestamp(_utc(now)), user_id),
            )
            if not active:
                connection.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            updated = connection.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            return self._public_user(connection, updated)

    def set_user_role(
        self,
        user_id: int,
        *,
        role: str,
        actor_user_id: int,
        now: datetime | None = None,
    ) -> dict[str, object]:
        self.initialize()
        validated_role = validate_role(role)
        if user_id == actor_user_id and validated_role != "superadmin":
            raise AuthConflictError("No puede degradar su propia cuenta.")
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            if row is None:
                raise AuthNotFoundError("Usuario no encontrado.")
            if (
                row["role"] == "superadmin"
                and validated_role != "superadmin"
                and bool(row["active"])
            ):
                active_admins = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM users "
                        "WHERE role = 'superadmin' AND active = 1"
                    ).fetchone()[0]
                )
                if active_admins <= 1:
                    raise AuthConflictError(
                        "No se puede degradar al último superadmin activo."
                    )
            connection.execute(
                "UPDATE users SET role = ?, updated_at = ? WHERE id = ?",
                (validated_role, _timestamp(_utc(now)), user_id),
            )
            if validated_role != str(row["role"]):
                connection.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            updated = connection.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            return self._public_user(connection, updated)

    @staticmethod
    def _public_agent(
        row: sqlite3.Row,
        *,
        now: datetime | None = None,
        offline_after_seconds: int = 120,
    ) -> dict[str, object]:
        presence = derive_agent_presence(
            row,
            now=_utc(now),
            offline_after_seconds=offline_after_seconds,
        )
        return {
            "agent_id": str(row["agent_id"]),
            "owner_user_id": int(row["owner_user_id"]),
            "hostname": str(row["hostname"]),
            # Kept for compatibility; presence is the source of truth.
            "status": presence,
            "presence": presence,
            "registered_at": str(row["registered_at"]),
            "last_seen_at": (
                str(row["last_seen_at"])
                if row["last_seen_at"] is not None
                else None
            ),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
        }

    def create_agent_registration_token(
        self,
        owner_user_id: int,
        *,
        ttl_seconds: int = 900,
        now: datetime | None = None,
    ) -> AgentRegistrationToken:
        self.initialize()
        current = _utc(now)
        expires_at = current + timedelta(seconds=ttl_seconds)
        token = f"reg_{secrets.token_urlsafe(32)}"
        with self._connection() as connection:
            owner = connection.execute(
                "SELECT active FROM users WHERE id = ?", (owner_user_id,)
            ).fetchone()
            if owner is None or not bool(owner["active"]):
                raise AuthNotFoundError("Usuario no encontrado.")
            connection.execute(
                """
                INSERT INTO agent_registration_tokens (
                    owner_user_id, token_digest, created_at, expires_at, used_at
                ) VALUES (?, ?, ?, ?, NULL)
                """,
                (
                    owner_user_id,
                    _digest_token(token),
                    _timestamp(current),
                    _timestamp(expires_at),
                ),
            )
        return AgentRegistrationToken(token=token, expires_at=expires_at)

    def enroll_agent(
        self,
        *,
        registration_token: str,
        hostname: str,
        now: datetime | None = None,
    ) -> EnrolledAgent:
        self.initialize()
        normalized_hostname = hostname.strip()
        if not normalized_hostname or len(normalized_hostname) > 255:
            raise AuthValidationError("Hostname no válido.")
        current = _utc(now)
        timestamp = _timestamp(current)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            token_row = connection.execute(
                """
                SELECT agent_registration_tokens.*
                FROM agent_registration_tokens
                JOIN users
                  ON users.id = agent_registration_tokens.owner_user_id
                WHERE token_digest = ?
                  AND users.active = 1
                """,
                (_digest_token(registration_token),),
            ).fetchone()
            if (
                token_row is None
                or token_row["used_at"] is not None
                or datetime.fromisoformat(str(token_row["expires_at"])) <= current
            ):
                raise AuthValidationError("Token de registro no válido o expirado.")

            owner_user_id = int(token_row["owner_user_id"])
            agent_id = f"agt_{secrets.token_urlsafe(24)}"
            credential = f"agc_{secrets.token_urlsafe(32)}"
            connection.execute(
                """
                INSERT INTO agents (
                    agent_id, owner_user_id, hostname, status,
                    registered_at, last_seen_at, created_at, updated_at
                ) VALUES (?, ?, ?, 'offline', ?, NULL, ?, ?)
                """,
                (
                    agent_id,
                    owner_user_id,
                    normalized_hostname,
                    timestamp,
                    timestamp,
                    timestamp,
                ),
            )
            connection.execute(
                """
                INSERT INTO agent_credentials (
                    agent_id, credential_digest, created_at, revoked_at
                ) VALUES (?, ?, ?, NULL)
                """,
                (agent_id, _digest_token(credential), timestamp),
            )
            connection.execute(
                """
                UPDATE agent_registration_tokens
                SET used_at = ?
                WHERE id = ? AND used_at IS NULL
                """,
                (timestamp, int(token_row["id"])),
            )
            agent_row = connection.execute(
                "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()
            return EnrolledAgent(
                agent=self._public_agent(agent_row),
                credential=credential,
            )

    def list_agents(
        self,
        *,
        owner_user_id: int | None = None,
        now: datetime | None = None,
        offline_after_seconds: int = 120,
    ) -> list[dict[str, object]]:
        self.initialize()
        parameters: tuple[object, ...] = ()
        where = ""
        if owner_user_id is not None:
            where = " WHERE owner_user_id = ?"
            parameters = (owner_user_id,)
        with self._connection() as connection:
            rows = connection.execute(
                f"SELECT * FROM agents{where} ORDER BY hostname, agent_id",
                parameters,
            ).fetchall()
        return [
            self._public_agent(
                row,
                now=now,
                offline_after_seconds=offline_after_seconds,
            )
            for row in rows
        ]

    def get_agent(
        self,
        agent_id: str,
        *,
        owner_user_id: int | None = None,
        now: datetime | None = None,
        offline_after_seconds: int = 120,
    ) -> dict[str, object] | None:
        self.initialize()
        query = "SELECT * FROM agents WHERE agent_id = ?"
        parameters: list[object] = [agent_id]
        if owner_user_id is not None:
            query += " AND owner_user_id = ?"
            parameters.append(owner_user_id)
        with self._connection() as connection:
            row = connection.execute(query, parameters).fetchone()
        return (
            self._public_agent(
                row,
                now=now,
                offline_after_seconds=offline_after_seconds,
            )
            if row is not None
            else None
        )

    def authenticate_agent_credential(
        self,
        credential: str,
    ) -> dict[str, object] | None:
        self.initialize()
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT agents.*
                FROM agent_credentials
                JOIN agents
                  ON agents.agent_id = agent_credentials.agent_id
                JOIN users
                  ON users.id = agents.owner_user_id
                WHERE agent_credentials.credential_digest = ?
                  AND agent_credentials.revoked_at IS NULL
                  AND users.active = 1
                """,
                (_digest_token(credential),),
            ).fetchone()
        return self._public_agent(row) if row is not None else None

    def record_agent_heartbeat(
        self,
        *,
        credential: str,
        now: datetime | None = None,
        offline_after_seconds: int = 120,
    ) -> dict[str, object] | None:
        self.initialize()
        current = _utc(now)
        timestamp = _timestamp(current)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT agents.*
                FROM agent_credentials
                JOIN agents ON agents.agent_id = agent_credentials.agent_id
                JOIN users ON users.id = agents.owner_user_id
                WHERE agent_credentials.credential_digest = ?
                  AND agent_credentials.revoked_at IS NULL
                  AND users.active = 1
                """,
                (_digest_token(credential),),
            ).fetchone()
            if row is None:
                return None
            connection.execute(
                """
                UPDATE agents
                SET last_seen_at = ?, updated_at = ?
                WHERE agent_id = ?
                """,
                (timestamp, timestamp, str(row["agent_id"])),
            )
            updated = connection.execute(
                "SELECT * FROM agents WHERE agent_id = ?", (str(row["agent_id"]),)
            ).fetchone()
            return self._public_agent(
                updated,
                now=current,
                offline_after_seconds=offline_after_seconds,
            )
