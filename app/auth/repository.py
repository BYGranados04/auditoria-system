from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import threading
import unicodedata
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

ResponseMode = Literal["audit_only", "assisted", "automatic"]
ConfigSource = Literal["local", "central"]
RESPONSE_MODES: frozenset[str] = frozenset({"audit_only", "assisted", "automatic"})
CONFIG_SOURCES: frozenset[str] = frozenset({"local", "central"})
DISPLAY_NAME_MAX_LENGTH = 64
AGENT_VERSION_PATTERN = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$")
CONFIG_PROTOCOL_VERSION = 1
ConfigStatus = Literal["pending", "applied", "rejected"]
CONFIG_STATUS_REASON_MAX_LENGTH = 160
DEFAULT_REJECTION_REASON = "El agente rechazó la configuración."


class AuthValidationError(ValueError):
    pass


class AuthConflictError(RuntimeError):
    pass


class AuthNotFoundError(LookupError):
    pass


class AgentConfigStaleError(RuntimeError):
    """Reporte de configuración anterior al último ya confirmado."""


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


def normalize_display_name(value: str | None) -> str | None:
    """Nombre visible asignado por un administrador.

    Vacío equivale a NULL (el dashboard muestra el hostname). Se rechazan
    caracteres Unicode de categoría C (control, formato, privados, no
    asignados), lo que incluye overrides bidireccionales y saltos de línea.
    """

    if value is None:
        return None
    normalized = value.strip()
    if not normalized:
        return None
    if len(normalized) > DISPLAY_NAME_MAX_LENGTH:
        raise AuthValidationError(
            f"El nombre debe tener como máximo {DISPLAY_NAME_MAX_LENGTH} caracteres."
        )
    if any(unicodedata.category(character).startswith("C") for character in normalized):
        raise AuthValidationError(
            "El nombre contiene caracteres de control o no permitidos."
        )
    return normalized


def validate_response_mode(value: str) -> ResponseMode:
    if value not in RESPONSE_MODES:
        raise AuthValidationError("Modo de respuesta no válido.")
    return value  # type: ignore[return-value]


def sanitize_config_reason(value: str | None) -> str | None:
    """Motivo corto y seguro para mostrar en el dashboard.

    Elimina caracteres Unicode de categoría C (control, formato, etc.),
    colapsa espacios y limita la longitud. Nunca debe contener trazas: el
    agente solo envía mensajes fijos generados por Nexora.
    """

    if value is None:
        return None
    cleaned = "".join(
        " " if unicodedata.category(character).startswith("C") else character
        for character in value
    )
    normalized = " ".join(cleaned.split())
    if not normalized:
        return None
    if len(normalized) > CONFIG_STATUS_REASON_MAX_LENGTH:
        normalized = normalized[: CONFIG_STATUS_REASON_MAX_LENGTH - 1].rstrip() + "…"
    return normalized


def normalize_agent_version(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    if not AGENT_VERSION_PATTERN.fullmatch(normalized):
        raise AuthValidationError("Versión de agente no válida.")
    return normalized


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
    SCHEMA_VERSION = 4

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
                    4: self._migrate_to_v4,
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

    @staticmethod
    def _migrate_to_v4(connection: sqlite3.Connection) -> None:
        """Control plane v1.1: nombre visible, versión y configuración remota.

        Solo agrega columnas y una tabla de historial. Cada columna se agrega
        únicamente si no existe, por lo que un reintento tras una interrupción
        no falla. No toca credenciales, tokens ni eventos.
        """

        modes = "('audit_only', 'assisted', 'automatic')"
        columns = (
            ("display_name", "TEXT"),
            ("agent_version", "TEXT"),
            ("config_protocol", "INTEGER"),
            (
                "desired_response_mode",
                "TEXT CHECK (desired_response_mode IS NULL "
                f"OR desired_response_mode IN {modes})",
            ),
            ("config_revision", "INTEGER NOT NULL DEFAULT 0"),
            ("config_updated_at", "TEXT"),
            ("applied_config_revision", "INTEGER NOT NULL DEFAULT 0"),
            (
                "effective_response_mode",
                "TEXT CHECK (effective_response_mode IS NULL "
                f"OR effective_response_mode IN {modes})",
            ),
            (
                "config_source",
                "TEXT CHECK (config_source IS NULL "
                "OR config_source IN ('local', 'central'))",
            ),
            (
                "blocking_enabled",
                "INTEGER CHECK (blocking_enabled IS NULL "
                "OR blocking_enabled IN (0, 1))",
            ),
            ("config_reported_at", "TEXT"),
            # Último resultado de configuración central: NULL si nunca hubo
            # una; pending al crear una revisión; applied o rejected según el
            # reporte del agente para config_status_revision.
            (
                "config_status",
                "TEXT CHECK (config_status IS NULL "
                "OR config_status IN ('pending', 'applied', 'rejected'))",
            ),
            ("config_status_revision", "INTEGER"),
            ("config_status_reason", "TEXT"),
        )
        existing = {
            str(row[1])
            for row in connection.execute("PRAGMA table_info(agents)").fetchall()
        }
        for name, definition in columns:
            if name not in existing:
                connection.execute(f"ALTER TABLE agents ADD COLUMN {name} {definition}")

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_config_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                -- Sin FK: el historial de auditoría sobrevive al agente.
                agent_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                field TEXT NOT NULL
                    CHECK (field IN ('display_name', 'response_mode')),
                old_value TEXT,
                new_value TEXT,
                changed_by_user_id INTEGER,
                changed_by_username TEXT NOT NULL,
                changed_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_agent_config_changes_agent
                ON agent_config_changes (agent_id, id)
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
            **AuthRepository._agent_control_fields(row),
        }

    @staticmethod
    def _agent_control_fields(row: sqlite3.Row) -> dict[str, object]:
        def optional_text(name: str) -> str | None:
            value = row[name]
            return str(value) if value is not None else None

        config_revision = int(row["config_revision"])
        applied_revision = int(row["applied_config_revision"])
        desired = optional_text("desired_response_mode")
        blocking = row["blocking_enabled"]
        return {
            "display_name": optional_text("display_name"),
            "agent_version": optional_text("agent_version"),
            "config_protocol": (
                int(row["config_protocol"])
                if row["config_protocol"] is not None
                else None
            ),
            "desired_response_mode": desired,
            "config_revision": config_revision,
            "config_updated_at": optional_text("config_updated_at"),
            "applied_config_revision": applied_revision,
            "effective_response_mode": optional_text("effective_response_mode"),
            "config_source": optional_text("config_source"),
            "blocking_enabled": bool(blocking) if blocking is not None else None,
            "config_reported_at": optional_text("config_reported_at"),
            "config_status": optional_text("config_status"),
            "config_status_revision": (
                int(row["config_status_revision"])
                if row["config_status_revision"] is not None
                else None
            ),
            "config_status_reason": optional_text("config_status_reason"),
            # Compatibilidad con la vista: pendiente solo si el último
            # resultado es pending (un rechazo no queda pendiente).
            "config_pending": row["config_status"] == "pending",
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
        agent_version: str | None = None,
    ) -> dict[str, object] | None:
        self.initialize()
        normalized_version = normalize_agent_version(agent_version)
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
                SET last_seen_at = ?,
                    updated_at = ?,
                    agent_version = COALESCE(?, agent_version)
                WHERE agent_id = ?
                """,
                (timestamp, timestamp, normalized_version, str(row["agent_id"])),
            )
            updated = connection.execute(
                "SELECT * FROM agents WHERE agent_id = ?", (str(row["agent_id"]),)
            ).fetchone()
            return self._public_agent(
                updated,
                now=current,
                offline_after_seconds=offline_after_seconds,
            )

    # ------------------------------------------------------------------
    # Control plane v1.1
    # ------------------------------------------------------------------

    @staticmethod
    def _insert_config_change(
        connection: sqlite3.Connection,
        *,
        agent_id: str,
        revision: int,
        field: str,
        old_value: str | None,
        new_value: str | None,
        user_id: int,
        username: str,
        changed_at: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO agent_config_changes (
                agent_id, revision, field, old_value, new_value,
                changed_by_user_id, changed_by_username, changed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                agent_id,
                revision,
                field,
                old_value,
                new_value,
                user_id,
                username,
                changed_at,
            ),
        )

    def set_agent_display_name(
        self,
        agent_id: str,
        *,
        display_name: str | None,
        actor_user_id: int,
        actor_username: str,
        now: datetime | None = None,
        offline_after_seconds: int = 120,
    ) -> dict[str, object]:
        self.initialize()
        normalized = normalize_display_name(display_name)
        current = _utc(now)
        timestamp = _timestamp(current)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()
            if row is None:
                raise AuthNotFoundError("Servidor no encontrado.")
            previous = row["display_name"]
            if previous != normalized:
                connection.execute(
                    """
                    UPDATE agents
                    SET display_name = ?, updated_at = ?
                    WHERE agent_id = ?
                    """,
                    (normalized, timestamp, agent_id),
                )
                self._insert_config_change(
                    connection,
                    agent_id=agent_id,
                    revision=int(row["config_revision"]),
                    field="display_name",
                    old_value=previous,
                    new_value=normalized,
                    user_id=actor_user_id,
                    username=actor_username,
                    changed_at=timestamp,
                )
            updated = connection.execute(
                "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()
            return self._public_agent(
                updated,
                now=current,
                offline_after_seconds=offline_after_seconds,
            )

    def set_desired_response_mode(
        self,
        agent_id: str,
        *,
        response_mode: str,
        expected_revision: int,
        actor_user_id: int,
        actor_username: str,
        now: datetime | None = None,
        offline_after_seconds: int = 120,
    ) -> dict[str, object]:
        """Modo deseado + revisión + historial en una sola transacción."""

        self.initialize()
        mode = validate_response_mode(response_mode)
        current = _utc(now)
        timestamp = _timestamp(current)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()
            if row is None:
                raise AuthNotFoundError("Servidor no encontrado.")
            if row["config_protocol"] is None:
                raise AuthConflictError(
                    "El agente no admite configuración central "
                    "(agente v1.0 o sin contacto de configuración)."
                )
            revision = int(row["config_revision"])
            if expected_revision != revision:
                raise AuthConflictError(
                    "La configuración cambió; recargue el servidor "
                    f"(revisión actual {revision})."
                )
            next_revision = revision + 1
            connection.execute(
                """
                UPDATE agents
                SET desired_response_mode = ?,
                    config_revision = ?,
                    config_updated_at = ?,
                    config_status = 'pending',
                    config_status_revision = ?,
                    config_status_reason = NULL,
                    updated_at = ?
                WHERE agent_id = ? AND config_revision = ?
                """,
                (
                    mode,
                    next_revision,
                    timestamp,
                    next_revision,
                    timestamp,
                    agent_id,
                    revision,
                ),
            )
            self._insert_config_change(
                connection,
                agent_id=agent_id,
                revision=next_revision,
                field="response_mode",
                old_value=row["desired_response_mode"],
                new_value=mode,
                user_id=actor_user_id,
                username=actor_username,
                changed_at=timestamp,
            )
            updated = connection.execute(
                "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()
            return self._public_agent(
                updated,
                now=current,
                offline_after_seconds=offline_after_seconds,
            )

    def list_agent_config_changes(
        self,
        agent_id: str,
        *,
        limit: int = 50,
    ) -> list[dict[str, object]]:
        self.initialize()
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM agent_config_changes
                WHERE agent_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (agent_id, max(1, min(limit, 200))),
            ).fetchall()
        return [
            {
                "id": int(row["id"]),
                "agent_id": str(row["agent_id"]),
                "revision": int(row["revision"]),
                "field": str(row["field"]),
                "old_value": row["old_value"],
                "new_value": row["new_value"],
                "changed_by_user_id": row["changed_by_user_id"],
                "changed_by_username": str(row["changed_by_username"]),
                "changed_at": str(row["changed_at"]),
            }
            for row in rows
        ]

    def get_agent_config_for_credential(
        self,
        credential: str,
    ) -> dict[str, object] | None:
        """Configuración del agente autenticado y marca de protocolo.

        Solo el agente dueño de la credencial obtiene su configuración. El
        acceso registra ``config_protocol``: es la prueba de que el agente
        entiende configuración central.
        """

        self.initialize()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._agent_row_for_credential(connection, credential)
            if row is None:
                return None
            if row["config_protocol"] != CONFIG_PROTOCOL_VERSION:
                connection.execute(
                    "UPDATE agents SET config_protocol = ? WHERE agent_id = ?",
                    (CONFIG_PROTOCOL_VERSION, str(row["agent_id"])),
                )
            return {
                "agent_id": str(row["agent_id"]),
                "revision": int(row["config_revision"]),
                "response_mode": (
                    str(row["desired_response_mode"])
                    if row["desired_response_mode"] is not None
                    else None
                ),
            }

    def report_agent_config_state(
        self,
        *,
        credential: str,
        applied_revision: int,
        effective_response_mode: str,
        config_source: str,
        blocking_enabled: bool,
        status: Literal["applied", "rejected"],
        reason: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, object] | None:
        """Registra el resultado de configuración que reporta el agente.

        - revisión mayor que la solicitada: conflicto (409);
        - revisión menor que el último resultado conocido (aplicado o
          pendiente/rechazado): obsoleta, no pisa el estado más nuevo;
        - ``applied``: exige que el modo efectivo coincida con el de esa
          revisión; avanza ``applied_config_revision`` y deja ``applied``;
        - ``rejected``: deja ``rejected`` con motivo saneado, sin tocar
          ``applied_config_revision`` ni el modo efectivo anterior;
        - ``applied`` con revisión 0: estado inicial del agente, sin
          configuración central (``config_status`` no cambia).
        """

        self.initialize()
        mode = validate_response_mode(effective_response_mode)
        if config_source not in CONFIG_SOURCES:
            raise AuthValidationError("Origen de configuración no válido.")
        if status not in {"applied", "rejected"}:
            raise AuthValidationError("Estado de configuración no válido.")
        if applied_revision < 0:
            raise AuthValidationError("Revisión no válida.")
        timestamp = _timestamp(_utc(now))
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._agent_row_for_credential(connection, credential)
            if row is None:
                return None
            agent_id = str(row["agent_id"])
            if applied_revision > int(row["config_revision"]):
                raise AuthConflictError(
                    "La revisión reportada no existe en el central."
                )
            latest_known = max(
                int(row["applied_config_revision"]),
                int(row["config_status_revision"] or 0),
            )
            if applied_revision < latest_known:
                raise AgentConfigStaleError(
                    "La revisión reportada es anterior al último estado conocido."
                )
            if status == "rejected" and applied_revision == 0:
                raise AuthConflictError(
                    "No existe una revisión central que rechazar."
                )
            if status == "applied" and applied_revision > 0:
                change = connection.execute(
                    """
                    SELECT new_value
                    FROM agent_config_changes
                    WHERE agent_id = ? AND field = 'response_mode'
                      AND revision = ?
                    ORDER BY id DESC
                    LIMIT 1
                    """,
                    (agent_id, applied_revision),
                ).fetchone()
                if change is None or change["new_value"] != mode:
                    raise AuthConflictError(
                        "El modo efectivo no corresponde a la revisión reportada."
                    )

            if status == "rejected":
                connection.execute(
                    """
                    UPDATE agents
                    SET config_status = 'rejected',
                        config_status_revision = ?,
                        config_status_reason = ?,
                        config_reported_at = ?
                    WHERE agent_id = ?
                    """,
                    (
                        applied_revision,
                        sanitize_config_reason(reason) or DEFAULT_REJECTION_REASON,
                        timestamp,
                        agent_id,
                    ),
                )
            elif applied_revision > 0:
                connection.execute(
                    """
                    UPDATE agents
                    SET applied_config_revision = ?,
                        effective_response_mode = ?,
                        config_source = ?,
                        blocking_enabled = ?,
                        config_status = 'applied',
                        config_status_revision = ?,
                        config_status_reason = NULL,
                        config_reported_at = ?
                    WHERE agent_id = ?
                    """,
                    (
                        applied_revision,
                        mode,
                        config_source,
                        int(blocking_enabled),
                        applied_revision,
                        timestamp,
                        agent_id,
                    ),
                )
            else:
                # Revisión 0: solo el estado real del agente (arranque).
                connection.execute(
                    """
                    UPDATE agents
                    SET effective_response_mode = ?,
                        config_source = ?,
                        blocking_enabled = ?,
                        config_reported_at = ?
                    WHERE agent_id = ?
                    """,
                    (mode, config_source, int(blocking_enabled), timestamp, agent_id),
                )
            updated = connection.execute(
                "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()
            return self._public_agent(updated)

    @staticmethod
    def _agent_row_for_credential(
        connection: sqlite3.Connection,
        credential: str,
    ) -> sqlite3.Row | None:
        return connection.execute(
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
