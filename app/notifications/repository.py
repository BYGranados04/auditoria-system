from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from app.notifications.models import NotificationAttempt


class NotificationRepository:
    def __init__(self, database_path: Path, *, read_only: bool = False) -> None:
        self.database_path = database_path
        self.read_only = read_only

    @contextmanager
    def _connection(self):
        if self.read_only:
            connection = sqlite3.connect(
                self.database_path.absolute().as_uri() + "?mode=ro",
                uri=True,
            )
            connection.execute("PRAGMA query_only = ON")
        else:
            connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            if not self.read_only:
                connection.commit()
        except Exception:
            if not self.read_only:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _is_unavailable(self) -> bool:
        return self.read_only and not self.database_path.is_file()

    def _supports_agent_id(self) -> bool:
        if not self.database_path.is_file():
            return False
        with self._connection() as connection:
            return "agent_id" in {
                str(row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(notifications)"
                ).fetchall()
            }

    def initialize(self) -> None:
        if self.read_only:
            raise RuntimeError(
                "No se puede inicializar un repositorio de solo lectura."
            )
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL,
                agent_id TEXT,
                channel TEXT NOT NULL, provider TEXT NOT NULL, recipient TEXT NOT NULL,
                hostname TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL,
                created_at TEXT NOT NULL, sent_at TEXT, error TEXT,
                provider_message_id TEXT,
                UNIQUE(event_id, channel, recipient))""")
            columns = {
                str(row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(notifications)"
                ).fetchall()
            }
            if "agent_id" not in columns:
                connection.execute("ALTER TABLE notifications ADD COLUMN agent_id TEXT")
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_notifications_agent_id "
                "ON notifications (agent_id)"
            )

    @staticmethod
    def _row(row: sqlite3.Row) -> NotificationAttempt:
        return NotificationAttempt(
            id=row["id"],
            event_id=row["event_id"],
            agent_id=(row["agent_id"] if "agent_id" in row.keys() else None),
            channel=row["channel"],
            provider=row["provider"],
            recipient=row["recipient"],
            hostname=row["hostname"],
            severity=row["severity"],
            status=row["status"],
            created_at=datetime.fromisoformat(row["created_at"]),
            sent_at=datetime.fromisoformat(row["sent_at"]) if row["sent_at"] else None,
            error=row["error"],
            provider_message_id=row["provider_message_id"],
        )

    def create_pending(
        self,
        *,
        event_id: str,
        agent_id: str | None = None,
        provider: str,
        recipient: str,
        hostname: str,
        severity: str,
    ) -> tuple[NotificationAttempt, bool]:
        self.initialize()
        timestamp = datetime.now(UTC).isoformat()
        with self._connection() as connection:
            try:
                connection.execute(
                    "INSERT INTO notifications "
                    "(event_id, agent_id, channel, provider, recipient, hostname, "
                    "severity, status, created_at) "
                    "VALUES (?, ?, 'email', ?, ?, ?, ?, 'pending', ?)",
                    (
                        event_id,
                        agent_id,
                        provider,
                        recipient,
                        hostname,
                        severity,
                        timestamp,
                    ),
                )
                created = True
            except sqlite3.IntegrityError:
                created = False
            row = connection.execute(
                "SELECT * FROM notifications WHERE event_id = ? "
                "AND channel = 'email' AND recipient = ?",
                (event_id, recipient),
            ).fetchone()
        return self._row(row), created

    def complete(
        self,
        notification_id: int,
        *,
        provider_message_id: str | None = None,
        error: str | None = None,
    ) -> NotificationAttempt:
        if self.read_only:
            raise RuntimeError("No se puede modificar un repositorio de solo lectura.")
        status = "sent" if error is None else "failed"
        sent_at = datetime.now(UTC).isoformat() if status == "sent" else None
        with self._connection() as connection:
            connection.execute(
                "UPDATE notifications SET status = ?, sent_at = ?, error = ?, "
                "provider_message_id = ? WHERE id = ?",
                (status, sent_at, error, provider_message_id, notification_id),
            )
            row = connection.execute(
                "SELECT * FROM notifications WHERE id = ?", (notification_id,)
            ).fetchone()
        return self._row(row)

    def list(
        self,
        *,
        agent_ids: tuple[str, ...] | None = None,
        hostnames: tuple[str, ...] | None = None,
        status: str | None = None,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[NotificationAttempt]:
        if self._is_unavailable():
            return []
        if not self.read_only:
            self.initialize()
        elif agent_ids is not None and not self._supports_agent_id():
            return []
        clauses: list[str] = []
        parameters: list[object] = []
        if agent_ids is not None:
            if not agent_ids:
                return []
            clauses.append("agent_id IN (" + ", ".join("?" for _ in agent_ids) + ")")
            parameters.extend(agent_ids)
        if hostnames is not None:
            if not hostnames:
                return []
            clauses.append("hostname IN (" + ", ".join("?" for _ in hostnames) + ")")
            parameters.extend(hostnames)
        if status is not None:
            clauses.append("status = ?")
            parameters.append(status)
        if severity is not None:
            clauses.append("severity = ?")
            parameters.append(severity)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        parameters.append(limit)
        with self._connection() as connection:
            rows = connection.execute(
                f"SELECT * FROM notifications{where} ORDER BY id DESC LIMIT ?",
                parameters,
            ).fetchall()
        return [self._row(row) for row in rows]

    def get(self, notification_id: int) -> NotificationAttempt | None:
        if self._is_unavailable():
            return None
        if not self.read_only:
            self.initialize()
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM notifications WHERE id = ?", (notification_id,)
            ).fetchone()
        return self._row(row) if row else None

    def summary(
        self,
        *,
        agent_ids: tuple[str, ...] | None = None,
        hostnames: tuple[str, ...] | None = None,
    ) -> dict[str, int]:
        empty = {
            "total": 0,
            "pending": 0,
            "sent": 0,
            "failed": 0,
            "high": 0,
            "critical": 0,
        }
        if self._is_unavailable():
            return empty
        if not self.read_only:
            self.initialize()
        elif agent_ids is not None and not self._supports_agent_id():
            return empty
        if (agent_ids is not None and not agent_ids) or (
            hostnames is not None and not hostnames
        ):
            return empty
        parameters: list[object] = []
        clauses: list[str] = []
        if agent_ids is not None:
            clauses.append("agent_id IN (" + ", ".join("?" for _ in agent_ids) + ")")
            parameters.extend(agent_ids)
        if hostnames is not None:
            clauses.append("hostname IN (" + ", ".join("?" for _ in hostnames) + ")")
            parameters.extend(hostnames)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        query = (
            "SELECT COUNT(*) AS total, "
            "SUM(status = 'pending') AS pending, SUM(status = 'sent') AS sent, "
            "SUM(status = 'failed') AS failed, SUM(severity = 'high') AS high, "
            "SUM(severity = 'critical') AS critical FROM notifications"
            f"{where}"
        )
        with self._connection() as connection:
            row = connection.execute(query, parameters).fetchone()
        return {key: int(row[key] or 0) for key in row.keys()}
