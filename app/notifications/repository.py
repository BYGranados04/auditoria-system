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

    def initialize(self) -> None:
        if self.read_only:
            raise RuntimeError(
                "No se puede inicializar un repositorio de solo lectura."
            )
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL,
                channel TEXT NOT NULL, provider TEXT NOT NULL, recipient TEXT NOT NULL,
                hostname TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL,
                created_at TEXT NOT NULL, sent_at TEXT, error TEXT,
                provider_message_id TEXT,
                UNIQUE(event_id, channel, recipient))""")

    @staticmethod
    def _row(row: sqlite3.Row) -> NotificationAttempt:
        return NotificationAttempt(
            id=row["id"],
            event_id=row["event_id"],
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
                    "(event_id, channel, provider, recipient, hostname, severity, "
                    "status, created_at) VALUES (?, 'email', ?, ?, ?, ?, 'pending', ?)",
                    (event_id, provider, recipient, hostname, severity, timestamp),
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
        hostnames: tuple[str, ...] | None = None,
        status: str | None = None,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[NotificationAttempt]:
        if self._is_unavailable():
            return []
        if not self.read_only:
            self.initialize()
        clauses: list[str] = []
        parameters: list[object] = []
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

    def summary(self, *, hostnames: tuple[str, ...] | None = None) -> dict[str, int]:
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
        if hostnames is not None and not hostnames:
            return empty
        parameters: list[object] = []
        where = ""
        if hostnames is not None:
            where = " WHERE hostname IN (" + ", ".join("?" for _ in hostnames) + ")"
            parameters.extend(hostnames)
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
