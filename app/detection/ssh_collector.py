from __future__ import annotations

import ipaddress
import json
import re
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True)
class SSHJournalRecord:
    cursor: str
    timestamp: datetime
    event_type: str
    severity: str
    description: str
    evidence: dict[str, Any]


@dataclass(frozen=True)
class SSHJournalBatch:
    records: list[SSHJournalRecord]
    cursor: str | None


class SSHJournalCollector:
    _ACCEPTED = re.compile(
        r"^Accepted (?P<method>\S+) for "
        r"(?P<user>\S+) from "
        r"(?P<ip>\S+) port "
        r"(?P<port>\d+)"
    )

    _FAILED = re.compile(
        r"^Failed (?P<method>\S+) for "
        r"(?:(?:invalid user) )?"
        r"(?P<user>\S+) from "
        r"(?P<ip>\S+) port "
        r"(?P<port>\d+)"
    )

    _INVALID_USER = re.compile(
        r"^Invalid user "
        r"(?P<user>\S+) from "
        r"(?P<ip>\S+) port "
        r"(?P<port>\d+)"
    )

    @staticmethod
    def _run(
        command: list[str],
    ) -> tuple[int, str, str]:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )

        return (
            result.returncode,
            result.stdout,
            result.stderr,
        )

    @staticmethod
    def _timestamp_from_journal(
        value: str,
    ) -> datetime:
        microseconds = int(value)

        return datetime.fromtimestamp(
            microseconds / 1_000_000,
            tz=UTC,
        )

    @staticmethod
    def _normalize_ip(value: str) -> str:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return value

    @classmethod
    def parse_entry(
        cls,
        entry: dict[str, Any],
    ) -> SSHJournalRecord | None:
        if entry.get("SYSLOG_IDENTIFIER") != "sshd":
            return None

        cursor = entry.get("__CURSOR")
        raw_timestamp = entry.get("__REALTIME_TIMESTAMP")
        message = entry.get("MESSAGE")

        if not isinstance(cursor, str):
            return None

        if not isinstance(raw_timestamp, str):
            return None

        if not isinstance(message, str):
            return None

        timestamp = cls._timestamp_from_journal(raw_timestamp)

        accepted = cls._ACCEPTED.match(message)

        if accepted:
            evidence = accepted.groupdict()
            evidence["ip"] = cls._normalize_ip(evidence["ip"])

            return SSHJournalRecord(
                cursor=cursor,
                timestamp=timestamp,
                event_type="SSH_AUTH_SUCCESS",
                severity="low",
                description=("Se detectó una autenticación SSH exitosa."),
                evidence=evidence,
            )

        failed = cls._FAILED.match(message)

        if failed:
            evidence = failed.groupdict()
            evidence["ip"] = cls._normalize_ip(evidence["ip"])

            return SSHJournalRecord(
                cursor=cursor,
                timestamp=timestamp,
                event_type="SSH_AUTH_FAILURE",
                severity="medium",
                description=("Se detectó un intento fallido de autenticación SSH."),
                evidence=evidence,
            )

        invalid_user = cls._INVALID_USER.match(message)

        if invalid_user:
            evidence = invalid_user.groupdict()
            evidence["ip"] = cls._normalize_ip(evidence["ip"])

            return SSHJournalRecord(
                cursor=cursor,
                timestamp=timestamp,
                event_type="SSH_INVALID_USER",
                severity="medium",
                description=("Se detectó un intento SSH con un usuario inexistente."),
                evidence=evidence,
            )

        return None

    def latest_cursor(self) -> str | None:
        code, stdout, _ = self._run(
            [
                "journalctl",
                "-u",
                "ssh.service",
                "-n",
                "1",
                "-o",
                "json",
                "--no-pager",
            ]
        )

        if code != 0:
            return None

        line = stdout.strip()

        if not line:
            return None

        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return None

        cursor = entry.get("__CURSOR")

        return cursor if isinstance(cursor, str) else None

    def read_after(
        self,
        cursor: str,
    ) -> SSHJournalBatch:
        code, stdout, stderr = self._run(
            [
                "journalctl",
                "-u",
                "ssh.service",
                "--after-cursor",
                cursor,
                "-o",
                "json",
                "--no-pager",
            ]
        )

        if code != 0:
            raise RuntimeError(f"No se pudo consultar journald: {stderr.strip()}")

        records: list[SSHJournalRecord] = []
        latest_cursor: str | None = None

        for line in stdout.splitlines():
            if not line.strip():
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            entry_cursor = entry.get("__CURSOR")

            if isinstance(entry_cursor, str):
                latest_cursor = entry_cursor

            record = self.parse_entry(entry)

            if record is not None:
                records.append(record)

        return SSHJournalBatch(
            records=records,
            cursor=latest_cursor,
        )
