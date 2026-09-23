from datetime import UTC, datetime

from app.detection.ssh_collector import SSHJournalCollector


def entry(message: str) -> dict[str, str]:
    return {
        "__CURSOR": "cursor-test",
        "__REALTIME_TIMESTAMP": "1790132923710159",
        "SYSLOG_IDENTIFIER": "sshd",
        "_PID": "1234",
        "MESSAGE": message,
    }


def test_parses_successful_publickey_login() -> None:
    record = SSHJournalCollector.parse_entry(
        entry(
            "Accepted publickey for auditor from "
            "2800:98:1902:a53:a862:37ca:d7d7:1383 "
            "port 49903 ssh2: ED25519"
        )
    )

    assert record is not None
    assert record.event_type == "SSH_AUTH_SUCCESS"
    assert record.severity == "low"
    assert record.evidence["user"] == "auditor"
    assert record.evidence["method"] == "publickey"
    assert record.evidence["ip"] == "2800:98:1902:a53:a862:37ca:d7d7:1383"
    assert record.evidence["port"] == "49903"


def test_parses_failed_password() -> None:
    record = SSHJournalCollector.parse_entry(
        entry("Failed password for auditor from 192.168.1.50 port 51234 ssh2")
    )

    assert record is not None
    assert record.event_type == "SSH_AUTH_FAILURE"
    assert record.severity == "medium"
    assert record.evidence == {
        "method": "password",
        "user": "auditor",
        "ip": "192.168.1.50",
        "port": "51234",
    }


def test_parses_failed_password_for_invalid_user() -> None:
    record = SSHJournalCollector.parse_entry(
        entry(
            "Failed password for invalid user admin from 192.168.1.99 port 60000 ssh2"
        )
    )

    assert record is not None
    assert record.event_type == "SSH_AUTH_FAILURE"
    assert record.evidence["user"] == "admin"
    assert record.evidence["ip"] == "192.168.1.99"


def test_parses_invalid_user() -> None:
    record = SSHJournalCollector.parse_entry(
        entry("Invalid user root2 from 10.10.10.20 port 45678")
    )

    assert record is not None
    assert record.event_type == "SSH_INVALID_USER"
    assert record.severity == "medium"
    assert record.evidence["user"] == "root2"
    assert record.evidence["ip"] == "10.10.10.20"


def test_ignores_non_authentication_message() -> None:
    record = SSHJournalCollector.parse_entry(
        entry("Server listening on 0.0.0.0 port 22.")
    )

    assert record is None


def test_ignores_non_sshd_entry() -> None:
    data = entry("Started ssh.service - OpenBSD Secure Shell server.")
    data["SYSLOG_IDENTIFIER"] = "systemd"

    assert SSHJournalCollector.parse_entry(data) is None


def test_converts_journal_timestamp_to_utc() -> None:
    record = SSHJournalCollector.parse_entry(
        entry("Accepted publickey for auditor from 192.168.1.10 port 49903 ssh2")
    )

    assert record is not None
    assert record.timestamp.tzinfo == UTC
    assert isinstance(record.timestamp, datetime)


def test_latest_cursor_reads_last_journal_entry(
    monkeypatch,
) -> None:
    collector = SSHJournalCollector()

    payload = '{"__CURSOR":"cursor-123","MESSAGE":"example"}\n'

    monkeypatch.setattr(
        collector,
        "_run",
        lambda command: (0, payload, ""),
    )

    assert collector.latest_cursor() == "cursor-123"


def test_read_after_returns_records_and_latest_cursor(
    monkeypatch,
) -> None:
    collector = SSHJournalCollector()

    payload = "\n".join(
        [
            (
                '{"__CURSOR":"cursor-1",'
                '"__REALTIME_TIMESTAMP":"1790132923710159",'
                '"SYSLOG_IDENTIFIER":"sshd",'
                '"MESSAGE":"Failed password for auditor '
                'from 192.168.1.50 port 50000 ssh2"}'
            ),
            (
                '{"__CURSOR":"cursor-2",'
                '"__REALTIME_TIMESTAMP":"1790132923710160",'
                '"SYSLOG_IDENTIFIER":"sshd",'
                '"MESSAGE":"Server listening on '
                '0.0.0.0 port 22."}'
            ),
        ]
    )

    monkeypatch.setattr(
        collector,
        "_run",
        lambda command: (0, payload, ""),
    )

    batch = collector.read_after("old-cursor")

    assert len(batch.records) == 1
    assert batch.records[0].event_type == "SSH_AUTH_FAILURE"
    assert batch.cursor == "cursor-2"


def test_parses_preauth_connection_closed() -> None:
    record = SSHJournalCollector.parse_entry(
        entry(
            "Connection closed by authenticating user "
            "auditor 127.0.0.1 port 32824 [preauth]"
        )
    )

    assert record is not None
    assert record.event_type == "SSH_PREAUTH_CONNECTION_CLOSED"
    assert record.severity == "low"
    assert record.evidence == {
        "user": "auditor",
        "ip": "127.0.0.1",
        "port": "32824",
    }


def test_ignores_invalid_user_connection_closed() -> None:
    record = SSHJournalCollector.parse_entry(
        entry(
            "Connection closed by invalid user admin 192.168.1.50 port 50000 [preauth]"
        )
    )

    assert record is None
