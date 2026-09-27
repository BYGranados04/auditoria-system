import sqlite3
from datetime import UTC, datetime
from uuid import uuid4

from app.core.events import SecurityEvent
from app.notifications.config import NotificationSettings
from app.notifications.models import ProviderResult
from app.notifications.repository import NotificationRepository
from app.notifications.service import NotificationService


class FakeProvider:
    name = "resend"

    def __init__(self, *, fails: bool = False) -> None:
        self.fails = fails
        self.calls = 0

    def send(self, _message):
        self.calls += 1
        if self.fails:
            raise RuntimeError("Bearer secret-api-key failed")
        return ProviderResult(provider_message_id="email_123")


def event(
    severity="high",
    *,
    category="detection",
    source="test",
    event_type="SSH_BRUTE_FORCE_ATTEMPT",
):
    return SecurityEvent(
        event_id=uuid4(),
        timestamp=datetime.now(UTC),
        hostname="server-a",
        source=source,
        category=category,
        event_type=event_type,
        severity=severity,
        description="Intentos fallidos.",
        evidence={"source_ip": "192.0.2.1"},
    )


def service(tmp_path, *, enabled=True, minimum="high", fails=False):
    provider = FakeProvider(fails=fails)
    result = NotificationService(
        settings=NotificationSettings(
            enabled=enabled,
            min_severity=minimum,
            resend_api_key="test-key",
            sender="from@example.test",
            recipient="to@example.test",
        ),
        repository=NotificationRepository(tmp_path / "notifications.db"),
        provider=provider,
    )
    return result, provider


def test_disabled_does_not_send(tmp_path):
    notifications, provider = service(tmp_path, enabled=False)
    assert notifications.notify(event()) is None
    assert provider.calls == 0


def test_high_and_critical_are_sent(tmp_path):
    notifications, provider = service(tmp_path)
    assert notifications.notify(event("high")).status == "sent"
    assert notifications.notify(event("critical")).status == "sent"
    assert provider.calls == 2


def test_only_security_detections_matching_severity_are_sent(tmp_path):
    notifications, provider = service(tmp_path)
    assert notifications.notify(event("high", category="system")) is None
    assert notifications.notify(event("high", category="response")) is None
    assert (
        notifications.notify(event("critical", category="detection")).status == "sent"
    )
    assert provider.calls == 1


def test_low_and_medium_below_minimum_do_not_send(tmp_path):
    notifications, provider = service(tmp_path)
    assert notifications.notify(event("low")) is None
    assert notifications.notify(event("medium")) is None
    assert provider.calls == 0


def test_failure_is_persisted_and_sanitized(tmp_path):
    notifications, provider = service(tmp_path, fails=True)
    attempt = notifications.notify(event())
    assert attempt.status == "failed"
    assert "secret-api-key" not in attempt.error
    assert provider.calls == 1


def test_pending_is_deduplicated(tmp_path):
    notifications, provider = service(tmp_path)
    security_event = event()
    first = notifications.notify(security_event)
    second = notifications.notify(security_event)
    assert first.id == second.id
    assert provider.calls == 1
    assert len(notifications.repository.list()) == 1


def test_incomplete_configuration_fails_without_provider_call(tmp_path):
    provider = FakeProvider()
    notifications = NotificationService(
        settings=NotificationSettings(enabled=True, recipient="to@example.test"),
        repository=NotificationRepository(tmp_path / "notifications.db"),
        provider=provider,
    )
    attempt = notifications.notify(event())
    assert attempt.status == "failed"
    assert provider.calls == 0


def test_summary_is_exact_beyond_one_thousand_records(tmp_path):
    repository = NotificationRepository(tmp_path / "notifications.db")
    repository.initialize()
    rows = []
    for index in range(1_005):
        hostname = "host-a" if index < 1_001 else "host-b"
        status = ("sent", "failed", "pending")[index % 3]
        severity = "critical" if index % 5 == 0 else "high"
        rows.append(
            (
                f"event-{index}",
                "email",
                "resend",
                f"recipient-{index}@example.test",
                hostname,
                severity,
                status,
                "2026-01-01T00:00:00+00:00",
            )
        )
    with sqlite3.connect(repository.database_path) as connection:
        connection.executemany(
            "INSERT INTO notifications (event_id, channel, provider, recipient, "
            "hostname, severity, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )

    summary = repository.summary()
    scoped = repository.summary(hostnames=("host-a",))

    assert summary == {
        "total": 1_005,
        "pending": 335,
        "sent": 335,
        "failed": 335,
        "high": 804,
        "critical": 201,
    }
    assert scoped["total"] == 1_001
