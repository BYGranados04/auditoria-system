from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.core.config import load_agent_settings
from app.core.events import SecurityEvent
from app.response.engine import ResponsePolicyEngine
from app.response.policy import ResponsePolicy
from app.response.recurrence import RecurrenceTracker
from app.storage.event_repository import EventRepository

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)
SOURCE = "192.168.1.50"


def policy(**overrides: object) -> ResponsePolicy:
    values: dict[str, object] = {
        "mode": "automatic",
        "allow_temporary_ip_block": True,
        "escalation_enabled": True,
        "escalation_seconds": (120, 600, 3600),
        "escalation_window_seconds": 86400,
    }
    values.update(overrides)
    return ResponsePolicy(**values)  # type: ignore[arg-type]


def repository(tmp_path: Path) -> EventRepository:
    repo = EventRepository(tmp_path / "auditoria.db")
    repo.initialize()
    return repo


def offend(
    tracker: RecurrenceTracker,
    at: datetime,
    *,
    source_ip: str = SOURCE,
):
    detection_id = str(uuid4())
    assessment = tracker.assess(
        hostname="server-test",
        source_ip=source_ip,
        detection_event_id=detection_id,
        now=at,
    )
    tracker.record(
        hostname="server-test",
        source_ip=source_ip,
        detection_event_id=detection_id,
        detection_type="SSH_BRUTE_FORCE_ATTEMPT",
        incident_id=None,
        occurred_at=at,
        assessment=assessment,
    )
    return assessment


def detection(at: datetime, source_ip: str = SOURCE) -> SecurityEvent:
    return SecurityEvent(
        timestamp=at,
        hostname="server-test",
        source="detection-engine",
        category="detection",
        event_type="SSH_BRUTE_FORCE_ATTEMPT",
        severity="high",
        description="Fuerza bruta",
        evidence={"source_ip": source_ip},
    )


def test_first_second_and_third_offense_escalate(tmp_path: Path) -> None:
    tracker = RecurrenceTracker(repository(tmp_path), policy())

    first = offend(tracker, NOW)
    second = offend(tracker, NOW + timedelta(minutes=5))
    third = offend(tracker, NOW + timedelta(minutes=20))

    assert (first.recurrence_level, first.previous_incidents) == (1, 0)
    assert first.selected_duration_seconds == 120
    assert (second.recurrence_level, second.previous_incidents) == (2, 1)
    assert second.selected_duration_seconds == 600
    assert (third.recurrence_level, third.previous_incidents) == (3, 2)
    assert third.selected_duration_seconds == 3600


def test_level_is_capped_and_never_infinite(tmp_path: Path) -> None:
    tracker = RecurrenceTracker(repository(tmp_path), policy())

    assessments = [
        offend(tracker, NOW + timedelta(minutes=index)) for index in range(6)
    ]

    assert [item.recurrence_level for item in assessments] == [1, 2, 3, 3, 3, 3]
    assert assessments[-1].previous_incidents == 5
    assert assessments[-1].selected_duration_seconds == 3600
    assert assessments[-1].capped is True


def test_expired_window_returns_to_initial_level(tmp_path: Path) -> None:
    tracker = RecurrenceTracker(
        repository(tmp_path),
        policy(escalation_window_seconds=3600),
    )

    offend(tracker, NOW)
    offend(tracker, NOW + timedelta(minutes=10))
    # La primera ofensa ya salió de la ventana deslizante; la segunda no.
    after_window = offend(tracker, NOW + timedelta(seconds=3601))

    assert after_window.recurrence_level == 2
    assert after_window.previous_incidents == 1

    reset = offend(tracker, NOW + timedelta(hours=5))
    assert reset.recurrence_level == 1
    assert reset.selected_duration_seconds == 120


def test_recurrence_survives_agent_restart(tmp_path: Path) -> None:
    first_process = RecurrenceTracker(repository(tmp_path), policy())
    offend(first_process, NOW)
    offend(first_process, NOW + timedelta(minutes=1))

    restarted = RecurrenceTracker(
        EventRepository(tmp_path / "auditoria.db"),
        policy(),
    )
    after_restart = offend(restarted, NOW + timedelta(minutes=2))

    assert after_restart.recurrence_level == 3
    assert after_restart.selected_duration_seconds == 3600


def test_recurrence_is_tracked_per_source_ip(tmp_path: Path) -> None:
    tracker = RecurrenceTracker(repository(tmp_path), policy())

    offend(tracker, NOW)
    offend(tracker, NOW + timedelta(minutes=1))
    other = offend(tracker, NOW + timedelta(minutes=2), source_ip="192.168.1.51")

    assert other.recurrence_level == 1


def test_same_detection_is_not_counted_twice(tmp_path: Path) -> None:
    repo = repository(tmp_path)
    tracker = RecurrenceTracker(repo, policy())
    detection_id = str(uuid4())
    assessment = tracker.assess(
        hostname="server-test",
        source_ip=SOURCE,
        detection_event_id=detection_id,
        now=NOW,
    )
    arguments = {
        "hostname": "server-test",
        "source_ip": SOURCE,
        "detection_event_id": detection_id,
        "detection_type": "SSH_BRUTE_FORCE_ATTEMPT",
        "incident_id": None,
        "occurred_at": NOW,
        "assessment": assessment,
    }

    assert tracker.record(**arguments) is True
    assert tracker.record(**arguments) is False
    again = tracker.assess(
        hostname="server-test",
        source_ip=SOURCE,
        detection_event_id=detection_id,
        now=NOW,
    )
    assert again.recurrence_level == 1


def test_engine_uses_escalated_duration_and_records_fields(tmp_path: Path) -> None:
    current = policy()
    tracker = RecurrenceTracker(repository(tmp_path), current)
    offend(tracker, NOW)
    assessment = tracker.assess(
        hostname="server-test",
        source_ip=SOURCE,
        detection_event_id=str(uuid4()),
        now=NOW + timedelta(minutes=3),
    )

    decision = ResponsePolicyEngine(current).evaluate(
        detection(NOW + timedelta(minutes=3)),
        recurrence=assessment,
    )

    assert decision.action == "TEMPORARY_BLOCK_IP"
    assert decision.duration_seconds == 600
    assert decision.recurrence_level == 2
    assert decision.previous_incidents == 1
    assert decision.selected_duration_seconds == 600
    assert "Reincidencia nivel 2/3" in decision.reason


def test_disabled_escalation_keeps_legacy_duration(tmp_path: Path) -> None:
    current = policy(escalation_enabled=False, temporary_block_seconds=900)
    tracker = RecurrenceTracker(repository(tmp_path), current)
    offend(tracker, NOW)
    assessment = tracker.assess(
        hostname="server-test",
        source_ip=SOURCE,
        detection_event_id=str(uuid4()),
        now=NOW + timedelta(minutes=1),
    )

    decision = ResponsePolicyEngine(current).evaluate(
        detection(NOW + timedelta(minutes=1)),
        recurrence=assessment,
    )

    assert decision.duration_seconds == 900
    assert decision.recurrence_level == 2
    assert decision.reason == (
        "La actividad cumple una política de respuesta automática autorizada."
    )


@pytest.mark.parametrize("source_ip", ["127.0.0.1", "::1", "fe80::1"])
def test_non_routable_addresses_keep_legacy_no_action(
    tmp_path: Path,
    source_ip: str,
) -> None:
    current = policy(trusted_admin_ips={"198.51.100.1"})
    tracker = RecurrenceTracker(repository(tmp_path), current)
    assessment = tracker.assess(
        hostname="server-test",
        source_ip=source_ip,
        detection_event_id=str(uuid4()),
        now=NOW,
    )

    decision = ResponsePolicyEngine(current).evaluate(
        detection(NOW, source_ip),
        recurrence=assessment,
    )

    assert decision.action == "NO_ACTION"
    assert decision.recurrence_level is None
    assert decision.duration_seconds is None


def test_trusted_admin_is_not_escalated(tmp_path: Path) -> None:
    current = policy(trusted_admin_ips={"198.51.100.1"})
    decision = ResponsePolicyEngine(current).evaluate(
        detection(NOW, "198.51.100.1"),
        recurrence=RecurrenceTracker(repository(tmp_path), current).assess(
            hostname="server-test",
            source_ip="198.51.100.1",
            detection_event_id=str(uuid4()),
            now=NOW,
        ),
    )

    assert decision.action == "NO_ACTION"
    assert decision.recurrence_level is None


@pytest.mark.parametrize(
    "levels",
    [(), (30,), (120, 90000), (600, 120), tuple(range(60, 60 + 11 * 60, 60))],
)
def test_policy_rejects_invalid_escalation_levels(levels: tuple[int, ...]) -> None:
    with pytest.raises(ValidationError):
        policy(escalation_seconds=levels)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, (120, 600, 3600)),
        ("120,600,3600,86400", (120, 600, 3600, 86400)),
        ("300", (300,)),
        ("120,abc", (120, 600, 3600)),
        ("120,999999", (120, 600, 3600)),
        ("600,120", (120, 600, 3600)),
        ("", (120, 600, 3600)),
    ],
)
def test_escalation_configuration_falls_back_to_safe_defaults(
    monkeypatch: pytest.MonkeyPatch,
    raw: str | None,
    expected: tuple[int, ...],
) -> None:
    if raw is None:
        monkeypatch.delenv("AUDITORIA_RESPONSE_ESCALATION_SECONDS", raising=False)
    else:
        monkeypatch.setenv("AUDITORIA_RESPONSE_ESCALATION_SECONDS", raw)

    settings = load_agent_settings()

    assert settings.response_escalation_seconds == expected
