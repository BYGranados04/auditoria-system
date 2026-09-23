from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.core.events import SecurityEvent
from app.detection.ssh_correlation import SSHCorrelationEngine
from app.storage.event_repository import EventRepository

BASE_TIME = datetime(
    2026,
    9,
    23,
    5,
    0,
    tzinfo=UTC,
)


def repository(tmp_path: Path) -> EventRepository:
    repo = EventRepository(tmp_path / "auditoria.db")
    repo.initialize()
    return repo


def ssh_event(
    *,
    event_type: str,
    timestamp: datetime,
    ip: str = "192.168.1.50",
    user: str = "auditor",
) -> SecurityEvent:
    return SecurityEvent(
        timestamp=timestamp,
        hostname="server-test",
        source="continuous-agent",
        category="authentication",
        event_type=event_type,
        severity="medium",
        description="Evento SSH de prueba",
        evidence={
            "ip": ip,
            "user": user,
            "method": "publickey",
            "port": "50000",
        },
    )


def test_does_not_detect_brute_force_below_threshold(
    tmp_path: Path,
) -> None:
    repo = repository(tmp_path)
    engine = SSHCorrelationEngine(repo)

    last_event = None

    for index in range(9):
        last_event = ssh_event(
            event_type="SSH_AUTH_FAILURE",
            timestamp=BASE_TIME + timedelta(seconds=index),
        )
        repo.add(last_event)

    assert last_event is not None
    assert engine.analyze(last_event) == []


def test_detects_ssh_brute_force(
    tmp_path: Path,
) -> None:
    repo = repository(tmp_path)
    engine = SSHCorrelationEngine(repo)

    last_event = None

    for index in range(10):
        last_event = ssh_event(
            event_type="SSH_AUTH_FAILURE",
            timestamp=BASE_TIME + timedelta(seconds=index),
        )
        repo.add(last_event)

    assert last_event is not None

    detections = engine.analyze(last_event)

    assert len(detections) == 1

    detection = detections[0]

    assert detection.event_type == "SSH_BRUTE_FORCE_ATTEMPT"
    assert detection.severity == "high"
    assert detection.evidence["attempt_count"] == 10
    assert detection.evidence["source_ip"] == "192.168.1.50"


def test_brute_force_separates_source_ips(
    tmp_path: Path,
) -> None:
    repo = repository(tmp_path)
    engine = SSHCorrelationEngine(repo)

    last_event = None

    for index in range(5):
        first = ssh_event(
            event_type="SSH_AUTH_FAILURE",
            timestamp=BASE_TIME + timedelta(seconds=index),
            ip="192.168.1.10",
        )
        second = ssh_event(
            event_type="SSH_AUTH_FAILURE",
            timestamp=BASE_TIME + timedelta(seconds=index),
            ip="192.168.1.20",
        )

        repo.add(first)
        repo.add(second)
        last_event = second

    assert last_event is not None
    assert engine.analyze(last_event) == []


def test_brute_force_respects_time_window(
    tmp_path: Path,
) -> None:
    repo = repository(tmp_path)
    engine = SSHCorrelationEngine(repo)

    for index in range(9):
        repo.add(
            ssh_event(
                event_type="SSH_AUTH_FAILURE",
                timestamp=BASE_TIME + timedelta(seconds=index),
            )
        )

    last_event = ssh_event(
        event_type="SSH_AUTH_FAILURE",
        timestamp=BASE_TIME + timedelta(seconds=120),
    )
    repo.add(last_event)

    assert engine.analyze(last_event) == []


def test_detects_user_enumeration(
    tmp_path: Path,
) -> None:
    repo = repository(tmp_path)
    engine = SSHCorrelationEngine(repo)

    last_event = None

    for index in range(5):
        last_event = ssh_event(
            event_type="SSH_INVALID_USER",
            timestamp=BASE_TIME + timedelta(seconds=index),
            user=f"usuario-{index}",
        )
        repo.add(last_event)

    assert last_event is not None

    detections = engine.analyze(last_event)

    assert len(detections) == 1

    detection = detections[0]

    assert detection.event_type == "SSH_USER_ENUMERATION_ATTEMPT"
    assert detection.severity == "high"
    assert detection.evidence["distinct_user_count"] == 5


def test_user_enumeration_requires_distinct_users(
    tmp_path: Path,
) -> None:
    repo = repository(tmp_path)
    engine = SSHCorrelationEngine(repo)

    last_event = None

    for index in range(8):
        last_event = ssh_event(
            event_type="SSH_INVALID_USER",
            timestamp=BASE_TIME + timedelta(seconds=index),
            user="mismo-usuario",
        )
        repo.add(last_event)

    assert last_event is not None
    assert engine.analyze(last_event) == []


def test_does_not_duplicate_recent_detection(
    tmp_path: Path,
) -> None:
    repo = repository(tmp_path)
    engine = SSHCorrelationEngine(repo)

    last_event = None

    for index in range(10):
        last_event = ssh_event(
            event_type="SSH_AUTH_FAILURE",
            timestamp=BASE_TIME + timedelta(seconds=index),
        )
        repo.add(last_event)

    assert last_event is not None

    first_detection = engine.analyze(last_event)

    assert len(first_detection) == 1

    detection_event = SecurityEvent(
        timestamp=last_event.timestamp,
        hostname="server-test",
        source="detection-engine",
        category="detection",
        event_type=(first_detection[0].event_type),
        severity="high",
        description=(first_detection[0].description),
        evidence=first_detection[0].evidence,
    )

    repo.add(detection_event)

    extra = ssh_event(
        event_type="SSH_AUTH_FAILURE",
        timestamp=BASE_TIME + timedelta(seconds=10),
    )
    repo.add(extra)

    assert engine.analyze(extra) == []
