from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.core.events import SecurityEvent
from app.response.engine import ResponsePolicyEngine
from app.response.policy import ResponsePolicy

BASE_TIME = datetime(
    2026,
    9,
    23,
    5,
    0,
    tzinfo=UTC,
)


def detection_event(
    *,
    event_type: str = "SSH_USER_ENUMERATION_ATTEMPT",
    source_ip: str | None = "192.168.1.50",
    category: str = "detection",
) -> SecurityEvent:
    evidence = {}

    if source_ip is not None:
        evidence["source_ip"] = source_ip

    return SecurityEvent(
        timestamp=BASE_TIME,
        hostname="server-test",
        source="detection-engine",
        category=category,
        event_type=event_type,
        severity="high",
        description="Detección de prueba.",
        evidence=evidence,
    )


@pytest.mark.parametrize(
    "event_type",
    [
        "SSH_USER_ENUMERATION_ATTEMPT",
        "SSH_BRUTE_FORCE_ATTEMPT",
        "SSH_REPEATED_PREAUTH_ACTIVITY",
    ],
)
def test_audit_only_recommends_supported_detections(
    event_type: str,
) -> None:
    engine = ResponsePolicyEngine(ResponsePolicy(mode="audit_only"))

    decision = engine.evaluate(detection_event(event_type=event_type))

    assert decision.action == "RECOMMEND_BLOCK_IP"
    assert decision.target_ip == "192.168.1.50"
    assert decision.executed is False
    assert decision.execution_allowed is False
    assert decision.approval_required is False


def test_ignores_non_detection_events() -> None:
    engine = ResponsePolicyEngine(ResponsePolicy())

    decision = engine.evaluate(
        detection_event(
            category="authentication",
            event_type="SSH_INVALID_USER",
        )
    )

    assert decision.action == "NO_ACTION"
    assert decision.executed is False


def test_ignores_detection_without_source_ip() -> None:
    engine = ResponsePolicyEngine(ResponsePolicy())

    decision = engine.evaluate(detection_event(source_ip=None))

    assert decision.action == "NO_ACTION"


def test_rejects_invalid_source_ip() -> None:
    engine = ResponsePolicyEngine(ResponsePolicy())

    decision = engine.evaluate(
        detection_event(
            source_ip="not-an-ip",
        )
    )

    assert decision.action == "NO_ACTION"


@pytest.mark.parametrize(
    "source_ip",
    [
        "127.0.0.1",
        "::1",
    ],
)
def test_never_blocks_loopback(
    source_ip: str,
) -> None:
    engine = ResponsePolicyEngine(
        ResponsePolicy(
            mode="automatic",
            allow_temporary_ip_block=True,
        )
    )

    decision = engine.evaluate(detection_event(source_ip=source_ip))

    assert decision.action == "NO_ACTION"
    assert decision.target_ip == source_ip
    assert decision.execution_allowed is False
    assert decision.executed is False


def test_never_blocks_trusted_admin_ip() -> None:
    engine = ResponsePolicyEngine(
        ResponsePolicy(
            mode="automatic",
            trusted_admin_ips={
                "192.168.1.25",
            },
            allow_temporary_ip_block=True,
        )
    )

    decision = engine.evaluate(
        detection_event(
            source_ip="192.168.1.25",
        )
    )

    assert decision.action == "NO_ACTION"
    assert decision.target_ip == "192.168.1.25"
    assert decision.execution_allowed is False


def test_assisted_mode_requires_approval() -> None:
    engine = ResponsePolicyEngine(ResponsePolicy(mode="assisted"))

    decision = engine.evaluate(detection_event())

    assert decision.action == "RECOMMEND_BLOCK_IP"
    assert decision.approval_required is True
    assert decision.execution_allowed is False
    assert decision.executed is False


def test_automatic_mode_requires_explicit_authorization() -> None:
    engine = ResponsePolicyEngine(
        ResponsePolicy(
            mode="automatic",
            allow_temporary_ip_block=False,
        )
    )

    decision = engine.evaluate(detection_event())

    assert decision.action == "RECOMMEND_BLOCK_IP"
    assert decision.execution_allowed is False
    assert decision.executed is False


def test_authorized_automatic_mode_proposes_temporary_block() -> None:
    engine = ResponsePolicyEngine(
        ResponsePolicy(
            mode="automatic",
            allow_temporary_ip_block=True,
        )
    )

    decision = engine.evaluate(detection_event())

    assert decision.action == "TEMPORARY_BLOCK_IP"
    assert decision.target_ip == "192.168.1.50"
    assert decision.execution_allowed is True
    assert decision.approval_required is False
    assert decision.duration_seconds == 900
    assert decision.executed is False
