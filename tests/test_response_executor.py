from __future__ import annotations

from uuid import uuid4

import pytest

from app.response.executor import ResponseExecutor
from app.response.models import ResponseDecision
from app.response.policy import ResponsePolicy


def decision(
    *,
    action: str = "TEMPORARY_BLOCK_IP",
    target_ip: str | None = "192.168.1.50",
    execution_allowed: bool = True,
    duration_seconds: int | None = 900,
) -> ResponseDecision:
    return ResponseDecision(
        detection_event_id=uuid4(),
        hostname="server-test",
        mode="automatic",
        action=action,
        target_ip=target_ip,
        reason="Decisión de prueba.",
        duration_seconds=duration_seconds,
        execution_allowed=execution_allowed,
        executed=False,
    )


def test_executor_skips_no_action() -> None:
    executor = ResponseExecutor(ResponsePolicy())

    result = executor.execute(
        decision(
            action="NO_ACTION",
            execution_allowed=False,
            duration_seconds=None,
        )
    )

    assert result.status == "SKIPPED"
    assert result.executed is False


def test_executor_skips_recommendation() -> None:
    executor = ResponseExecutor(ResponsePolicy())

    result = executor.execute(
        decision(
            action="RECOMMEND_BLOCK_IP",
            execution_allowed=False,
            duration_seconds=None,
        )
    )

    assert result.status == "SKIPPED"
    assert result.executed is False


def test_executor_requires_execution_authorization() -> None:
    executor = ResponseExecutor(ResponsePolicy())

    result = executor.execute(decision(execution_allowed=False))

    assert result.status == "SKIPPED"
    assert result.executed is False


def test_executor_dry_run_validates_temporary_block() -> None:
    policy = ResponsePolicy(
        mode="automatic",
        allow_temporary_ip_block=True,
    )

    executor = ResponseExecutor(policy)

    result = executor.execute(decision())

    assert result.status == "DRY_RUN"
    assert result.target_ip == "192.168.1.50"
    assert result.duration_seconds == 900
    assert result.dry_run is True
    assert result.executed is False


@pytest.mark.parametrize(
    "source_ip",
    [
        "127.0.0.1",
        "::1",
    ],
)
def test_executor_rejects_protected_addresses(
    source_ip: str,
) -> None:
    policy = ResponsePolicy(
        mode="automatic",
        allow_temporary_ip_block=True,
    )

    executor = ResponseExecutor(policy)

    result = executor.execute(decision(target_ip=source_ip))

    assert result.status == "SKIPPED"
    assert result.executed is False


def test_executor_rechecks_trusted_admin_ip() -> None:
    policy = ResponsePolicy(
        mode="automatic",
        trusted_admin_ips={"192.168.1.25"},
        allow_temporary_ip_block=True,
    )

    executor = ResponseExecutor(policy)

    result = executor.execute(decision(target_ip="192.168.1.25"))

    assert result.status == "SKIPPED"
    assert result.executed is False


def test_executor_rejects_real_execution_mode() -> None:
    with pytest.raises(
        ValueError,
        match="todavía no está implementada",
    ):
        ResponseExecutor(
            ResponsePolicy(),
            dry_run=False,
        )
