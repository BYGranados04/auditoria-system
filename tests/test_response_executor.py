from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.response.executor import ResponseExecutor
from app.response.models import ResponseDecision
from app.response.policy import ResponsePolicy
from app.storage.event_repository import EventRepository


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


class FakeProtectionResolver:
    def __init__(
        self,
        protected_ips: set[str] | None = None,
    ) -> None:
        self.protected_ips = protected_ips or set()

    def resolve(self):
        return SimpleNamespace(protected_ips=set(self.protected_ips))


class FakeFirewallBackend:
    def __init__(
        self,
        *,
        fail_add: bool = False,
    ) -> None:
        self.fail_add = fail_add
        self.prepare_calls = 0
        self.added = []
        self.removed = []

    def prepare(self) -> bool:
        self.prepare_calls += 1
        return True

    def add_temporary_block(
        self,
        plan,
    ) -> None:
        if self.fail_add:
            raise RuntimeError("fallo simulado de nftables")

        self.added.append(plan)

    def remove_block(
        self,
        plan,
    ) -> None:
        self.removed.append(plan)


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
    assert result.block_id is None


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
        trusted_admin_ips={
            "192.168.1.25",
        },
        allow_temporary_ip_block=True,
    )

    executor = ResponseExecutor(policy)

    result = executor.execute(decision(target_ip="192.168.1.25"))

    assert result.status == "SKIPPED"
    assert result.executed is False


def test_real_executor_requires_repository() -> None:
    policy = ResponsePolicy(
        mode="automatic",
        allow_temporary_ip_block=True,
    )

    with pytest.raises(
        ValueError,
        match="repositorio",
    ):
        ResponseExecutor(
            policy,
            dry_run=False,
        )


def test_real_executor_applies_and_persists_block(
    tmp_path: Path,
) -> None:
    repository = EventRepository(tmp_path / "auditoria.db")
    repository.initialize()

    backend = FakeFirewallBackend()

    now = datetime(
        2026,
        9,
        24,
        5,
        0,
        tzinfo=UTC,
    )

    executor = ResponseExecutor(
        ResponsePolicy(
            mode="automatic",
            allow_temporary_ip_block=True,
        ),
        dry_run=False,
        repository=repository,
        backend=backend,  # type: ignore[arg-type]
        protection_resolver=(FakeProtectionResolver()),  # type: ignore[arg-type]
        clock=lambda: now,
    )

    response_event_id = uuid4()
    execution_event_id = uuid4()

    result = executor.execute(
        decision(),
        response_event_id=response_event_id,
        execution_event_id=execution_event_id,
    )

    assert result.status == "EXECUTED"
    assert result.executed is True
    assert result.dry_run is False
    assert result.block_id is not None

    assert backend.prepare_calls == 1
    assert len(backend.added) == 1

    block = repository.get_response_block(str(result.block_id))

    assert block is not None
    assert block["status"] == "ACTIVE"
    assert block["response_event_id"] == str(response_event_id)
    assert block["execution_event_id"] == str(execution_event_id)
    assert block["target_ip"] == "192.168.1.50"


def test_real_executor_rechecks_dynamic_protection(
    tmp_path: Path,
) -> None:
    repository = EventRepository(tmp_path / "auditoria.db")
    repository.initialize()

    backend = FakeFirewallBackend()

    executor = ResponseExecutor(
        ResponsePolicy(
            mode="automatic",
            allow_temporary_ip_block=True,
        ),
        dry_run=False,
        repository=repository,
        backend=backend,  # type: ignore[arg-type]
        protection_resolver=(
            FakeProtectionResolver(
                {
                    "192.168.1.50",
                }
            )
        ),  # type: ignore[arg-type]
    )

    result = executor.execute(
        decision(),
        response_event_id=uuid4(),
        execution_event_id=uuid4(),
    )

    assert result.status == "SKIPPED"
    assert result.executed is False
    assert result.block_id is None
    assert backend.prepare_calls == 0
    assert backend.added == []


def test_real_executor_marks_failed_when_backend_fails(
    tmp_path: Path,
) -> None:
    repository = EventRepository(tmp_path / "auditoria.db")
    repository.initialize()

    backend = FakeFirewallBackend(fail_add=True)

    now = datetime(
        2026,
        9,
        24,
        5,
        30,
        tzinfo=UTC,
    )

    executor = ResponseExecutor(
        ResponsePolicy(
            mode="automatic",
            allow_temporary_ip_block=True,
        ),
        dry_run=False,
        repository=repository,
        backend=backend,  # type: ignore[arg-type]
        protection_resolver=(FakeProtectionResolver()),  # type: ignore[arg-type]
        clock=lambda: now,
    )

    result = executor.execute(
        decision(),
        response_event_id=uuid4(),
        execution_event_id=uuid4(),
    )

    assert result.status == "FAILED"
    assert result.executed is False
    assert result.block_id is not None

    block = repository.get_response_block(str(result.block_id))

    assert block is not None
    assert block["status"] == "FAILED"
    assert "fallo simulado de nftables" in block["last_error"]


def test_real_executor_requires_correlation_ids(
    tmp_path: Path,
) -> None:
    repository = EventRepository(tmp_path / "auditoria.db")
    repository.initialize()

    backend = FakeFirewallBackend()

    executor = ResponseExecutor(
        ResponsePolicy(
            mode="automatic",
            allow_temporary_ip_block=True,
        ),
        dry_run=False,
        repository=repository,
        backend=backend,  # type: ignore[arg-type]
        protection_resolver=(FakeProtectionResolver()),  # type: ignore[arg-type]
    )

    result = executor.execute(decision())

    assert result.status == "FAILED"
    assert result.executed is False
    assert backend.prepare_calls == 0
