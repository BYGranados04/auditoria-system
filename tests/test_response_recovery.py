from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.response.firewall import (
    NftablesFirewallPlanner,
    TemporaryBlockPlan,
)
from app.response.recovery import (
    ResponseRecoveryManager,
)
from app.storage.event_repository import EventRepository


class FakeFirewallBackend:
    def __init__(
        self,
        *,
        table_created: bool = True,
        fail_targets: set[str] | None = None,
    ) -> None:
        self.table_created = table_created
        self.fail_targets = fail_targets or set()
        self.prepare_calls = 0
        self.added: list[TemporaryBlockPlan] = []

    def prepare(self) -> bool:
        self.prepare_calls += 1
        return self.table_created

    def add_temporary_block(
        self,
        plan: TemporaryBlockPlan,
    ) -> None:
        if plan.target_ip in self.fail_targets:
            raise RuntimeError("fallo simulado de nftables")

        self.added.append(plan)


def repository(
    tmp_path: Path,
) -> EventRepository:
    repo = EventRepository(tmp_path / "auditoria.db")
    repo.initialize()
    return repo


def create_block(
    repo: EventRepository,
    *,
    block_id: str,
    target_ip: str,
    now: datetime,
    expires_at: datetime,
    active: bool,
) -> None:
    repo.create_response_block(
        block_id=block_id,
        detection_event_id=f"detection-{block_id}",
        response_event_id=f"response-{block_id}",
        hostname="auditoria-server",
        target_ip=target_ip,
        family="ip",
        duration_seconds=60,
        requested_at=now - timedelta(seconds=33),
        expires_at=expires_at,
    )

    if active:
        repo.mark_response_block_active(
            block_id,
            execution_event_id=f"execution-{block_id}",
            applied_at=now - timedelta(seconds=33),
        )


def test_recovers_active_block_with_remaining_timeout(
    tmp_path: Path,
) -> None:
    repo = repository(tmp_path)

    now = datetime(
        2026,
        9,
        24,
        3,
        0,
        tzinfo=UTC,
    )

    create_block(
        repo,
        block_id="active-short",
        target_ip="198.51.100.77",
        now=now,
        expires_at=now + timedelta(seconds=27),
        active=True,
    )

    backend = FakeFirewallBackend()

    manager = ResponseRecoveryManager(
        repository=repo,
        backend=backend,  # type: ignore[arg-type]
        planner=NftablesFirewallPlanner(),
    )

    summary = manager.recover(
        now=now,
    )

    assert summary.table_created is True
    assert summary.expired_count == 0
    assert summary.failed_pending_count == 0
    assert summary.restored_count == 1
    assert summary.failed_restore_count == 0

    assert backend.prepare_calls == 1
    assert len(backend.added) == 1

    restored = backend.added[0]

    assert restored.target_ip == "198.51.100.77"
    assert restored.duration_seconds == 27


def test_recovery_expires_old_and_fails_pending(
    tmp_path: Path,
) -> None:
    repo = repository(tmp_path)

    now = datetime(
        2026,
        9,
        24,
        3,
        10,
        tzinfo=UTC,
    )

    create_block(
        repo,
        block_id="expired-pending",
        target_ip="198.51.100.80",
        now=now,
        expires_at=now - timedelta(seconds=1),
        active=False,
    )

    create_block(
        repo,
        block_id="live-pending",
        target_ip="198.51.100.81",
        now=now,
        expires_at=now + timedelta(seconds=60),
        active=False,
    )

    backend = FakeFirewallBackend()

    manager = ResponseRecoveryManager(
        repository=repo,
        backend=backend,  # type: ignore[arg-type]
        planner=NftablesFirewallPlanner(),
    )

    summary = manager.recover(
        now=now,
    )

    assert summary.expired_count == 1
    assert summary.failed_pending_count == 1
    assert summary.restored_count == 0

    expired = repo.get_response_block("expired-pending")
    pending = repo.get_response_block("live-pending")

    assert expired is not None
    assert pending is not None

    assert expired["status"] == "EXPIRED"
    assert pending["status"] == "FAILED"


def test_recovery_marks_failed_when_firewall_rejects(
    tmp_path: Path,
) -> None:
    repo = repository(tmp_path)

    now = datetime(
        2026,
        9,
        24,
        3,
        20,
        tzinfo=UTC,
    )

    create_block(
        repo,
        block_id="active-failure",
        target_ip="198.51.100.90",
        now=now,
        expires_at=now + timedelta(seconds=60),
        active=True,
    )

    backend = FakeFirewallBackend(
        fail_targets={
            "198.51.100.90",
        }
    )

    manager = ResponseRecoveryManager(
        repository=repo,
        backend=backend,  # type: ignore[arg-type]
        planner=NftablesFirewallPlanner(),
    )

    summary = manager.recover(
        now=now,
    )

    assert summary.restored_count == 0
    assert summary.failed_restore_count == 1

    block = repo.get_response_block("active-failure")

    assert block is not None
    assert block["status"] == "FAILED"
    assert "fallo simulado de nftables" in block["last_error"]
