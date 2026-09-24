from pathlib import Path

from app.agent.continuous_agent import ContinuousAgent
from app.core.config import AgentSettings
from app.response.models import ResponseExecutionResult


class CapturingExecutor:
    def __init__(self) -> None:
        self.response_event_id = None
        self.execution_event_id = None

    def execute(
        self,
        decision,
        *,
        response_event_id=None,
        execution_event_id=None,
    ):
        self.response_event_id = response_event_id
        self.execution_event_id = execution_event_id

        return ResponseExecutionResult(
            detection_event_id=(decision.detection_event_id),
            action=decision.action,
            target_ip=decision.target_ip,
            duration_seconds=(decision.duration_seconds),
            status="DRY_RUN",
            dry_run=True,
            executed=False,
            reason="Prueba de correlación.",
        )


def test_response_execution_uses_preassigned_event_id(
    tmp_path: Path,
) -> None:
    settings = AgentSettings(
        interval=1,
        state_dir=tmp_path / "state",
        log_dir=tmp_path / "logs",
    )

    agent = ContinuousAgent(
        interval=1,
        settings=settings,
    )

    detection_event = agent.emit(
        category="detection",
        event_type="TEST_DETECTION",
        severity="high",
        description="Detección de prueba.",
        evidence={
            "source_ip": "192.0.2.50",
        },
        source="detection-engine",
    )

    response_event = agent.emit(
        category="response",
        event_type="RESPONSE_DECISION",
        severity="low",
        description="Decisión de prueba.",
        evidence={
            "detection_event_id": str(detection_event.event_id),
            "hostname": agent.hostname,
            "mode": "automatic",
            "action": "TEMPORARY_BLOCK_IP",
            "target_ip": "192.0.2.50",
            "reason": "Prueba.",
            "duration_seconds": 900,
            "approval_required": False,
            "execution_allowed": True,
            "executed": False,
        },
        source="response-engine",
    )

    executor = CapturingExecutor()
    agent.response_executor = executor

    execution_event = agent._emit_response_execution(response_event)

    assert executor.response_event_id == response_event.event_id

    assert executor.execution_event_id == execution_event.event_id

    assert execution_event.evidence["response_event_id"] == str(response_event.event_id)


def test_agent_uses_dry_run_in_audit_only(
    tmp_path: Path,
) -> None:
    settings = AgentSettings(
        interval=1,
        state_dir=tmp_path / "state",
        log_dir=tmp_path / "logs",
        response_mode="audit_only",
        allow_temporary_ip_block=False,
    )

    agent = ContinuousAgent(
        interval=1,
        settings=settings,
    )

    assert agent.response_executor.dry_run is True


def test_agent_uses_dry_run_when_automatic_not_allowed(
    tmp_path: Path,
) -> None:
    settings = AgentSettings(
        interval=1,
        state_dir=tmp_path / "state",
        log_dir=tmp_path / "logs",
        response_mode="automatic",
        allow_temporary_ip_block=False,
    )

    agent = ContinuousAgent(
        interval=1,
        settings=settings,
    )

    assert agent.response_executor.dry_run is True


def test_agent_builds_real_executor_only_when_authorized(
    tmp_path: Path,
) -> None:
    settings = AgentSettings(
        interval=1,
        state_dir=tmp_path / "state",
        log_dir=tmp_path / "logs",
        response_mode="automatic",
        allow_temporary_ip_block=True,
        trusted_admin_ips=("192.0.2.10",),
    )

    agent = ContinuousAgent(
        interval=1,
        settings=settings,
    )

    executor = agent.response_executor

    assert executor.dry_run is False
    assert executor.repository is not None
    assert executor.backend is not None
    assert executor.protection_resolver is not None


def test_ssh_detection_reaches_real_executor_with_fake_firewall(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from datetime import UTC, datetime
    from types import SimpleNamespace

    from app.detection.ssh_collector import (
        SSHJournalBatch,
        SSHJournalRecord,
    )
    from app.response.executor import ResponseExecutor
    from app.storage.event_repository import (
        EventRepository,
    )

    class FakeFirewallBackend:
        def __init__(self) -> None:
            self.prepare_calls = 0
            self.added = []

        def prepare(self) -> bool:
            self.prepare_calls += 1
            return True

        def add_temporary_block(
            self,
            plan,
        ) -> None:
            self.added.append(plan)

        def remove_block(
            self,
            plan,
        ) -> None:
            raise AssertionError("No se esperaba rollback.")

    class FakeProtectionResolver:
        def resolve(self):
            return SimpleNamespace(protected_ips=set())

    settings = AgentSettings(
        interval=1,
        state_dir=tmp_path / "state",
        log_dir=tmp_path / "logs",
        response_mode="automatic",
        allow_temporary_ip_block=True,
        temporary_block_seconds=900,
    )

    agent = ContinuousAgent(
        interval=1,
        settings=settings,
    )

    repository = EventRepository(settings.database_file)
    repository.initialize()

    backend = FakeFirewallBackend()

    agent.response_executor = ResponseExecutor(
        agent.response_policy,
        dry_run=False,
        repository=repository,
        backend=backend,  # type: ignore[arg-type]
        protection_resolver=(FakeProtectionResolver()),  # type: ignore[arg-type]
    )

    previous = {
        "ssh_journal_cursor": "cursor-before",
    }
    current = {}

    records = []

    for index in range(5):
        records.append(
            SSHJournalRecord(
                cursor=f"cursor-real-{index}",
                timestamp=datetime(
                    2026,
                    9,
                    24,
                    5,
                    0,
                    index,
                    tzinfo=UTC,
                ),
                event_type="SSH_INVALID_USER",
                severity="medium",
                description=("Usuario SSH inexistente."),
                evidence={
                    "user": f"real-{index}",
                    "ip": "192.0.2.50",
                    "port": str(52000 + index),
                },
            )
        )

    monkeypatch.setattr(
        agent.ssh_collector,
        "read_after",
        lambda cursor: SSHJournalBatch(
            records=records,
            cursor="cursor-real-final",
        ),
    )

    agent._collect_ssh_events(
        previous,
        current,
    )

    detections = repository.list_events(
        category="detection",
        limit=10,
    )

    responses = repository.list_events(
        category="response",
        limit=10,
    )

    assert len(detections) == 1
    assert len(responses) == 2

    responses_by_type = {event["event_type"]: event for event in responses}

    response = responses_by_type["RESPONSE_DECISION"]
    execution = responses_by_type["RESPONSE_EXECUTION"]

    assert response["evidence"]["action"] == "TEMPORARY_BLOCK_IP"
    assert response["evidence"]["execution_allowed"] is True

    assert execution["evidence"]["status"] == "EXECUTED"
    assert execution["evidence"]["dry_run"] is False
    assert execution["evidence"]["executed"] is True

    block_id = execution["evidence"]["block_id"]

    assert block_id is not None

    block = repository.get_response_block(block_id)

    assert block is not None
    assert block["status"] == "ACTIVE"
    assert block["target_ip"] == "192.0.2.50"

    assert block["response_event_id"] == response["event_id"]

    assert block["execution_event_id"] == execution["event_id"]

    assert backend.prepare_calls == 1
    assert len(backend.added) == 1

    assert backend.added[0].target_ip == "192.0.2.50"

    assert current["ssh_journal_cursor"] == "cursor-real-final"
