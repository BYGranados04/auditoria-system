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
