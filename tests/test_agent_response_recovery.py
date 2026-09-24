from pathlib import Path
from types import SimpleNamespace

from app.agent.continuous_agent import ContinuousAgent
from app.core.config import AgentSettings
from app.storage.event_repository import EventRepository


def settings(
    tmp_path: Path,
) -> AgentSettings:
    return AgentSettings(
        interval=1,
        state_dir=tmp_path / "state",
        log_dir=tmp_path / "logs",
    )


def test_agent_emits_successful_response_recovery(
    tmp_path: Path,
    monkeypatch,
) -> None:
    class FakeRecoveryManager:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs

        def recover(self):
            return SimpleNamespace(
                table_created=True,
                expired_count=1,
                failed_pending_count=2,
                restored_count=3,
                failed_restore_count=0,
            )

    monkeypatch.setattr(
        "app.agent.continuous_agent.ResponseRecoveryManager",
        FakeRecoveryManager,
    )

    agent_settings = settings(tmp_path)

    agent = ContinuousAgent(
        interval=1,
        settings=agent_settings,
    )

    agent._recover_response_state()

    repository = EventRepository(agent_settings.database_file)

    events = repository.list_events(event_type="RESPONSE_RECOVERY")

    assert len(events) == 1

    event = events[0]

    assert event["source"] == "response-recovery"
    assert event["severity"] == "low"
    assert event["evidence"] == {
        "table_created": True,
        "expired_count": 1,
        "failed_pending_count": 2,
        "restored_count": 3,
        "failed_restore_count": 0,
    }


def test_agent_survives_response_recovery_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    class FailingRecoveryManager:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs

        def recover(self):
            raise RuntimeError("fallo simulado de nftables")

    monkeypatch.setattr(
        "app.agent.continuous_agent.ResponseRecoveryManager",
        FailingRecoveryManager,
    )

    agent_settings = settings(tmp_path)

    agent = ContinuousAgent(
        interval=1,
        settings=agent_settings,
    )

    agent._recover_response_state()

    repository = EventRepository(agent_settings.database_file)

    events = repository.list_events(event_type="RESPONSE_RECOVERY_ERROR")

    assert len(events) == 1

    event = events[0]

    assert event["source"] == "response-recovery"
    assert event["severity"] == "high"
    assert event["evidence"]["error"] == "fallo simulado de nftables"
