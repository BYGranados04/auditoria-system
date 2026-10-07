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
        identity_file=tmp_path / "agent-identity.json",
    )


class FakeProtectionResolver:
    def __init__(
        self,
        *,
        trusted_admin_ips,
    ) -> None:
        self.trusted_admin_ips = tuple(trusted_admin_ips)

    def resolve(self):
        return SimpleNamespace(
            protected_ips={
                "192.0.2.10",
                "2001:db8::10",
            }
        )


def test_agent_emits_successful_response_recovery(
    tmp_path: Path,
    monkeypatch,
) -> None:
    class FakeRecoveryManager:
        def __init__(
            self,
            **kwargs,
        ) -> None:
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
        "app.agent.continuous_agent.ResponseProtectionResolver",
        FakeProtectionResolver,
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
        def __init__(
            self,
            **kwargs,
        ) -> None:
            self.kwargs = kwargs

        def recover(self):
            raise RuntimeError("fallo simulado de nftables")

    monkeypatch.setattr(
        "app.agent.continuous_agent.ResponseProtectionResolver",
        FakeProtectionResolver,
    )

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


def test_agent_survives_protection_resolution_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    class FailingProtectionResolver:
        def __init__(
            self,
            *,
            trusted_admin_ips,
        ) -> None:
            self.trusted_admin_ips = tuple(trusted_admin_ips)

        def resolve(self):
            raise RuntimeError("fallo simulado al resolver direcciones protegidas")

    monkeypatch.setattr(
        "app.agent.continuous_agent.ResponseProtectionResolver",
        FailingProtectionResolver,
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

    assert "resolver direcciones protegidas" in events[0]["evidence"]["error"]


def test_agent_passes_dynamic_ips_to_firewall_planner(
    tmp_path: Path,
    monkeypatch,
) -> None:
    captured: dict[str, set[str]] = {}

    class CapturingPlanner:
        def __init__(
            self,
            *,
            protected_ips,
        ) -> None:
            captured["protected_ips"] = set(protected_ips)

    class FakeBackend:
        pass

    class FakeRecoveryManager:
        def __init__(
            self,
            *,
            repository,
            backend,
            planner,
        ) -> None:
            self.repository = repository
            self.backend = backend
            self.planner = planner

        def recover(self):
            return SimpleNamespace(
                table_created=False,
                expired_count=0,
                failed_pending_count=0,
                restored_count=0,
                failed_restore_count=0,
            )

    monkeypatch.setattr(
        "app.agent.continuous_agent.ResponseProtectionResolver",
        FakeProtectionResolver,
    )

    monkeypatch.setattr(
        "app.agent.continuous_agent.NftablesFirewallPlanner",
        CapturingPlanner,
    )

    monkeypatch.setattr(
        "app.agent.continuous_agent.NftablesFirewallBackend",
        FakeBackend,
    )

    monkeypatch.setattr(
        "app.agent.continuous_agent.ResponseRecoveryManager",
        FakeRecoveryManager,
    )

    agent = ContinuousAgent(
        interval=1,
        settings=settings(tmp_path),
    )

    agent._recover_response_state()

    assert captured["protected_ips"] == {
        "192.0.2.10",
        "2001:db8::10",
    }
