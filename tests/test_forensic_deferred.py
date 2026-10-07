from __future__ import annotations

import time
from datetime import timedelta
from pathlib import Path

import pytest

from app.agent.continuous_agent import ContinuousAgent
from app.response.executor import ResponseExecutor
from tests.test_incidents import (
    BASE,
    FakeBackend,
    FakeResolver,
    auth_failure_records,
    build_agent,
    feed,
    invalid_user_records,
    local_repository,
)

SLOW_COMMAND_SECONDS = 0.25


class OrderedBackend(FakeBackend):
    def __init__(self, timeline: list[tuple[str, float]]) -> None:
        super().__init__()
        self.timeline = timeline

    def add_temporary_block(self, plan) -> None:
        self.timeline.append((f"block:{plan.target_ip}", time.monotonic()))
        super().add_temporary_block(plan)


def automatic_agent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    timeline: list[tuple[str, float]],
) -> tuple[ContinuousAgent, OrderedBackend]:
    agent = build_agent(
        tmp_path,
        monkeypatch,
        response_mode="automatic",
        response_block_scope="ip_port",
        allow_temporary_ip_port_block=True,
        evidence_enabled=True,
    )

    def slow_runner(command, _timeout):
        timeline.append((f"command:{command[0]}", time.monotonic()))
        time.sleep(SLOW_COMMAND_SECONDS)
        return 0, f"{command[0]} salida\n", ""

    agent.evidence_collector._runner = slow_runner
    backend = OrderedBackend(timeline)
    agent.response_executor = ResponseExecutor(
        agent.response_policy,
        dry_run=False,
        repository=local_repository(agent),
        backend=backend,  # type: ignore[arg-type]
        protection_resolver=FakeResolver(),  # type: ignore[arg-type]
    )
    return agent, backend


def test_slow_forensic_capture_does_not_delay_containment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    timeline: list[tuple[str, float]] = []
    agent, backend = automatic_agent(tmp_path, monkeypatch, timeline)

    feed(
        agent,
        monkeypatch,
        [
            *invalid_user_records(BASE),
            *invalid_user_records(
                BASE + timedelta(seconds=1),
                source_ip="192.168.1.77",
                prefix="otro",
            ),
        ],
    )

    # Ambas contenciones ocurren sin ejecutar ningún comando forense: el
    # único origen de demora simulada (slow_runner) no se invocó en feed().
    # No se acota el wall-clock de feed(): incluye ~80 transacciones SQLite
    # cuyo costo depende del disco del host (fsync), no de la captura.
    assert [label for label, _ in timeline] == [
        "block:192.168.1.50",
        "block:192.168.1.77",
    ]

    capture_started = time.monotonic()
    assert agent.process_forensic_queue() == 2
    capture_elapsed = time.monotonic() - capture_started

    commands = [label for label, _ in timeline if label.startswith("command:")]
    assert len(commands) == 12
    assert capture_elapsed >= 12 * SLOW_COMMAND_SECONDS
    last_block = max(moment for label, moment in timeline if label.startswith("block"))
    first_command = min(
        moment for label, moment in timeline if label.startswith("command")
    )
    assert last_block < first_command
    assert len(backend.added) == 2


def test_quick_evidence_is_taken_before_decision_without_subprocesses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    timeline: list[tuple[str, float]] = []
    agent, _ = automatic_agent(tmp_path, monkeypatch, timeline)
    quick_calls: list[str | None] = []

    def quick_provider(source_ip):
        timeline.append(("quick", time.monotonic()))
        quick_calls.append(source_ip)
        return {"connections_to_source": [], "logged_in_users": [], "errors": []}

    agent.evidence_collector._quick_provider = quick_provider

    feed(agent, monkeypatch, invalid_user_records(BASE))

    assert quick_calls == ["192.168.1.50"]
    assert [label for label, _ in timeline] == ["quick", "block:192.168.1.50"]
    queued = local_repository(agent).list_pending_forensic_captures(limit=10)
    assert len(queued) == 1
    assert '"connections_to_source"' in queued[0]["quick_snapshot_json"]


def test_forensic_queue_is_persistent_and_bounded_per_cycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent = build_agent(tmp_path, monkeypatch, evidence_enabled=True)
    for index, source in enumerate(("192.168.1.50", "192.168.1.51", "192.168.1.52")):
        feed(
            agent,
            monkeypatch,
            invalid_user_records(
                BASE + timedelta(minutes=index),
                source_ip=source,
                prefix=f"s{index}",
            ),
        )
    feed(agent, monkeypatch, auth_failure_records(BASE + timedelta(minutes=5)))
    assert len(local_repository(agent).list_pending_forensic_captures(limit=10)) == 4

    # Reinicio del agente: la cola sigue en SQLite.
    restarted = build_agent(tmp_path, monkeypatch, evidence_enabled=True)

    assert restarted.process_forensic_queue(limit=3) == 3
    assert (
        len(local_repository(restarted).list_pending_forensic_captures(limit=10)) == 1
    )
    assert restarted.process_forensic_queue(limit=3) == 1
    assert restarted.process_forensic_queue(limit=3) == 0
    captured = local_repository(restarted).list_events(
        event_type="FORENSIC_EVIDENCE_CAPTURED",
        limit=10,
    )
    assert len(captured) == 4


def test_failed_capture_is_retried_then_reported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent = build_agent(tmp_path, monkeypatch, evidence_enabled=True)
    feed(agent, monkeypatch, invalid_user_records(BASE))

    def broken_capture(*_args, **_kwargs):
        raise OSError("disco lleno")

    monkeypatch.setattr(agent.evidence_collector, "capture", broken_capture)

    for _ in range(3):
        agent.process_forensic_queue()

    assert local_repository(agent).list_pending_forensic_captures(limit=10) == []
    failures = local_repository(agent).list_events(
        event_type="FORENSIC_EVIDENCE_FAILED",
        limit=10,
    )
    assert len(failures) == 1
    assert "disco lleno" in failures[0]["evidence"]["error"]


def test_disabled_evidence_never_queues_or_runs_commands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    timeline: list[tuple[str, float]] = []
    agent, _ = automatic_agent(tmp_path, monkeypatch, timeline)
    agent.evidence_collector.settings = type(agent.evidence_collector.settings)(
        **{**agent.evidence_collector.settings.__dict__, "enabled": False}
    )

    feed(agent, monkeypatch, invalid_user_records(BASE))

    assert agent.process_forensic_queue() == 0
    assert local_repository(agent).list_pending_forensic_captures(limit=10) == []
    assert all(not label.startswith("command") for label, _ in timeline)
