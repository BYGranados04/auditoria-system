from typing import Any

from app.agent.continuous_agent import ContinuousAgent


def prepare_agent(
    monkeypatch,
    previous: dict[str, Any],
    current: dict[str, Any],
):
    agent = ContinuousAgent(interval=1)

    monkeypatch.setattr(
        agent.ssh_collector,
        "latest_cursor",
        lambda: None,
    )

    events: list[dict[str, Any]] = []
    saved: list[dict[str, Any]] = []
    comparisons: list[tuple[dict[str, Any], dict[str, Any]]] = []

    monkeypatch.setattr(
        agent,
        "emit",
        lambda **kwargs: events.append(kwargs),
    )
    monkeypatch.setattr(
        agent,
        "load_state",
        lambda: previous,
    )
    monkeypatch.setattr(
        agent,
        "snapshot",
        lambda: current,
    )
    monkeypatch.setattr(
        agent,
        "save_state",
        saved.append,
    )
    monkeypatch.setattr(
        agent,
        "compare",
        lambda old, new: comparisons.append((old, new)),
    )

    return agent, events, saved, comparisons


def test_reboot_skips_state_comparison(monkeypatch) -> None:
    previous = {
        "boot_id": "boot-anterior",
        "listening_ports": ["tcp:127.0.0.1:8000"],
    }

    current = {
        "boot_id": "boot-actual",
        "listening_ports": [],
    }

    agent, events, saved, comparisons = prepare_agent(
        monkeypatch,
        previous,
        current,
    )

    agent.run_once()

    assert comparisons == []
    assert saved == [current]
    assert events[0]["event_type"] == "SYSTEM_REBOOT_DETECTED"
    assert events[0]["severity"] == "low"


def test_legacy_baseline_is_migrated(monkeypatch) -> None:
    previous = {
        "listening_ports": ["tcp:0.0.0.0:22"],
    }

    current = {
        "boot_id": "boot-actual",
        "listening_ports": ["tcp:0.0.0.0:22"],
    }

    agent, events, saved, comparisons = prepare_agent(
        monkeypatch,
        previous,
        current,
    )

    agent.run_once()

    assert comparisons == []
    assert saved == [current]
    assert events[0]["event_type"] == "BASELINE_MIGRATED"


def test_same_boot_compares_states(monkeypatch) -> None:
    previous = {
        "boot_id": "mismo-boot",
        "listening_ports": [],
    }

    current = {
        "boot_id": "mismo-boot",
        "listening_ports": ["tcp:127.0.0.1:8000"],
    }

    agent, events, saved, comparisons = prepare_agent(
        monkeypatch,
        previous,
        current,
    )

    agent.run_once()

    assert comparisons == [(previous, current)]
    assert saved == [current]
    assert events == []
