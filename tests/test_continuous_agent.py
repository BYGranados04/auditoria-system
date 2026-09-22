from typing import Any

from app.agent.continuous_agent import ContinuousAgent


def capture_events(
    agent: ContinuousAgent,
    monkeypatch,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []

    def fake_emit(**kwargs: Any) -> None:
        events.append(kwargs)

    monkeypatch.setattr(agent, "emit", fake_emit)

    return events


def test_detects_opened_and_closed_ports(monkeypatch) -> None:
    agent = ContinuousAgent(interval=1)
    events = capture_events(agent, monkeypatch)

    previous = {
        "listening_ports": [
            "tcp:0.0.0.0:22",
            "tcp:127.0.0.1:9000",
        ]
    }

    current = {
        "listening_ports": [
            "tcp:0.0.0.0:22",
            "tcp:127.0.0.1:8000",
        ]
    }

    agent.compare(previous, current)

    event_types = [event["event_type"] for event in events]

    assert "PORT_OPENED" in event_types
    assert "PORT_CLOSED" in event_types

    opened = next(event for event in events if event["event_type"] == "PORT_OPENED")

    assert opened["severity"] == "medium"
    assert opened["evidence"]["port"] == "tcp:127.0.0.1:8000"


def test_detects_user_creation(monkeypatch) -> None:
    agent = ContinuousAgent(interval=1)
    events = capture_events(agent, monkeypatch)

    previous = {
        "users": {
            "auditor": {
                "uid": 1000,
                "gid": 1000,
                "shell": "/bin/bash",
                "home": "/home/auditor",
            }
        }
    }

    current = {
        "users": {
            **previous["users"],
            "intruder-test": {
                "uid": 1001,
                "gid": 1001,
                "shell": "/bin/bash",
                "home": "/home/intruder-test",
            },
        }
    }

    agent.compare(previous, current)

    created = [event for event in events if event["event_type"] == "USER_CREATED"]

    assert len(created) == 1
    assert created[0]["evidence"]["username"] == "intruder-test"
    assert created[0]["severity"] == "medium"


def test_detects_critical_file_change(monkeypatch) -> None:
    agent = ContinuousAgent(interval=1)
    events = capture_events(agent, monkeypatch)

    previous = {
        "watched_files": {
            "/etc/ssh/sshd_config": "old-hash",
        }
    }

    current = {
        "watched_files": {
            "/etc/ssh/sshd_config": "new-hash",
        }
    }

    agent.compare(previous, current)

    changed = [
        event for event in events if event["event_type"] == "CRITICAL_FILE_CHANGED"
    ]

    assert len(changed) == 1
    assert changed[0]["severity"] == "high"
    assert changed[0]["evidence"]["path"] == "/etc/ssh/sshd_config"


def test_detects_firewall_disabled(monkeypatch) -> None:
    agent = ContinuousAgent(interval=1)
    events = capture_events(agent, monkeypatch)

    previous = {
        "firewall": {
            "active": True,
            "digest": "before",
        }
    }

    current = {
        "firewall": {
            "active": False,
            "digest": "after",
        }
    }

    agent.compare(previous, current)

    disabled = [event for event in events if event["event_type"] == "FIREWALL_DISABLED"]

    assert len(disabled) == 1
    assert disabled[0]["severity"] == "high"


def test_no_event_when_state_is_unchanged(monkeypatch) -> None:
    agent = ContinuousAgent(interval=1)
    events = capture_events(agent, monkeypatch)

    state = {
        "listening_ports": ["tcp:0.0.0.0:22"],
        "users": {},
        "running_services": ["ssh.service"],
        "watched_files": {
            "/etc/ssh/sshd_config": "same-hash",
        },
        "firewall": {
            "active": True,
            "digest": "same-firewall",
        },
    }

    agent.compare(state, state)

    assert events == []
