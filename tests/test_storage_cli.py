import json
import sys
from datetime import UTC, datetime

from app.core.events import SecurityEvent
from app.storage.__main__ import build_parser, main
from app.storage.event_repository import EventRepository


def test_events_cli_parses_time_range() -> None:
    parser = build_parser()

    args = parser.parse_args(
        [
            "events",
            "--since",
            "2026-09-23T03:16:00Z",
            "--until",
            "2026-09-23T03:18:00Z",
        ]
    )

    assert args.since == datetime(
        2026,
        9,
        23,
        3,
        16,
        tzinfo=UTC,
    )

    assert args.until == datetime(
        2026,
        9,
        23,
        3,
        18,
        tzinfo=UTC,
    )


def test_events_cli_rejects_naive_datetime() -> None:
    parser = build_parser()

    try:
        parser.parse_args(
            [
                "events",
                "--since",
                "2026-09-23T03:16:00",
            ]
        )
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("La CLI aceptó una fecha sin zona horaria.")


def test_retention_cli_is_dry_run_by_default() -> None:
    parser = build_parser()

    args = parser.parse_args(
        [
            "retention",
            "--before",
            "2026-01-01T00:00:00Z",
        ]
    )

    assert args.apply is False
    assert args.before == datetime(
        2026,
        1,
        1,
        tzinfo=UTC,
    )


def test_main_executes_retention_dry_run(
    tmp_path,
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setenv(
        "AUDITORIA_STATE_DIR",
        str(tmp_path / "state"),
    )
    monkeypatch.setenv(
        "AUDITORIA_LOG_DIR",
        str(tmp_path / "logs"),
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "app.storage",
            "retention",
            "--before",
            "2026-09-23T03:16:00Z",
        ],
    )

    main()

    output = json.loads(capsys.readouterr().out)

    assert output == {
        "mode": "dry-run",
        "matching_events": 0,
        "deleted_events": 0,
    }


def test_main_applies_retention_when_requested(
    tmp_path,
    monkeypatch,
    capsys,
) -> None:
    state_dir = tmp_path / "state"
    log_dir = tmp_path / "logs"

    monkeypatch.setenv(
        "AUDITORIA_STATE_DIR",
        str(state_dir),
    )
    monkeypatch.setenv(
        "AUDITORIA_LOG_DIR",
        str(log_dir),
    )

    repository = EventRepository(state_dir / "auditoria.db")
    repository.initialize()

    old_event = SecurityEvent(
        timestamp=datetime(
            2026,
            1,
            1,
            tzinfo=UTC,
        ),
        hostname="server-test",
        source="test",
        category="network",
        event_type="OLD_EVENT",
        severity="low",
        description="Evento antiguo",
        evidence={},
    )

    recent_event = SecurityEvent(
        timestamp=datetime(
            2026,
            9,
            1,
            tzinfo=UTC,
        ),
        hostname="server-test",
        source="test",
        category="network",
        event_type="RECENT_EVENT",
        severity="low",
        description="Evento reciente",
        evidence={},
    )

    repository.add(old_event)
    repository.add(recent_event)

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "app.storage",
            "retention",
            "--before",
            "2026-06-01T00:00:00Z",
            "--apply",
        ],
    )

    main()

    output = json.loads(capsys.readouterr().out)

    assert output == {
        "mode": "applied",
        "matching_events": 1,
        "deleted_events": 1,
    }

    assert repository.count() == 1

    remaining = repository.list_events()

    assert remaining[0]["event_id"] == str(recent_event.event_id)
