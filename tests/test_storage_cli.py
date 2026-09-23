from datetime import UTC, datetime

from app.storage.__main__ import build_parser


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
