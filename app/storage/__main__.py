from __future__ import annotations

import argparse
import json
from datetime import datetime

from app.core.config import load_agent_settings
from app.storage.event_repository import EventRepository


def parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))

    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError("La fecha debe incluir zona horaria.")

    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Consulta histórica de eventos de Auditoria System"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    events = subparsers.add_parser(
        "events",
        help="Consultar eventos almacenados",
    )

    events.add_argument(
        "--severity",
        choices=("low", "medium", "high", "critical"),
    )
    events.add_argument(
        "--type",
        dest="event_type",
    )
    events.add_argument(
        "--hostname",
    )
    events.add_argument(
        "--since",
        type=parse_datetime,
        help="Inicio del rango en formato ISO 8601",
    )
    events.add_argument(
        "--until",
        type=parse_datetime,
        help="Fin del rango en formato ISO 8601",
    )
    events.add_argument(
        "--limit",
        type=int,
        default=100,
    )

    subparsers.add_parser(
        "stats",
        help="Mostrar estadísticas de eventos",
    )

    return parser


def main() -> None:
    args = build_parser().parse_args()

    settings = load_agent_settings()
    repository = EventRepository(settings.database_file)
    repository.initialize()

    if args.command == "events":
        result = repository.list_events(
            severity=args.severity,
            event_type=args.event_type,
            hostname=args.hostname,
            since=args.since,
            until=args.until,
            limit=args.limit,
        )
    else:
        result = repository.statistics()

    print(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
