from __future__ import annotations

import argparse
from pathlib import Path

from app.agent.continuous_agent import main as run_continuous_agent
from app.agent.registration import (
    DEFAULT_IDENTITY_FILE,
    AgentRegistrationError,
    register_agent,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.agent")
    subparsers = parser.add_subparsers(dest="command")
    register = subparsers.add_parser("register", help="Registrar este servidor")
    register.add_argument("--server", required=True)
    register.add_argument("--token", required=True)
    register.add_argument(
        "--identity-file",
        type=Path,
        default=DEFAULT_IDENTITY_FILE,
        help=argparse.SUPPRESS,
    )
    return parser


def cli(argv: list[str] | None = None) -> int:
    parser = _parser()
    arguments, remaining = parser.parse_known_args(argv)
    if arguments.command != "register":
        if argv:
            parser.error(f"argumentos no reconocidos: {' '.join(remaining)}")
        run_continuous_agent()
        return 0
    if remaining:
        parser.error(f"argumentos no reconocidos: {' '.join(remaining)}")
    try:
        identity = register_agent(
            server=arguments.server,
            token=arguments.token,
            identity_file=arguments.identity_file,
        )
    except AgentRegistrationError as exc:
        print(f"Error: {exc}")
        return 1
    print(f"Servidor registrado: {identity['agent_id']}")
    print(f"Identidad guardada en: {arguments.identity_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
