from __future__ import annotations

import argparse
import getpass
from pathlib import Path

from app.auth.config import load_auth_settings
from app.auth.repository import (
    AuthConflictError,
    AuthRepository,
    AuthValidationError,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.auth")
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create-superadmin")
    create.add_argument(
        "--database",
        type=Path,
        default=None,
        help="Ruta de auth.db; usa AUDITORIA_AUTH_DB por defecto.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.command != "create-superadmin":
        return 2

    database_file = arguments.database or load_auth_settings().database_file
    username = input("Usuario: ").strip()
    password = getpass.getpass("Contraseña: ")
    confirmation = getpass.getpass("Confirmar contraseña: ")
    if password != confirmation:
        print("Error: las contraseñas no coinciden.")
        return 1

    repository = AuthRepository(database_file)
    try:
        user = repository.create_user(
            username=username,
            password=password,
            role="superadmin",
        )
    except (AuthValidationError, AuthConflictError) as exc:
        print(f"Error: {exc}")
        return 1

    print(f"Superadmin creado: {user['username']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
