"""Versión instalada del agente, reportada en el heartbeat.

La fuente es ``pyproject.toml`` del árbol desplegado (el mismo dato que usa
``scripts/backup.sh``). Si no puede leerse, se intenta con los metadatos del
paquete instalado. Si nada es válido, el agente simplemente no reporta
versión: el heartbeat sigue funcionando.
"""

from __future__ import annotations

import re
import tomllib
from functools import lru_cache
from importlib import metadata
from pathlib import Path

PACKAGE_NAME = "auditoria-system"
VERSION_PATTERN = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$")
PYPROJECT_FILE = Path(__file__).resolve().parents[2] / "pyproject.toml"
MAX_PYPROJECT_BYTES = 65_536


def _valid(value: object) -> str | None:
    if isinstance(value, str) and VERSION_PATTERN.fullmatch(value.strip()):
        return value.strip()
    return None


def _from_pyproject(path: Path) -> str | None:
    try:
        if not path.is_file() or path.stat().st_size > MAX_PYPROJECT_BYTES:
            return None
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return None
    project = data.get("project")
    if not isinstance(project, dict) or project.get("name") != PACKAGE_NAME:
        return None
    return _valid(project.get("version"))


def _from_metadata() -> str | None:
    try:
        return _valid(metadata.version(PACKAGE_NAME))
    except metadata.PackageNotFoundError:
        return None


@lru_cache(maxsize=1)
def agent_version() -> str | None:
    return _from_pyproject(PYPROJECT_FILE) or _from_metadata()
