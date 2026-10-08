from __future__ import annotations

import json
import os
import platform
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from app.core.config import DEFAULT_AGENT_IDENTITY_FILE

DEFAULT_IDENTITY_FILE = DEFAULT_AGENT_IDENTITY_FILE
MAX_IDENTITY_FILE_BYTES = 16_384


class AgentRegistrationError(RuntimeError):
    pass


class AgentIdentityError(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    central_url: str
    credential: str


def normalize_central_url(value: str) -> str:
    normalized = value.strip().rstrip("/")
    try:
        parsed = urlsplit(normalized)
        _ = parsed.port
    except ValueError as exc:
        raise AgentIdentityError("La URL central no es válida.") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise AgentIdentityError("La URL central debe usar http o https.")
    return normalized


def central_events_batch_url(central_url: str) -> str:
    return f"{normalize_central_url(central_url)}/agent/events/batch"


def central_heartbeat_url(central_url: str) -> str:
    return f"{normalize_central_url(central_url)}/agent/heartbeat"


def central_response_actions_url(central_url: str) -> str:
    return f"{normalize_central_url(central_url)}/agent/response-actions"


def central_config_url(central_url: str) -> str:
    return f"{normalize_central_url(central_url)}/agent/config"


def central_config_state_url(central_url: str) -> str:
    return f"{normalize_central_url(central_url)}/agent/config/state"


def load_identity(
    path: Path = DEFAULT_IDENTITY_FILE,
) -> AgentIdentity | None:
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise AgentIdentityError("El archivo de identidad no es seguro.")
    try:
        file_stat = path.stat()
        if file_stat.st_size > MAX_IDENTITY_FILE_BYTES:
            raise AgentIdentityError("El archivo de identidad es demasiado grande.")
        if os.name != "nt" and file_stat.st_mode & 0o077:
            raise AgentIdentityError(
                "El archivo de identidad tiene permisos inseguros."
            )
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgentIdentityError("No se pudo leer la identidad del agente.") from exc
    if not isinstance(raw, dict):
        raise AgentIdentityError("La identidad del agente no es válida.")
    agent_id = raw.get("agent_id")
    central_url = raw.get("central_url")
    credential = raw.get("credential")
    if (
        not isinstance(agent_id, str)
        or not agent_id.strip()
        or len(agent_id) > 255
        or not isinstance(central_url, str)
        or not isinstance(credential, str)
        or not credential
        or len(credential) > 512
    ):
        raise AgentIdentityError("La identidad del agente no es válida.")
    try:
        normalized_url = normalize_central_url(central_url)
    except AgentIdentityError as exc:
        raise AgentIdentityError("La identidad del agente no es válida.") from exc
    return AgentIdentity(
        agent_id=agent_id.strip(),
        central_url=normalized_url,
        credential=credential,
    )


def _post_json(
    url: str,
    payload: dict[str, object],
    *,
    credential: str | None = None,
) -> dict[str, Any]:
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if credential is not None:
        headers["Authorization"] = f"Bearer {credential}"
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310
            body = response.read()
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
        raise AgentRegistrationError(
            "No fue posible contactar al servidor central."
        ) from exc
    try:
        result = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AgentRegistrationError(
            "Respuesta inválida del servidor central."
        ) from exc
    if not isinstance(result, dict):
        raise AgentRegistrationError("Respuesta inválida del servidor central.")
    return result


def save_identity(identity: dict[str, str], path: Path = DEFAULT_IDENTITY_FILE) -> None:
    if path.exists():
        raise AgentRegistrationError(
            f"Ya existe una identidad en {path}; no se sobrescribió."
        )
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            json.dump(identity, temporary, ensure_ascii=False, sort_keys=True)
            temporary.write("\n")
            temporary.flush()
            os.fsync(temporary.fileno())
        temporary_path.chmod(0o600)
        temporary_path.replace(path)
        path.chmod(0o600)
    except Exception:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise


def register_agent(
    *,
    server: str,
    token: str,
    identity_file: Path = DEFAULT_IDENTITY_FILE,
    hostname: str | None = None,
) -> dict[str, str]:
    if identity_file.exists():
        raise AgentRegistrationError(
            f"Ya existe una identidad en {identity_file}; no se sobrescribió."
        )
    try:
        central_url = normalize_central_url(server)
    except AgentIdentityError as exc:
        raise AgentRegistrationError(str(exc)) from exc
    enrollment = _post_json(
        f"{central_url}/agent/enroll",
        {
            "registration_token": token,
            "hostname": hostname or platform.node(),
            "metadata": {
                "platform": platform.system(),
                "release": platform.release(),
            },
        },
    )
    agent_id = enrollment.get("agent_id")
    credential = enrollment.get("credential")
    if not isinstance(agent_id, str) or not isinstance(credential, str):
        raise AgentRegistrationError("Respuesta de enrolamiento incompleta.")
    identity = {
        "agent_id": agent_id,
        "central_url": central_url,
        "credential": credential,
    }
    save_identity(identity, identity_file)
    _post_json(
        f"{central_url}/agent/heartbeat",
        {"agent_id": agent_id},
        credential=credential,
    )
    return identity
