from __future__ import annotations

import json
import os
import platform
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

DEFAULT_IDENTITY_FILE = Path("/etc/auditoria-system/agent-identity.json")


class AgentRegistrationError(RuntimeError):
    pass


def _central_url(value: str) -> str:
    normalized = value.rstrip("/")
    parsed = urlsplit(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise AgentRegistrationError("La URL central debe usar http o https.")
    return normalized


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
    central_url = _central_url(server)
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
