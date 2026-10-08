from __future__ import annotations

import json
import platform
import threading
from dataclasses import dataclass
from typing import Protocol

from app.agent.registration import (
    AgentIdentityError,
    central_heartbeat_url,
    load_identity,
)
from app.agent.sync import SyncTransport, SyncTransportError, UrllibSyncTransport
from app.agent.version import agent_version
from app.core.config import AgentSettings

MAX_HEARTBEAT_RESPONSE_BYTES = 65_536
MAX_CONFIG_REVISION = 2_147_483_647


class HeartbeatConfigListener(Protocol):
    def on_heartbeat(self, revision_hint: int | None) -> None: ...


@dataclass(frozen=True)
class HeartbeatRunResult:
    sent: bool = False
    skipped: bool = False
    next_delay_seconds: int = 0
    config_revision: int | None = None


def _config_revision(body: bytes) -> int | None:
    """Revisión de configuración anunciada por un central v1.1.

    Un central v1.0 no la incluye: el resultado es ``None`` y el agente sigue
    con su configuración local.
    """

    if not body or len(body) > MAX_HEARTBEAT_RESPONSE_BYTES:
        return None
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    value = data.get("config_revision") if isinstance(data, dict) else None
    if (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= MAX_CONFIG_REVISION
    ):
        return value
    return None


class AgentHeartbeatSender:
    def __init__(
        self,
        settings: AgentSettings,
        *,
        transport: SyncTransport | None = None,
        hostname: str | None = None,
        version: str | None = None,
        config_listener: HeartbeatConfigListener | None = None,
    ) -> None:
        self.settings = settings
        self.transport = transport or UrllibSyncTransport()
        self.hostname = hostname or platform.node()
        self.version = version if version is not None else agent_version()
        self.config_listener = config_listener

    def _payload(self) -> dict[str, object]:
        # agent_version ya era aceptado por el central v1.0, por lo que un
        # agente v1.1 no rompe el heartbeat contra un central anterior.
        payload: dict[str, object] = {"hostname": self.hostname}
        if self.version:
            payload["agent_version"] = self.version
        return payload

    @property
    def _maximum_delay(self) -> int:
        return max(
            self.settings.heartbeat_interval,
            self.settings.sync_retry_max_seconds,
        )

    def run_once(self) -> HeartbeatRunResult:
        try:
            identity = load_identity(self.settings.identity_file)
        except AgentIdentityError:
            return HeartbeatRunResult(
                skipped=True,
                next_delay_seconds=self._maximum_delay,
            )
        if identity is None:
            return HeartbeatRunResult(
                skipped=True,
                next_delay_seconds=self.settings.heartbeat_interval,
            )
        try:
            response = self.transport.post_json(
                central_heartbeat_url(identity.central_url),
                self._payload(),
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {identity.credential}",
                },
                timeout_seconds=self.settings.sync_timeout_seconds,
            )
        except (SyncTransportError, TimeoutError, OSError):
            return HeartbeatRunResult(
                next_delay_seconds=self.settings.heartbeat_interval
            )
        except Exception:
            return HeartbeatRunResult(
                next_delay_seconds=self.settings.heartbeat_interval
            )

        if response.status_code == 200:
            revision = _config_revision(response.body)
            if self.config_listener is not None:
                try:
                    self.config_listener.on_heartbeat(revision)
                except Exception:
                    # La configuración remota nunca debe romper el heartbeat.
                    pass
            return HeartbeatRunResult(
                sent=True,
                next_delay_seconds=self.settings.heartbeat_interval,
                config_revision=revision,
            )
        if response.status_code in {401, 403, 422}:
            return HeartbeatRunResult(next_delay_seconds=self._maximum_delay)
        return HeartbeatRunResult(
            next_delay_seconds=self.settings.heartbeat_interval
        )


class AgentHeartbeatWorker:
    def __init__(self, sender: AgentHeartbeatSender) -> None:
        self.sender = sender
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="auditoria-agent-heartbeat",
            daemon=True,
        )
        self._thread.start()

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                result = self.sender.run_once()
                delay = result.next_delay_seconds
            except Exception:
                delay = self.sender.settings.heartbeat_interval
            self._stop_event.wait(delay)

    def stop(self) -> None:
        self._stop_event.set()

    def join(self, timeout: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout)
