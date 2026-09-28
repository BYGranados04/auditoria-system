from __future__ import annotations

import platform
import threading
from dataclasses import dataclass

from app.agent.registration import (
    AgentIdentityError,
    central_heartbeat_url,
    load_identity,
)
from app.agent.sync import SyncTransport, SyncTransportError, UrllibSyncTransport
from app.core.config import AgentSettings


@dataclass(frozen=True)
class HeartbeatRunResult:
    sent: bool = False
    skipped: bool = False
    next_delay_seconds: int = 0


class AgentHeartbeatSender:
    def __init__(
        self,
        settings: AgentSettings,
        *,
        transport: SyncTransport | None = None,
        hostname: str | None = None,
    ) -> None:
        self.settings = settings
        self.transport = transport or UrllibSyncTransport()
        self.hostname = hostname or platform.node()

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
                {"hostname": self.hostname},
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
            return HeartbeatRunResult(
                sent=True,
                next_delay_seconds=self.settings.heartbeat_interval,
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
