from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

from app.agent.registration import (
    AgentIdentity,
    AgentIdentityError,
    central_events_batch_url,
    load_identity,
)
from app.core.config import AgentSettings
from app.storage.event_repository import EventRepository, PendingOutboxEvent

MAX_RESPONSE_BYTES = 65_536


@dataclass(frozen=True)
class SyncHttpResponse:
    status_code: int
    body: bytes


class SyncTransportError(RuntimeError):
    pass


class SyncTransport(Protocol):
    def post_json(
        self,
        url: str,
        payload: dict[str, object],
        *,
        headers: dict[str, str],
        timeout_seconds: int,
    ) -> SyncHttpResponse: ...


class UrllibSyncTransport:
    def post_json(
        self,
        url: str,
        payload: dict[str, object],
        *,
        headers: dict[str, str],
        timeout_seconds: int,
    ) -> SyncHttpResponse:
        request = urllib.request.Request(
            url,
            data=json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(  # noqa: S310
                request,
                timeout=timeout_seconds,
            ) as response:
                return SyncHttpResponse(
                    status_code=int(response.status),
                    body=response.read(MAX_RESPONSE_BYTES + 1),
                )
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read(MAX_RESPONSE_BYTES + 1)
            except OSError:
                body = b""
            return SyncHttpResponse(status_code=int(exc.code), body=body)
        except (OSError, TimeoutError, urllib.error.URLError) as exc:
            raise SyncTransportError("No fue posible contactar al central.") from exc


@dataclass(frozen=True)
class SyncRunResult:
    selected: int = 0
    acknowledged: int = 0
    pending: int = 0
    permanently_failed: int = 0
    skipped: bool = False

    def __add__(self, other: SyncRunResult) -> SyncRunResult:
        return SyncRunResult(
            selected=self.selected + other.selected,
            acknowledged=self.acknowledged + other.acknowledged,
            pending=self.pending + other.pending,
            permanently_failed=(
                self.permanently_failed + other.permanently_failed
            ),
            skipped=self.skipped and other.skipped,
        )


class AgentEventSynchronizer:
    def __init__(
        self,
        settings: AgentSettings,
        *,
        repository: EventRepository | None = None,
        transport: SyncTransport | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.settings = settings
        self.repository = repository or EventRepository(settings.database_file)
        self.transport = transport or UrllibSyncTransport()
        self.clock = clock or (lambda: datetime.now(UTC))
        self._run_lock = threading.Lock()

    def retry_delay_seconds(self, attempt_count: int) -> int:
        exponent = min(max(attempt_count, 0), 30)
        delay = self.settings.sync_retry_base_seconds * (2**exponent)
        return min(delay, self.settings.sync_retry_max_seconds)

    def run_once(self) -> SyncRunResult:
        if not self._run_lock.acquire(blocking=False):
            return SyncRunResult(skipped=True)
        try:
            return self._run_once_locked()
        finally:
            self._run_lock.release()

    def _run_once_locked(self) -> SyncRunResult:
        try:
            identity = load_identity(self.settings.identity_file)
        except AgentIdentityError:
            return SyncRunResult(skipped=True)
        if identity is None:
            return SyncRunResult(skipped=True)

        self.repository.initialize()
        now = self.clock()
        pending = self.repository.list_pending_outbox(
            now=now,
            limit=min(max(self.settings.sync_batch_size, 1), 100),
        )
        if not pending:
            return SyncRunResult()

        matching: list[PendingOutboxEvent] = []
        anomalies = 0
        for item in pending:
            if item.event.agent_id != identity.agent_id:
                reason = (
                    "Evento local sin agent_id; sincronización rechazada."
                    if item.event.agent_id is None
                    else "agent_id local no coincide con la identidad instalada."
                )
                self.repository.record_outbox_failure(
                    str(item.event.event_id),
                    error=reason,
                    next_attempt_at=None,
                    permanently_failed=True,
                )
                anomalies += 1
            else:
                matching.append(item)

        result = SyncRunResult(
            selected=len(pending),
            permanently_failed=anomalies,
        )
        if matching:
            result += self._send_batch(identity, matching)
        return result

    @staticmethod
    def _payload(entries: list[PendingOutboxEvent]) -> dict[str, object]:
        return {
            "events": [
                item.event.model_dump(mode="json", exclude={"agent_id"})
                for item in entries
            ]
        }

    def _send_batch(
        self,
        identity: AgentIdentity,
        entries: list[PendingOutboxEvent],
    ) -> SyncRunResult:
        try:
            response = self.transport.post_json(
                central_events_batch_url(identity.central_url),
                self._payload(entries),
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {identity.credential}",
                },
                timeout_seconds=self.settings.sync_timeout_seconds,
            )
        except (SyncTransportError, TimeoutError, OSError):
            return self._retry(entries, "Error temporal de red.")
        except Exception:
            return self._retry(entries, "Error inesperado de sincronización.")

        if response.status_code == 200:
            if self._valid_success_response(response.body, len(entries)):
                acknowledged = self.repository.mark_outbox_acknowledged(
                    (str(item.event.event_id) for item in entries),
                    acknowledged_at=self.clock(),
                )
                return SyncRunResult(acknowledged=acknowledged)
            return self._retry(entries, "Respuesta 200 inconsistente del central.")

        if response.status_code in {409, 422}:
            if len(entries) > 1:
                isolated = SyncRunResult()
                for entry in entries:
                    isolated += self._send_batch(identity, [entry])
                return isolated
            reason = (
                "Conflicto de payload central (HTTP 409)."
                if response.status_code == 409
                else "Evento rechazado permanentemente por el central (HTTP 422)."
            )
            self.repository.record_outbox_failure(
                str(entries[0].event.event_id),
                error=reason,
                next_attempt_at=None,
                permanently_failed=True,
            )
            return SyncRunResult(permanently_failed=1)

        if response.status_code in {401, 403}:
            error = (
                "Autenticación rechazada por el central "
                f"(HTTP {response.status_code})."
            )
            result = self._retry(
                entries,
                error,
                force_maximum_delay=True,
            )
            self.repository.defer_pending_outbox(
                next_attempt_at=self.clock()
                + timedelta(seconds=self.settings.sync_retry_max_seconds),
                error=error,
            )
            return result

        if (
            response.status_code in {408, 429}
            or 500 <= response.status_code <= 599
        ):
            return self._retry(
                entries,
                f"Error temporal del central (HTTP {response.status_code}).",
            )

        return self._retry(
            entries,
            f"Respuesta HTTP no aceptada ({response.status_code}).",
            force_maximum_delay=True,
        )

    @staticmethod
    def _valid_success_response(body: bytes, expected: int) -> bool:
        if len(body) > MAX_RESPONSE_BYTES:
            return False
        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False
        if not isinstance(data, dict):
            return False
        values = (
            data.get("accepted"),
            data.get("inserted"),
            data.get("duplicates"),
        )
        if any(
            not isinstance(value, int) or isinstance(value, bool)
            for value in values
        ):
            return False
        accepted, inserted, duplicates = values
        return (
            accepted == expected
            and inserted >= 0
            and duplicates >= 0
            and inserted + duplicates == accepted
        )

    def _retry(
        self,
        entries: list[PendingOutboxEvent],
        error: str,
        *,
        force_maximum_delay: bool = False,
    ) -> SyncRunResult:
        now = self.clock()
        for item in entries:
            delay = (
                self.settings.sync_retry_max_seconds
                if force_maximum_delay
                else self.retry_delay_seconds(item.attempt_count)
            )
            self.repository.record_outbox_failure(
                str(item.event.event_id),
                error=error,
                next_attempt_at=now + timedelta(seconds=delay),
            )
        return SyncRunResult(pending=len(entries))


class AgentEventSyncWorker:
    def __init__(self, synchronizer: AgentEventSynchronizer) -> None:
        self.synchronizer = synchronizer
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="auditoria-event-sync",
            daemon=True,
        )
        self._thread.start()

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.synchronizer.run_once()
            except Exception:
                pass
            self._stop_event.wait(self.synchronizer.settings.sync_interval)

    def stop(self) -> None:
        self._stop_event.set()

    def join(self, timeout: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout)
