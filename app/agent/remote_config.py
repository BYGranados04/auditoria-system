"""Configuración remota segura del modo de respuesta (control plane v1.1).

Reglas del diseño:

- El central solo publica ``{revision, response_mode}`` para el agente dueño
  de la credencial. No hay comandos, rutas ni secretos en el canal.
- El hilo de heartbeat detecta revisiones nuevas, descarga y valida la
  configuración y la deja *pendiente*. Nunca cambia el modo.
- El hilo principal del agente aplica o rechaza la configuración pendiente al
  inicio de ``run_once`` y reporta el estado al central.
- Con ``AUDITORIA_RESPONSE_MODE_SOURCE=local`` (por defecto) el agente nunca
  aplica cambios remotos: los rechaza y conserva ``agent.env``.
- Un central v1.0 responde 404: el agente deja de consultar hasta reiniciar y
  sigue con su configuración local.
- Cualquier dato inválido se descarta; ante un archivo local corrupto el
  modo de partida es ``audit_only``. Nunca hay fallback hacia ``automatic``.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol

from app.agent.approvals import UrllibApprovalTransport
from app.agent.registration import (
    AgentIdentityError,
    central_config_state_url,
    central_config_url,
    load_identity,
)
from app.agent.sync import SyncHttpResponse, SyncTransportError, UrllibSyncTransport
from app.core.config import AgentSettings

RESPONSE_MODES: frozenset[str] = frozenset({"audit_only", "assisted", "automatic"})
SAFE_FALLBACK_MODE = "audit_only"
MAX_CONFIG_RESPONSE_BYTES = 16_384
MAX_LOCAL_CONFIG_BYTES = 4_096
MAX_REVISION = 2_147_483_647
# Motivos fijos generados por Nexora: nunca se envían excepciones ni datos
# del sistema al central.
LOCAL_MANAGEMENT_REASON = "Gestión del modo configurada localmente"
APPLY_FAILED_REASON = "No se pudo aplicar la configuración en el agente"

ConfigStatus = Literal["applied", "rejected"]


class LocalResponseConfigError(RuntimeError):
    pass


def _valid_revision(value: object) -> bool:
    # bool es subclase de int en Python: se excluye explícitamente.
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= MAX_REVISION
    )


@dataclass(frozen=True)
class CentralResponseConfig:
    revision: int
    response_mode: str | None


@dataclass(frozen=True)
class LocalResponseConfig:
    revision: int
    response_mode: str


@dataclass(frozen=True)
class ConfigStateReport:
    applied_revision: int
    effective_response_mode: str
    config_source: str
    blocking_enabled: bool
    status: ConfigStatus
    reason: str | None = None

    def payload(self) -> dict[str, object]:
        data: dict[str, object] = {
            "applied_revision": self.applied_revision,
            "effective_response_mode": self.effective_response_mode,
            "config_source": self.config_source,
            "blocking_enabled": self.blocking_enabled,
            "status": self.status,
        }
        if self.reason is not None:
            data["reason"] = self.reason
        return data


@dataclass(frozen=True)
class ConfigNotice:
    """Hecho a registrar como evento por el hilo principal."""

    event_type: str
    description: str
    evidence: dict[str, object] = field(default_factory=dict)


def parse_central_config(body: bytes) -> CentralResponseConfig:
    if len(body) > MAX_CONFIG_RESPONSE_BYTES:
        raise ValueError("Respuesta de configuración demasiado grande.")
    data = json.loads(body.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("La configuración no es un objeto JSON.")
    revision = data.get("revision")
    mode = data.get("response_mode")
    if not _valid_revision(revision):
        raise ValueError("Revisión de configuración no válida.")
    if mode is not None and mode not in RESPONSE_MODES:
        raise ValueError("Modo de respuesta no válido.")
    if revision > 0 and mode is None:
        raise ValueError("Una revisión central requiere modo de respuesta.")
    return CentralResponseConfig(revision=revision, response_mode=mode)


def load_local_response_config(path: Path) -> LocalResponseConfig | None:
    """Último modo central aplicado. ``None`` si nunca se aplicó ninguno."""

    if not path.exists() and not path.is_symlink():
        return None
    if path.is_symlink() or not path.is_file():
        raise LocalResponseConfigError("El archivo de configuración no es seguro.")
    try:
        file_stat = path.stat()
        if file_stat.st_size > MAX_LOCAL_CONFIG_BYTES:
            raise LocalResponseConfigError(
                "El archivo de configuración es demasiado grande."
            )
        if os.name != "nt" and file_stat.st_mode & 0o077:
            raise LocalResponseConfigError(
                "El archivo de configuración tiene permisos inseguros."
            )
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LocalResponseConfigError(
            "No se pudo leer la configuración de respuesta."
        ) from exc
    if not isinstance(data, dict) or set(data) != {
        "revision",
        "response_mode",
        "applied_at",
    }:
        raise LocalResponseConfigError("La configuración de respuesta no es válida.")
    revision = data["revision"]
    mode = data["response_mode"]
    if not _valid_revision(revision) or revision < 1 or mode not in RESPONSE_MODES:
        raise LocalResponseConfigError("La configuración de respuesta no es válida.")
    if not isinstance(data["applied_at"], str):
        raise LocalResponseConfigError("La configuración de respuesta no es válida.")
    return LocalResponseConfig(revision=revision, response_mode=mode)


def save_local_response_config(
    path: Path,
    config: LocalResponseConfig,
    *,
    now: datetime | None = None,
) -> None:
    """Escritura atómica con permisos 0600. No contiene secretos."""

    if config.response_mode not in RESPONSE_MODES or not _valid_revision(
        config.revision
    ):
        raise LocalResponseConfigError("Configuración de respuesta no válida.")
    if path.is_symlink():
        raise LocalResponseConfigError("El archivo de configuración no es seguro.")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = {
        "revision": config.revision,
        "response_mode": config.response_mode,
        "applied_at": (now or datetime.now(UTC)).astimezone(UTC).isoformat(),
    }
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
            json.dump(payload, temporary, ensure_ascii=False, sort_keys=True)
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


class RemoteConfigTransport(Protocol):
    def get_json(
        self,
        url: str,
        *,
        headers: dict[str, str],
        timeout_seconds: int,
    ) -> SyncHttpResponse: ...

    def post_json(
        self,
        url: str,
        payload: dict[str, object],
        *,
        headers: dict[str, str],
        timeout_seconds: int,
    ) -> SyncHttpResponse: ...


class UrllibRemoteConfigTransport:
    """Reutiliza los transportes HTTP ya existentes del agente."""

    def __init__(self) -> None:
        self._get = UrllibApprovalTransport()
        self._post = UrllibSyncTransport()

    def get_json(
        self,
        url: str,
        *,
        headers: dict[str, str],
        timeout_seconds: int,
    ) -> SyncHttpResponse:
        return self._get.get_json(url, headers=headers, timeout_seconds=timeout_seconds)

    def post_json(
        self,
        url: str,
        payload: dict[str, object],
        *,
        headers: dict[str, str],
        timeout_seconds: int,
    ) -> SyncHttpResponse:
        return self._post.post_json(
            url,
            payload,
            headers=headers,
            timeout_seconds=timeout_seconds,
        )


class RemoteConfigCoordinator:
    """Estado compartido entre el hilo de heartbeat y el hilo principal."""

    def __init__(
        self,
        settings: AgentSettings,
        *,
        transport: RemoteConfigTransport | None = None,
        processed_revision: int = 0,
    ) -> None:
        self.settings = settings
        self.transport = transport or UrllibRemoteConfigTransport()
        self._lock = threading.Lock()
        self._processed_revision = processed_revision
        self._pending: CentralResponseConfig | None = None
        self._notices: list[ConfigNotice] = []
        self._queued_report: ConfigStateReport | None = None
        self._initial_fetch_done = False
        self._unsupported = False
        self._invalid_hint: int | None = None

    # -- consultas -----------------------------------------------------

    @property
    def unsupported(self) -> bool:
        with self._lock:
            return self._unsupported

    @property
    def processed_revision(self) -> int:
        with self._lock:
            return self._processed_revision

    # -- hilo de heartbeat ---------------------------------------------

    def on_heartbeat(self, revision_hint: int | None) -> None:
        """Llamado tras un heartbeat aceptado. Nunca cambia el modo."""

        with self._lock:
            if self._unsupported:
                return
            if self._initial_fetch_done:
                if revision_hint is None:
                    return
                if revision_hint <= self._processed_revision:
                    return
                pending = self._pending
                if pending is not None and revision_hint <= pending.revision:
                    return
                if revision_hint == self._invalid_hint:
                    return
        self._fetch(revision_hint)
        self.flush_report()

    def _headers(self, credential: str, *, body: bool = False) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {credential}",
        }
        if body:
            headers["Content-Type"] = "application/json"
        return headers

    def _fetch(self, revision_hint: int | None) -> None:
        try:
            identity = load_identity(self.settings.identity_file)
        except AgentIdentityError:
            return
        if identity is None:
            return
        try:
            response = self.transport.get_json(
                central_config_url(identity.central_url),
                headers=self._headers(identity.credential),
                timeout_seconds=self.settings.sync_timeout_seconds,
            )
        except (SyncTransportError, TimeoutError, OSError):
            return
        except Exception:
            return

        if response.status_code == 404:
            # Central v1.0: sin configuración remota. Se deja de consultar
            # para no generar tráfico ni errores en bucle.
            with self._lock:
                self._unsupported = True
                self._initial_fetch_done = True
                self._queued_report = None
            return
        if response.status_code != 200:
            return

        try:
            config = parse_central_config(response.body)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            with self._lock:
                self._initial_fetch_done = True
                self._invalid_hint = revision_hint
                self._notices.append(
                    ConfigNotice(
                        event_type="AGENT_CONFIG_INVALID",
                        description=(
                            "Se descartó una configuración central no válida."
                        ),
                        evidence={"source": "central", "revision_hint": revision_hint},
                    )
                )
            return

        with self._lock:
            self._initial_fetch_done = True
            if (
                config.response_mode is not None
                and config.revision > self._processed_revision
                and (self._pending is None or config.revision > self._pending.revision)
            ):
                self._pending = config

    # -- hilo principal --------------------------------------------------

    def take_pending(self) -> CentralResponseConfig | None:
        with self._lock:
            pending = self._pending
            self._pending = None
            return pending

    def mark_processed(self, revision: int) -> None:
        with self._lock:
            if revision > self._processed_revision:
                self._processed_revision = revision

    def add_notice(self, notice: ConfigNotice) -> None:
        with self._lock:
            self._notices.append(notice)

    def take_notices(self) -> list[ConfigNotice]:
        with self._lock:
            notices = self._notices
            self._notices = []
            return notices

    def queue_report(self, report: ConfigStateReport) -> None:
        with self._lock:
            if not self._unsupported:
                self._queued_report = report

    def flush_report(self) -> bool:
        """Envía el último estado pendiente. Seguro desde ambos hilos."""

        with self._lock:
            report = self._queued_report
            self._queued_report = None
            if report is None or self._unsupported:
                return False
        try:
            identity = load_identity(self.settings.identity_file)
        except AgentIdentityError:
            return False
        if identity is None:
            return False
        try:
            response = self.transport.post_json(
                central_config_state_url(identity.central_url),
                report.payload(),
                headers=self._headers(identity.credential, body=True),
                timeout_seconds=self.settings.sync_timeout_seconds,
            )
        except Exception:
            self._requeue(report)
            return False

        if response.status_code == 200:
            return True
        if response.status_code == 404:
            with self._lock:
                self._unsupported = True
            return False
        if response.status_code in {401, 403, 409, 422}:
            # Rechazo definitivo: no se reintenta en bucle.
            self.add_notice(
                ConfigNotice(
                    event_type="AGENT_CONFIG_REPORT_REJECTED",
                    description="El central rechazó el estado de configuración.",
                    evidence={
                        "status_code": response.status_code,
                        "applied_revision": report.applied_revision,
                        "status": report.status,
                    },
                )
            )
            return False
        self._requeue(report)
        return False

    def _requeue(self, report: ConfigStateReport) -> None:
        with self._lock:
            # Un estado más nuevo encolado mientras tanto tiene prioridad.
            if self._queued_report is None and not self._unsupported:
                self._queued_report = report
