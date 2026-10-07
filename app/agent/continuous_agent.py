from __future__ import annotations

import argparse
import hashlib
import json
import platform
import signal
import socket
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import psutil

try:
    import pwd
except ImportError:  # pragma: no cover - depende de la plataforma
    # `pwd` es exclusivo de Unix. En plataformas sin él (por ejemplo,
    # Windows en desarrollo) la enumeración de usuarios devuelve vacío.
    pwd = None  # type: ignore[assignment]

from app.agent.approvals import ApprovalInstruction, ResponseApprovalClient
from app.agent.event_store import LocalEventStore
from app.agent.heartbeat import AgentHeartbeatSender, AgentHeartbeatWorker
from app.agent.sync import AgentEventSynchronizer, AgentEventSyncWorker
from app.core.config import AgentSettings, load_agent_settings
from app.core.events import SecurityEvent
from app.detection.ssh_collector import SSHJournalCollector
from app.detection.ssh_correlation import SSHCorrelationEngine
from app.notifications.config import load_notification_settings
from app.notifications.providers.resend import ResendProvider
from app.notifications.repository import NotificationRepository
from app.notifications.service import NotificationService
from app.response.engine import ResponsePolicyEngine
from app.response.executor import ResponseExecutor
from app.response.firewall import NftablesFirewallPlanner, static_protection_reason
from app.response.firewall_backend import NftablesFirewallBackend
from app.response.forensics import (
    EvidenceSettings,
    ForensicEvidenceCollector,
    ForensicEvidenceError,
)
from app.response.incidents import IncidentManager, link
from app.response.models import (
    EXECUTABLE_ACTIONS,
    ResponseDecision,
    ResponseExecutionResult,
)
from app.response.policy import ResponsePolicy
from app.response.protection import ResponseProtectionResolver
from app.response.recovery import ResponseRecoveryManager
from app.response.recurrence import RecurrenceAssessment, RecurrenceTracker
from app.storage.event_repository import EventRepository

FORENSIC_CAPTURES_PER_CYCLE = 3
FORENSIC_MAX_ATTEMPTS = 3
INTERRUPTED_APPROVAL_REASON = (
    "La ejecución aprobada quedó interrumpida por un reinicio del agente y no "
    "puede confirmarse."
)

WATCHED_PATHS = [
    "/etc/ssh/sshd_config",
    "/etc/ssh/sshd_config.d",
    "/etc/passwd",
    "/etc/group",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/ufw/user.rules",
    "/etc/ufw/user6.rules",
]


class ContinuousAgent:
    def __init__(
        self,
        interval: int | None = None,
        settings: AgentSettings | None = None,
    ) -> None:
        self.settings = settings or load_agent_settings()
        self.interval = (
            interval
            if interval is not None and interval > 0
            else self.settings.interval
        )
        self.running = True
        self.hostname = platform.node()
        self.ssh_collector = SSHJournalCollector()
        self.response_policy = ResponsePolicy(
            mode=self.settings.response_mode,
            trusted_admin_ips=set(self.settings.trusted_admin_ips),
            allow_temporary_ip_block=(self.settings.allow_temporary_ip_block),
            temporary_block_seconds=(self.settings.temporary_block_seconds),
            block_scope=self.settings.response_block_scope,
            allow_temporary_ip_port_block=(
                self.settings.allow_temporary_ip_port_block
            ),
            ssh_port=self.settings.ssh_port,
            escalation_enabled=self.settings.response_escalation_enabled,
            escalation_seconds=self.settings.response_escalation_seconds,
            escalation_window_seconds=(
                self.settings.response_escalation_window_seconds
            ),
        )
        self.response_engine = ResponsePolicyEngine(self.response_policy)
        self.response_executor = self._build_response_executor()
        # Ejecutor separado para acciones aprobadas en assisted: las
        # decisiones automáticas del modo assisted nunca son ejecutables.
        self.approval_executor = self._build_approval_executor()
        self.approval_client = ResponseApprovalClient(self.settings)
        self.event_repository = EventRepository(self.settings.database_file)
        self.event_store = LocalEventStore(
            self.event_repository,
            self.settings.identity_file,
        )
        self.event_synchronizer = AgentEventSynchronizer(
            self.settings,
            repository=self.event_repository,
        )
        self.event_sync_worker = AgentEventSyncWorker(self.event_synchronizer)
        self.incident_manager = IncidentManager(
            self.event_repository,
            grouping_seconds=self.settings.incident_grouping_seconds,
        )
        self.recurrence_tracker = RecurrenceTracker(
            self.event_repository,
            self.response_policy,
        )
        self.evidence_collector = ForensicEvidenceCollector(
            EvidenceSettings(
                enabled=self.settings.evidence_enabled,
                base_dir=self.settings.evidence_dir,
                retention_days=self.settings.evidence_retention_days,
                max_bytes=self.settings.evidence_max_bytes,
                max_total_bytes=self.settings.evidence_max_total_bytes,
                command_timeout_seconds=(
                    self.settings.evidence_command_timeout_seconds
                ),
            )
        )
        self.heartbeat_sender = AgentHeartbeatSender(
            self.settings,
            hostname=self.hostname,
        )
        self.heartbeat_worker = AgentHeartbeatWorker(self.heartbeat_sender)
        notification_settings = load_notification_settings()
        self.notification_service = NotificationService(
            settings=notification_settings,
            repository=NotificationRepository(
                self.settings.state_dir / "notifications.db"
            ),
            provider=ResendProvider(
                api_key=notification_settings.resend_api_key,
                sender=notification_settings.sender,
                api_url=notification_settings.resend_api_url,
                timeout_seconds=notification_settings.timeout_seconds,
            ),
        )

    def _build_response_executor(self) -> ResponseExecutor:
        real_execution_enabled = self.settings.response_mode == "automatic" and (
            self.settings.allow_temporary_ip_block
            or self.settings.allow_temporary_ip_port_block
        )

        if not real_execution_enabled:
            return ResponseExecutor(
                self.response_policy,
                dry_run=True,
            )

        repository = EventRepository(self.settings.database_file)

        backend = NftablesFirewallBackend()

        protection_resolver = self._protection_resolver()

        return ResponseExecutor(
            self.response_policy,
            dry_run=False,
            repository=repository,
            backend=backend,
            protection_resolver=protection_resolver,
        )

    def _protection_resolver(self) -> ResponseProtectionResolver:
        if self.settings.ssh_port == 22:
            # Llamada idéntica a la histórica cuando SSH usa el puerto 22.
            return ResponseProtectionResolver(
                trusted_admin_ips=(self.settings.trusted_admin_ips)
            )

        return ResponseProtectionResolver(
            trusted_admin_ips=(self.settings.trusted_admin_ips),
            ssh_ports=(self.settings.ssh_port,),
        )

    def _ensure_runtime_dirs(self) -> None:
        self.settings.state_dir.mkdir(
            parents=True,
            exist_ok=True,
        )
        self.settings.log_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

    @staticmethod
    def _run(command: list[str]) -> tuple[int, str, str]:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )

            return (
                result.returncode,
                result.stdout.strip(),
                result.stderr.strip(),
            )
        except Exception as exc:
            return 1, "", str(exc)

    @staticmethod
    def _sha256_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _hash_path(self, raw_path: str) -> str:
        path = Path(raw_path)

        if not path.exists():
            return "MISSING"

        try:
            if path.is_file():
                return self._sha256_bytes(path.read_bytes())

            if path.is_dir():
                hasher = hashlib.sha256()

                for child in sorted(
                    (p for p in path.rglob("*") if p.is_file()),
                    key=lambda p: str(p),
                ):
                    try:
                        relative = str(child.relative_to(path))
                        hasher.update(relative.encode())
                        hasher.update(child.read_bytes())
                    except (PermissionError, OSError):
                        continue

                return hasher.hexdigest()

        except (PermissionError, OSError):
            return "UNREADABLE"

        return "UNKNOWN"

    @staticmethod
    def _users() -> dict[str, dict[str, Any]]:
        users: dict[str, dict[str, Any]] = {}

        if pwd is None:
            return users

        for entry in pwd.getpwall():
            if entry.pw_uid == 0 or entry.pw_uid >= 1000:
                if entry.pw_uid == 65534:
                    continue

                users[entry.pw_name] = {
                    "uid": entry.pw_uid,
                    "gid": entry.pw_gid,
                    "shell": entry.pw_shell,
                    "home": entry.pw_dir,
                }

        return users

    @staticmethod
    def _listening_ports() -> list[str]:
        ports: set[str] = set()

        try:
            connections = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            return []

        for conn in connections:
            if conn.status != psutil.CONN_LISTEN:
                continue

            if not conn.laddr:
                continue

            protocol = "tcp" if conn.type == socket.SOCK_STREAM else "udp"

            ports.add(f"{protocol}:{conn.laddr.ip}:{conn.laddr.port}")

        return sorted(ports)

    def _running_services(self) -> list[str]:
        rc, stdout, _ = self._run(
            [
                "systemctl",
                "list-units",
                "--type=service",
                "--state=running",
                "--no-legend",
                "--no-pager",
            ]
        )

        if rc != 0:
            return []

        services = []

        for line in stdout.splitlines():
            parts = line.split()

            if parts:
                services.append(parts[0])

        return sorted(set(services))

    def _firewall(self) -> dict[str, Any]:
        rc, stdout, stderr = self._run(["ufw", "status", "verbose"])

        raw = stdout if stdout else stderr

        return {
            "active": rc == 0 and "Status: active" in raw,
            "digest": self._sha256_bytes(raw.encode()),
        }

    @staticmethod
    def _boot_id() -> str | None:
        try:
            boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        except OSError:
            return None

        return boot_id or None

    def snapshot(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "boot_id": self._boot_id(),
            "captured_at": datetime.now(UTC).isoformat(),
            "listening_ports": self._listening_ports(),
            "users": self._users(),
            "running_services": self._running_services(),
            "watched_files": {path: self._hash_path(path) for path in WATCHED_PATHS},
            "firewall": self._firewall(),
        }

    @staticmethod
    def _write_json_atomic(
        path: Path,
        content: dict[str, Any],
    ) -> None:
        temporary = path.with_suffix(path.suffix + ".tmp")

        temporary.write_text(
            json.dumps(
                content,
                indent=2,
                ensure_ascii=False,
            )
        )

        temporary.replace(path)

    def save_state(self, state: dict[str, Any]) -> None:
        self._ensure_runtime_dirs()
        self._write_json_atomic(
            self.settings.state_file,
            state,
        )

    def load_state(self) -> dict[str, Any] | None:
        if not self.settings.state_file.exists():
            return None

        try:
            return json.loads(self.settings.state_file.read_text())
        except (json.JSONDecodeError, OSError):
            return None

    def emit(
        self,
        *,
        category: str,
        event_type: str,
        severity: str,
        description: str,
        evidence: dict[str, Any],
        timestamp: datetime | None = None,
        source: str = "continuous-agent",
        event_id: UUID | None = None,
    ) -> SecurityEvent:
        event_model = SecurityEvent(
            event_id=event_id or uuid4(),
            timestamp=timestamp or datetime.now(UTC),
            hostname=self.hostname,
            source=source,
            category=category,
            event_type=event_type,
            severity=severity,
            description=description,
            evidence=evidence,
        )

        self._ensure_runtime_dirs()
        event_model = self.event_store.persist(event_model)
        event = event_model.model_dump(mode="json")

        try:
            self.notification_service.notify(event_model)
        except Exception:
            # Notifications are intentionally secondary to audit persistence.
            print("Notification delivery failed after event persistence.", flush=True)

        with self.settings.events_file.open("a") as file:
            file.write(
                json.dumps(
                    event,
                    ensure_ascii=False,
                )
                + "\n"
            )

        print(
            json.dumps(
                event,
                indent=2,
                ensure_ascii=False,
            ),
            flush=True,
        )

        return event_model

    def _seed_ssh_cursor(
        self,
        state: dict[str, Any],
    ) -> None:
        cursor = self.ssh_collector.latest_cursor()

        if cursor is not None:
            state["ssh_journal_cursor"] = cursor

    def _emit_response_decision(
        self,
        detection_event: SecurityEvent,
        *,
        recurrence: RecurrenceAssessment | None = None,
        incident_id: str | None = None,
        decision: ResponseDecision | None = None,
    ) -> SecurityEvent:
        if decision is None:
            decision = self.response_engine.evaluate(
                detection_event,
                recurrence=recurrence,
                incident_id=incident_id,
            )

        evidence = decision.model_dump(mode="json")

        return self.emit(
            category="response",
            event_type="RESPONSE_DECISION",
            severity="low",
            description=("El motor de respuesta evaluó una detección de seguridad."),
            evidence=evidence,
            source="response-engine",
        )

    def _emit_response_execution(
        self,
        response_event: SecurityEvent,
    ) -> SecurityEvent:
        decision = ResponseDecision.model_validate(response_event.evidence)

        execution_event_id = uuid4()

        result = self.response_executor.execute(
            decision,
            response_event_id=response_event.event_id,
            execution_event_id=execution_event_id,
        )

        return self._emit_execution_result(
            result,
            response_event_id=response_event.event_id,
            execution_event_id=execution_event_id,
        )

    def _emit_execution_result(
        self,
        result: ResponseExecutionResult,
        *,
        response_event_id: UUID,
        execution_event_id: UUID,
        extra: dict[str, Any] | None = None,
    ) -> SecurityEvent:
        return self.emit(
            category="response",
            event_type="RESPONSE_EXECUTION",
            severity="low",
            description=("El ejecutor de respuestas evaluó una decisión de seguridad."),
            evidence={
                "response_event_id": str(response_event_id),
                **result.model_dump(mode="json"),
                **(extra or {}),
            },
            source="response-executor",
            event_id=execution_event_id,
        )

    def _recover_response_state(self) -> None:
        try:
            repository = EventRepository(self.settings.database_file)
            repository.initialize()

            protection_snapshot = self._protection_resolver().resolve()

            planner = NftablesFirewallPlanner(
                protected_ips=(protection_snapshot.protected_ips)
            )

            backend = NftablesFirewallBackend()

            manager = ResponseRecoveryManager(
                repository=repository,
                backend=backend,
                planner=planner,
            )

            summary = manager.recover()

        except Exception as exc:
            self.emit(
                category="response",
                event_type="RESPONSE_RECOVERY_ERROR",
                severity="high",
                description=(
                    "No fue posible recuperar el estado de respuestas defensivas."
                ),
                evidence={
                    "error": str(exc),
                },
                source="response-recovery",
            )
            return

        self.emit(
            category="response",
            event_type="RESPONSE_RECOVERY",
            severity="low",
            description=("Se recuperó el estado de respuestas defensivas del agente."),
            evidence={
                "table_created": summary.table_created,
                "expired_count": summary.expired_count,
                "failed_pending_count": (summary.failed_pending_count),
                "restored_count": summary.restored_count,
                "failed_restore_count": (summary.failed_restore_count),
            },
            source="response-recovery",
        )

    # ------------------------------------------------------------------
    # Flujo defensivo: incidente -> evidencia -> decisión -> ejecución
    # ------------------------------------------------------------------

    def _emit_incident(
        self,
        incident: dict[str, Any],
        *,
        links: list[dict[str, str]],
        opened: bool = False,
    ) -> SecurityEvent:
        return self.emit(
            category="incident",
            event_type="INCIDENT_OPENED" if opened else "INCIDENT_UPDATED",
            severity="low",
            description=(
                "Se abrió un incidente de seguridad."
                if opened
                else "Se actualizó un incidente de seguridad."
            ),
            evidence=IncidentManager.event_evidence(incident, links=links),
            source="incident-manager",
        )

    def _open_incident(
        self,
        detection_event: SecurityEvent,
    ) -> str | None:
        if not self.settings.incidents_enabled:
            return None

        if not self.incident_manager.is_candidate(detection_event):
            return None

        try:
            for closed in self.incident_manager.close_stale(
                now=detection_event.timestamp
            ):
                self._emit_incident(closed, links=[])

            change = self.incident_manager.open_or_update(detection_event)
            self._emit_incident(
                change.incident,
                links=change.links,
                opened=change.opened,
            )
        except Exception as exc:
            self.emit(
                category="incident",
                event_type="INCIDENT_ERROR",
                severity="medium",
                description="No fue posible registrar el incidente.",
                evidence={
                    "detection_event_id": str(detection_event.event_id),
                    "error": " ".join(str(exc).split())[:300],
                },
                source="incident-manager",
            )
            return None

        return str(change.incident["incident_id"])

    # ------------------------------------------------------------------
    # Evidencia: mínima antes de decidir, ampliada después de contener
    # ------------------------------------------------------------------

    def _quick_evidence(
        self,
        detection_event: SecurityEvent,
    ) -> dict[str, Any] | None:
        try:
            return self.evidence_collector.quick_snapshot(detection_event)
        except Exception:
            # La evidencia mínima nunca bloquea la respuesta defensiva.
            return None

    def _enqueue_forensic_capture(
        self,
        detection_event: SecurityEvent,
        *,
        incident_id: str | None,
        quick_snapshot: dict[str, Any] | None,
    ) -> None:
        collector = self.evidence_collector

        if not collector.settings.enabled or not collector.should_capture(
            detection_event
        ):
            return

        try:
            self.event_repository.enqueue_forensic_capture(
                detection_event_id=str(detection_event.event_id),
                incident_id=incident_id,
                detection_json=detection_event.model_dump_json(),
                quick_snapshot_json=(
                    json.dumps(quick_snapshot, ensure_ascii=False, default=str)
                    if quick_snapshot is not None
                    else None
                ),
                created_at=datetime.now(UTC),
            )
        except Exception as exc:
            self.emit(
                category="forensics",
                event_type="FORENSIC_EVIDENCE_FAILED",
                severity="medium",
                description="No fue posible encolar la captura forense.",
                evidence={
                    "action": "COLLECT_FORENSIC_EVIDENCE",
                    "incident_id": incident_id,
                    "detection_event_id": str(detection_event.event_id),
                    "error": " ".join(str(exc).split())[:300],
                },
                source="forensic-collector",
            )

    def process_forensic_queue(
        self,
        *,
        limit: int = FORENSIC_CAPTURES_PER_CYCLE,
    ) -> int:
        """Ejecuta capturas ampliadas pendientes, después de la contención.

        Corre en el mismo hilo del agente (sin concurrencia con el ejecutor
        ni con SQLite) y está acotado por ciclo; lo pendiente queda en la
        cola persistente para el siguiente ciclo o tras un reinicio.
        """

        collector = self.evidence_collector

        if not collector.settings.enabled:
            return 0

        try:
            pending = self.event_repository.list_pending_forensic_captures(
                limit=limit
            )
        except Exception:
            return 0

        processed = 0

        for item in pending:
            detection_id = str(item["detection_event_id"])
            incident_id = item["incident_id"]

            try:
                detection = SecurityEvent.model_validate_json(item["detection_json"])
                quick = (
                    json.loads(item["quick_snapshot_json"])
                    if item["quick_snapshot_json"]
                    else None
                )
                result = collector.capture(
                    detection,
                    incident_id=incident_id,
                    quick_snapshot=quick,
                )
            except ForensicEvidenceError as exc:
                already = "ya existe" in str(exc)
                self._finish_forensic_item(
                    item,
                    status="DONE" if already else "FAILED",
                    error=None if already else str(exc),
                )
                if not already:
                    self._emit_forensic_failure(detection_id, incident_id, exc)
                continue
            except Exception as exc:
                final = int(item["attempts"]) + 1 >= FORENSIC_MAX_ATTEMPTS
                self._finish_forensic_item(
                    item,
                    status="FAILED" if final else "PENDING",
                    error=str(exc),
                )
                if final:
                    self._emit_forensic_failure(detection_id, incident_id, exc)
                continue
            finally:
                try:
                    collector.purge()
                except Exception:
                    # La retención se reintenta en la próxima captura.
                    pass

            self._finish_forensic_item(item, status="DONE", error=None)
            processed += 1

            if result is None:
                continue

            evidence_event = self.emit(
                category="forensics",
                event_type="FORENSIC_EVIDENCE_CAPTURED",
                severity="low",
                description="Se capturó evidencia forense defensiva del servidor.",
                evidence=result.event_evidence(),
                source="forensic-collector",
            )

            if incident_id and self.settings.incidents_enabled:
                self._link_to_incident(
                    str(incident_id),
                    [link(evidence_event, "evidence")],
                )

        return processed

    def _finish_forensic_item(
        self,
        item: dict[str, Any],
        *,
        status: str,
        error: str | None,
    ) -> None:
        try:
            self.event_repository.update_forensic_capture(
                str(item["detection_event_id"]),
                status=status,
                error=error,
                now=datetime.now(UTC),
            )
        except Exception:
            pass

    def _emit_forensic_failure(
        self,
        detection_id: str,
        incident_id: str | None,
        exc: Exception,
    ) -> None:
        self.emit(
            category="forensics",
            event_type="FORENSIC_EVIDENCE_FAILED",
            severity="medium",
            description="No fue posible capturar evidencia forense.",
            evidence={
                "action": "COLLECT_FORENSIC_EVIDENCE",
                "incident_id": incident_id,
                "detection_event_id": detection_id,
                "error": " ".join(str(exc).split())[:300],
            },
            source="forensic-collector",
        )

    def _link_to_incident(
        self,
        incident_id: str,
        links: list[dict[str, str]],
        *,
        status: str | None = None,
        last_execution_status: str | None = None,
    ) -> None:
        try:
            if status is not None:
                incident = self.incident_manager.set_status(
                    incident_id,
                    status=status,
                    last_execution_status=last_execution_status,
                )
            else:
                incident = self.repository_incident(incident_id)
            if incident is not None:
                self._emit_incident(incident, links=links)
        except Exception as exc:
            self.emit(
                category="incident",
                event_type="INCIDENT_ERROR",
                severity="medium",
                description="No fue posible actualizar el incidente.",
                evidence={
                    "incident_id": incident_id,
                    "error": " ".join(str(exc).split())[:300],
                },
                source="incident-manager",
            )

    def repository_incident(self, incident_id: str) -> dict[str, Any] | None:
        return self.event_repository.get_incident(incident_id)

    # ------------------------------------------------------------------
    # Reincidencia
    # ------------------------------------------------------------------

    def _assess_recurrence(
        self,
        detection_event: SecurityEvent,
    ) -> RecurrenceAssessment | None:
        if detection_event.event_type not in (
            self.response_engine.BLOCK_CANDIDATE_DETECTIONS
        ):
            return None

        source_ip = IncidentManager.source_ip(detection_event)

        if source_ip is None:
            return None

        try:
            return self.recurrence_tracker.assess(
                hostname=detection_event.hostname,
                source_ip=source_ip,
                detection_event_id=str(detection_event.event_id),
                now=detection_event.timestamp,
            )
        except Exception:
            # Sin historial confiable se usa la duración base (nivel inicial).
            return None

    def _record_offense(
        self,
        detection_event: SecurityEvent,
        *,
        decision: ResponseDecision,
        result: ResponseExecutionResult,
        assessment: RecurrenceAssessment | None,
    ) -> None:
        if assessment is None or decision.action == "NO_ACTION":
            return

        if result.protection_rejected:
            # El ejecutor rechazó una dirección protegida: no escala.
            return

        if static_protection_reason(assessment.source_ip) is not None:
            # Categorías protegidas estáticas (p. ej. Tailscale) tampoco
            # escalan en modos que no ejecutan (audit_only/assisted).
            return

        if decision.action in EXECUTABLE_ACTIONS and result.status == "SKIPPED":
            # Bloqueo vigente equivalente u otra omisión: misma ofensa.
            return

        try:
            self.recurrence_tracker.record(
                hostname=detection_event.hostname,
                source_ip=assessment.source_ip,
                detection_event_id=str(detection_event.event_id),
                detection_type=detection_event.event_type,
                incident_id=decision.incident_id,
                occurred_at=detection_event.timestamp,
                assessment=assessment,
            )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Flujo principal de una detección
    # ------------------------------------------------------------------

    def _handle_detection(
        self,
        detection_event: SecurityEvent,
    ) -> None:
        incident_id = self._open_incident(detection_event)
        quick_snapshot = self._quick_evidence(detection_event)
        assessment = self._assess_recurrence(detection_event)

        decision = self.response_engine.evaluate(
            detection_event,
            recurrence=assessment,
            incident_id=incident_id,
        )

        approval_id: str | None = None
        if self._needs_approval(decision):
            approval_id = str(uuid4())
            decision = decision.model_copy(update={"approval_id": approval_id})

        response_event = self._emit_response_decision(
            detection_event,
            decision=decision,
        )
        approval_event = (
            self._request_approval(decision, response_event)
            if approval_id is not None
            else None
        )
        execution_event = self._emit_response_execution(response_event)

        result = ResponseExecutionResult.model_validate(
            {
                key: value
                for key, value in execution_event.evidence.items()
                if key != "response_event_id"
            }
        )

        self._record_offense(
            detection_event,
            decision=decision,
            result=result,
            assessment=assessment,
        )

        # La captura ampliada se ejecuta después de la contención.
        self._enqueue_forensic_capture(
            detection_event,
            incident_id=incident_id,
            quick_snapshot=quick_snapshot,
        )

        if incident_id is None:
            return

        try:
            incident = self.incident_manager.apply_response(
                incident_id,
                decision=decision,
                result=result,
            )
            links = [
                link(event, kind)
                for event, kind in (
                    (response_event, "decision"),
                    (approval_event, "approval"),
                    (execution_event, "execution"),
                )
                if event is not None
            ]
            self._emit_incident(incident, links=links)
        except Exception as exc:
            self.emit(
                category="incident",
                event_type="INCIDENT_ERROR",
                severity="medium",
                description="No fue posible actualizar el incidente.",
                evidence={
                    "incident_id": incident_id,
                    "detection_event_id": str(detection_event.event_id),
                    "error": " ".join(str(exc).split())[:300],
                },
                source="incident-manager",
            )

    # ------------------------------------------------------------------
    # Modo assisted: aprobación humana
    # ------------------------------------------------------------------

    def _needs_approval(self, decision: ResponseDecision) -> bool:
        return (
            self.settings.response_mode == "assisted"
            and decision.approval_required
            and not decision.execution_allowed
            and decision.proposed_action in EXECUTABLE_ACTIONS
            and decision.target_ip is not None
            and decision.selected_duration_seconds is not None
        )

    def _request_approval(
        self,
        decision: ResponseDecision,
        response_event: SecurityEvent,
    ) -> SecurityEvent | None:
        assert decision.approval_id is not None
        assert decision.proposed_action is not None
        assert decision.target_ip is not None
        assert decision.selected_duration_seconds is not None

        requested_at = datetime.now(UTC)
        expires_at = requested_at + timedelta(
            seconds=self.settings.approval_ttl_seconds
        )
        port_scoped = decision.proposed_action == "TEMPORARY_BLOCK_IP_PORT"

        try:
            self.event_repository.create_response_approval(
                action_id=decision.approval_id,
                incident_id=decision.incident_id,
                detection_event_id=str(decision.detection_event_id),
                decision_event_id=str(response_event.event_id),
                hostname=decision.hostname,
                action=decision.proposed_action,
                target_ip=decision.target_ip,
                protocol=decision.protocol if port_scoped else None,
                port=decision.port if port_scoped else None,
                duration_seconds=decision.selected_duration_seconds,
                requested_at=requested_at,
                expires_at=expires_at,
            )
        except Exception as exc:
            self.emit(
                category="response",
                event_type="RESPONSE_APPROVAL_ERROR",
                severity="medium",
                description="No fue posible registrar la acción pendiente.",
                evidence={
                    "approval_id": decision.approval_id,
                    "error": " ".join(str(exc).split())[:300],
                },
                source="response-approvals",
            )
            return None

        return self.emit(
            category="response",
            event_type="RESPONSE_APPROVAL_REQUESTED",
            severity="low",
            description="Una acción defensiva quedó pendiente de aprobación.",
            evidence={
                "approval_id": decision.approval_id,
                "status": "PENDING_APPROVAL",
                "incident_id": decision.incident_id,
                "detection_event_id": str(decision.detection_event_id),
                "decision_event_id": str(response_event.event_id),
                "action": decision.proposed_action,
                "target_ip": decision.target_ip,
                "protocol": decision.protocol if port_scoped else None,
                "port": decision.port if port_scoped else None,
                "duration_seconds": decision.selected_duration_seconds,
                "requested_at": requested_at.isoformat(),
                "expires_at": expires_at.isoformat(),
            },
            source="response-approvals",
        )

    def _build_approval_executor(self) -> ResponseExecutor | None:
        allowed = (
            self.settings.allow_temporary_ip_block
            or self.settings.allow_temporary_ip_port_block
        )

        if self.settings.response_mode != "assisted" or not allowed:
            return None

        return ResponseExecutor(
            self.response_policy,
            dry_run=False,
            repository=EventRepository(self.settings.database_file),
            backend=NftablesFirewallBackend(),
            protection_resolver=self._protection_resolver(),
        )

    def process_response_approvals(self) -> int:
        """Aplica decisiones APPROVE/REJECT del central (assisted).

        Corre en el hilo principal del agente, igual que el ejecutor
        automático, por lo que no compite con otras operaciones de firewall.
        """

        now = datetime.now(UTC)
        handled = 0

        try:
            expired = self.event_repository.expire_response_approvals(now=now)
        except Exception:
            expired = []

        for row in expired:
            self._emit_approval_outcome(
                row,
                event_type="RESPONSE_APPROVAL_EXPIRED",
                description="La acción pendiente venció sin aprobación.",
                incident_status="OBSERVED",
                last_execution_status="EXPIRED",
            )
            handled += 1

        try:
            pending = self.event_repository.count_pending_response_approvals()
        except Exception:
            return handled

        if pending == 0:
            return handled

        fetched = self.approval_client.fetch()

        for instruction in fetched.instructions:
            action_id = str(instruction.action_id)

            if instruction.decision == "APPROVE":
                handled += self._apply_approval(action_id, instruction)
            else:
                handled += self._apply_rejection(action_id, instruction)

        return handled

    def _apply_approval(self, action_id: str, instruction: ApprovalInstruction) -> int:
        now = datetime.now(UTC)
        row = self.event_repository.claim_response_approval(
            action_id,
            decided_by=instruction.decided_by,
            decided_at=instruction.decided_at,
            now=now,
        )

        if row is None:
            # Ya procesada, inexistente o vencida: idempotente.
            return 0

        decision = ResponseDecision(
            detection_event_id=row["detection_event_id"],
            hostname=row["hostname"],
            mode="assisted",
            action=row["action"],
            target_ip=row["target_ip"],
            protocol=row["protocol"],
            port=row["port"],
            duration_seconds=row["duration_seconds"],
            reason=f"Acción aprobada por {instruction.decided_by}.",
            approval_required=True,
            execution_allowed=True,
            incident_id=row["incident_id"],
            approval_id=action_id,
        )

        execution_event_id = uuid4()
        result = self._execute_approved(decision, row, execution_event_id)

        try:
            self.event_repository.finish_response_approval(
                action_id,
                status=result.status if result.status != "DRY_RUN" else "SKIPPED",
                result_reason=result.reason,
                execution_event_id=str(execution_event_id),
                now=datetime.now(UTC),
            )
        except Exception:
            pass

        execution_event = self._emit_execution_result(
            result,
            response_event_id=UUID(row["decision_event_id"]),
            execution_event_id=execution_event_id,
            extra={
                "approval_id": action_id,
                "approved_by": instruction.decided_by,
                "approved_at": instruction.decided_at.astimezone(UTC).isoformat(),
            },
        )

        if row["incident_id"] and self.settings.incidents_enabled:
            try:
                incident = self.incident_manager.apply_response(
                    str(row["incident_id"]),
                    decision=decision,
                    result=result,
                )
                self._emit_incident(
                    incident,
                    links=[link(execution_event, "execution")],
                )
            except Exception:
                pass

        return 1

    def _execute_approved(
        self,
        decision: ResponseDecision,
        row: dict[str, Any],
        execution_event_id: UUID,
    ) -> ResponseExecutionResult:
        def skipped(reason: str) -> ResponseExecutionResult:
            return ResponseExecutionResult(
                detection_event_id=decision.detection_event_id,
                action=decision.action,
                target_ip=decision.target_ip,
                duration_seconds=decision.duration_seconds,
                status="SKIPPED",
                dry_run=False,
                executed=False,
                reason=reason,
                protocol=decision.protocol,
                port=decision.port,
                approval_id=decision.approval_id,
            )

        if self.settings.response_mode != "assisted":
            return skipped(
                "El modo de respuesta actual ya no admite ejecución aprobada."
            )

        allowed = (
            self.settings.allow_temporary_ip_port_block
            if decision.action == "TEMPORARY_BLOCK_IP_PORT"
            else self.settings.allow_temporary_ip_block
        )

        if not allowed or self.approval_executor is None:
            return skipped(
                "La configuración del agente no autoriza este tipo de bloqueo."
            )

        try:
            # Mismo ResponseExecutor: vuelve a resolver protecciones
            # dinámicas, valida trusted/Tailscale y evita duplicados.
            return self.approval_executor.execute(
                decision,
                response_event_id=UUID(row["decision_event_id"]),
                execution_event_id=execution_event_id,
            )
        except Exception as exc:
            return ResponseExecutionResult(
                detection_event_id=decision.detection_event_id,
                action=decision.action,
                target_ip=decision.target_ip,
                duration_seconds=decision.duration_seconds,
                status="FAILED",
                dry_run=False,
                executed=False,
                reason=f"Error inesperado al ejecutar: {exc}"[:500],
                protocol=decision.protocol,
                port=decision.port,
                approval_id=decision.approval_id,
            )

    def _apply_rejection(self, action_id: str, instruction: ApprovalInstruction) -> int:
        now = datetime.now(UTC)
        row = self.event_repository.reject_response_approval(
            action_id,
            decided_by=instruction.decided_by,
            decided_at=instruction.decided_at,
            reason=instruction.reason,
            now=now,
        )

        if row is None:
            return 0

        self._emit_approval_outcome(
            row,
            event_type="RESPONSE_REJECTION_APPLIED",
            description=(
                "La acción pendiente fue rechazada; no se modificó el firewall."
            ),
            incident_status="OBSERVED",
            last_execution_status="REJECTED",
            extra={
                "rejected_by": instruction.decided_by,
                "rejected_at": instruction.decided_at.astimezone(UTC).isoformat(),
                "reason": instruction.reason,
            },
        )
        return 1

    def _emit_approval_outcome(
        self,
        row: dict[str, Any],
        *,
        event_type: str,
        description: str,
        incident_status: str,
        last_execution_status: str,
        extra: dict[str, Any] | None = None,
    ) -> None:
        event = self.emit(
            category="response",
            event_type=event_type,
            severity="low",
            description=description,
            evidence={
                "approval_id": row["action_id"],
                "status": row["status"],
                "incident_id": row["incident_id"],
                "action": row["action"],
                "target_ip": row["target_ip"],
                "protocol": row["protocol"],
                "port": row["port"],
                **(extra or {}),
            },
            source="response-approvals",
        )

        if row["incident_id"] and self.settings.incidents_enabled:
            self._link_to_incident(
                str(row["incident_id"]),
                [link(event, "approval")],
                status=incident_status,
                last_execution_status=last_execution_status,
            )

    def _run_deferred_tasks(self) -> None:
        for task in (self.process_response_approvals, self.process_forensic_queue):
            try:
                task()
            except Exception as exc:
                self.emit(
                    category="agent",
                    event_type="AGENT_ERROR",
                    severity="medium",
                    description="Falló una tarea diferida del agente.",
                    evidence={"error": " ".join(str(exc).split())[:300]},
                )

    def _recover_interrupted_approvals(self) -> None:
        try:
            self.event_repository.initialize()
            self.event_repository.fail_interrupted_response_approvals(
                reason=INTERRUPTED_APPROVAL_REASON
            )
        except Exception:
            pass

    def _reconcile_expired_response_blocks(self) -> int:
        """Marca como EXPIRED los bloqueos cuyo expires_at ya pasó.

        nftables retira la regla al vencer su timeout, pero response_blocks
        solo se actualizaba al arrancar (ResponseRecoveryManager) o al crear
        un bloqueo nuevo. Esta reconciliación es exclusivamente de estado en
        SQLite: no invoca nftables, no restaura ni crea acciones y no emite
        eventos. Es best-effort: cualquier error (permisos, E/S, base
        ausente o inaccesible, SQLite) se ignora y se reintenta en el
        siguiente ciclo.
        """

        try:
            # No crear la base como efecto colateral: solo initialize() la
            # crea. exists() también puede lanzar PermissionError (EACCES).
            if not self.event_repository.database_path.exists():
                return 0
            return self.event_repository.expire_response_blocks(
                now=datetime.now(UTC)
            )
        except Exception:
            return 0

    def close_stale_incidents(self) -> None:
        if not self.settings.incidents_enabled:
            return

        try:
            for closed in self.incident_manager.close_stale():
                self._emit_incident(closed, links=[])
        except Exception:
            # Se reintenta en el siguiente ciclo.
            pass

    def _collect_ssh_events(
        self,
        previous: dict[str, Any],
        current: dict[str, Any],
    ) -> None:
        cursor = previous.get("ssh_journal_cursor")

        if not isinstance(cursor, str) or not cursor:
            self._seed_ssh_cursor(current)
            return

        try:
            batch = self.ssh_collector.read_after(cursor)
        except RuntimeError as exc:
            latest_cursor = self.ssh_collector.latest_cursor()

            current["ssh_journal_cursor"] = latest_cursor or cursor

            self.emit(
                category="authentication",
                event_type="SSH_JOURNAL_RESYNC",
                severity="medium",
                description=(
                    "El colector SSH perdió su posición "
                    "en journald y fue resincronizado."
                ),
                evidence={
                    "previous_cursor": cursor,
                    "new_cursor": latest_cursor,
                    "error": str(exc),
                },
            )
            return

        if not batch.records:
            current["ssh_journal_cursor"] = batch.cursor or cursor
            return

        repository = EventRepository(self.settings.database_file)
        repository.initialize()

        correlation = SSHCorrelationEngine(repository)

        for record in batch.records:
            event_model = self.emit(
                category="authentication",
                event_type=record.event_type,
                severity=record.severity,
                description=record.description,
                evidence={
                    "journal_cursor": record.cursor,
                    **record.evidence,
                },
                timestamp=record.timestamp,
            )

            detections = correlation.analyze(event_model)

            for detection in detections:
                detection_event = self.emit(
                    category="detection",
                    event_type=detection.event_type,
                    severity=detection.severity,
                    description=detection.description,
                    evidence=detection.evidence,
                    timestamp=record.timestamp,
                    source="detection-engine",
                )

                self._handle_detection(detection_event)

        current["ssh_journal_cursor"] = batch.cursor or cursor

    def compare(
        self,
        previous: dict[str, Any],
        current: dict[str, Any],
    ) -> None:
        previous_ports = set(previous.get("listening_ports", []))
        current_ports = set(current.get("listening_ports", []))

        for port in sorted(current_ports - previous_ports):
            self.emit(
                category="network",
                event_type="PORT_OPENED",
                severity="medium",
                description=f"Se detectó un nuevo puerto en escucha: {port}",
                evidence={"port": port},
            )

        for port in sorted(previous_ports - current_ports):
            self.emit(
                category="network",
                event_type="PORT_CLOSED",
                severity="low",
                description=f"Un puerto dejó de estar en escucha: {port}",
                evidence={"port": port},
            )

        previous_users = previous.get("users", {})
        current_users = current.get("users", {})

        previous_names = set(previous_users)
        current_names = set(current_users)

        for username in sorted(current_names - previous_names):
            self.emit(
                category="identity",
                event_type="USER_CREATED",
                severity="medium",
                description=f"Se detectó un nuevo usuario: {username}",
                evidence={
                    "username": username,
                    "attributes": current_users[username],
                },
            )

        for username in sorted(previous_names - current_names):
            self.emit(
                category="identity",
                event_type="USER_REMOVED",
                severity="medium",
                description=f"Se eliminó el usuario: {username}",
                evidence={
                    "username": username,
                    "previous_attributes": previous_users[username],
                },
            )

        for username in sorted(previous_names & current_names):
            if previous_users[username] != current_users[username]:
                self.emit(
                    category="identity",
                    event_type="USER_MODIFIED",
                    severity="medium",
                    description=(f"Cambiaron atributos del usuario: {username}"),
                    evidence={
                        "username": username,
                        "before": previous_users[username],
                        "after": current_users[username],
                    },
                )

        previous_services = set(previous.get("running_services", []))
        current_services = set(current.get("running_services", []))

        for service in sorted(current_services - previous_services):
            self.emit(
                category="service",
                event_type="SERVICE_STARTED",
                severity="low",
                description=(f"Se inició un servicio: {service}"),
                evidence={"service": service},
            )

        for service in sorted(previous_services - current_services):
            self.emit(
                category="service",
                event_type="SERVICE_STOPPED",
                severity="low",
                description=(f"Se detuvo un servicio: {service}"),
                evidence={"service": service},
            )

        previous_files = previous.get(
            "watched_files",
            {},
        )
        current_files = current.get(
            "watched_files",
            {},
        )

        high_severity_paths = {
            "/etc/ssh/sshd_config",
            "/etc/ssh/sshd_config.d",
            "/etc/sudoers",
            "/etc/sudoers.d",
            "/etc/ufw/user.rules",
            "/etc/ufw/user6.rules",
        }

        for path, current_hash in current_files.items():
            previous_hash = previous_files.get(path)

            if previous_hash is None:
                continue

            if previous_hash != current_hash:
                severity = "high" if path in high_severity_paths else "medium"

                self.emit(
                    category="integrity",
                    event_type="CRITICAL_FILE_CHANGED",
                    severity=severity,
                    description=(f"Se detectó un cambio en {path}"),
                    evidence={
                        "path": path,
                        "previous_hash": previous_hash,
                        "current_hash": current_hash,
                    },
                )

        previous_firewall = previous.get(
            "firewall",
            {},
        )
        current_firewall = current.get(
            "firewall",
            {},
        )

        if previous_firewall.get("active") and not current_firewall.get("active"):
            self.emit(
                category="firewall",
                event_type="FIREWALL_DISABLED",
                severity="high",
                description="El firewall UFW fue desactivado.",
                evidence={
                    "before": previous_firewall,
                    "after": current_firewall,
                },
            )

        elif previous_firewall.get("digest") != current_firewall.get("digest"):
            self.emit(
                category="firewall",
                event_type="FIREWALL_CHANGED",
                severity="medium",
                description="La configuración efectiva de UFW cambió.",
                evidence={
                    "previous_digest": previous_firewall.get("digest"),
                    "current_digest": current_firewall.get("digest"),
                },
            )

    def initialize_baseline(self) -> dict[str, Any]:
        state = self.snapshot()
        self._seed_ssh_cursor(state)
        self.save_state(state)

        self.emit(
            category="agent",
            event_type="BASELINE_CREATED",
            severity="low",
            description=("Se creó la línea base inicial del servidor."),
            evidence={
                "state_file": str(self.settings.state_file),
            },
        )

        return state

    def run_once(self) -> None:
        # Antes de cualquier retorno temprano del ciclo.
        self._reconcile_expired_response_blocks()

        previous = self.load_state()

        if previous is None:
            self.initialize_baseline()
            return

        current = self.snapshot()

        if "boot_id" not in previous:
            self._seed_ssh_cursor(current)
            self.save_state(current)
            self.emit(
                category="agent",
                event_type="BASELINE_MIGRATED",
                severity="low",
                description=(
                    "La línea base fue actualizada para "
                    "registrar el identificador de arranque."
                ),
                evidence={},
            )
            return

        previous_boot_id = previous.get("boot_id")
        current_boot_id = current.get("boot_id")

        if previous_boot_id and current_boot_id and previous_boot_id != current_boot_id:
            self._seed_ssh_cursor(current)
            self.emit(
                category="system",
                event_type="SYSTEM_REBOOT_DETECTED",
                severity="low",
                description="Se detectó un nuevo arranque del servidor.",
                evidence={
                    "previous_boot_id": previous_boot_id,
                    "current_boot_id": current_boot_id,
                },
            )
            self.save_state(current)
            return

        self.compare(previous, current)
        self._collect_ssh_events(
            previous,
            current,
        )
        self.close_stale_incidents()
        # Después de que todas las detecciones del lote fueron contenidas.
        self._run_deferred_tasks()
        self.save_state(current)

    def run_forever(self) -> None:
        self.event_repository.initialize()
        self.event_sync_worker.start()
        self.heartbeat_worker.start()
        try:
            self.emit(
                category="agent",
                event_type="AGENT_STARTED",
                severity="low",
                description="El agente de monitoreo fue iniciado.",
                evidence={
                    "interval_seconds": self.interval,
                },
            )

            self._recover_response_state()
            self._recover_interrupted_approvals()

            if self.load_state() is None:
                self.initialize_baseline()

            while self.running:
                try:
                    self.run_once()
                    time.sleep(self.interval)
                except Exception as exc:
                    self.emit(
                        category="agent",
                        event_type="AGENT_ERROR",
                        severity="medium",
                        description="El agente encontró un error.",
                        evidence={
                            "error": str(exc),
                        },
                    )
                    time.sleep(self.interval)

            self.emit(
                category="agent",
                event_type="AGENT_STOPPED",
                severity="low",
                description="El agente de monitoreo fue detenido.",
                evidence={},
            )
        finally:
            self.event_sync_worker.stop()
            self.event_sync_worker.join(
                timeout=self.settings.sync_timeout_seconds + 1
            )
            self.heartbeat_worker.stop()
            self.heartbeat_worker.join(
                timeout=self.settings.sync_timeout_seconds + 1
            )

    def stop(self, *_: Any) -> None:
        self.running = False
        self.event_sync_worker.stop()
        self.heartbeat_worker.stop()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Nexora continuous monitoring agent"
    )

    parser.add_argument(
        "--interval",
        type=int,
        default=None,
        help=(
            "Intervalo de monitoreo en segundos. Si se omite, usa AUDITORIA_INTERVAL."
        ),
    )

    parser.add_argument(
        "--once",
        action="store_true",
        help="Ejecuta una sola comprobación",
    )

    parser.add_argument(
        "--reset-baseline",
        action="store_true",
        help="Elimina la línea base actual antes de ejecutar",
    )

    args = parser.parse_args()

    settings = load_agent_settings()

    agent = ContinuousAgent(
        interval=args.interval,
        settings=settings,
    )

    signal.signal(signal.SIGTERM, agent.stop)
    signal.signal(signal.SIGINT, agent.stop)

    if args.reset_baseline and agent.settings.state_file.exists():
        agent.settings.state_file.unlink()

    if args.once:
        agent.run_once()
        return

    agent.run_forever()


if __name__ == "__main__":
    main()
