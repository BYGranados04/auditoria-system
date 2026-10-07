"""Captura forense defensiva y de solo lectura (COLLECT_FORENSIC_EVIDENCE).

Principios:

- Solo se ejecutan comandos de una lista fija definida en este módulo. Ningún
  argumento proviene de eventos, del journal ni del usuario; la IP de origen
  solo se usa para filtrar en Python datos ya obtenidos.
- ``subprocess.run`` con lista de argumentos, sin ``shell=True``, con timeout,
  con un entorno mínimo (no se hereda el entorno del agente) y salida acotada.
- La evidencia se escribe en ``<state_dir>/evidence/<uuid>/`` con directorios
  0700 y archivos 0600 creados con ``O_EXCL | O_NOFOLLOW``.
- Nunca se leen archivos de configuración, identidad, claves ni variables de
  entorno. Toda salida pasa por un sanitizador de secretos evidentes.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from uuid import UUID

import psutil

from app.core.events import SecurityEvent

EVIDENCE_SCHEMA_VERSION = 1
CAPTURE_SEVERITIES = frozenset({"high", "critical"})
SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
SAFE_ENVIRONMENT = {"PATH": SAFE_PATH, "LC_ALL": "C", "LANG": "C"}
MAXIMUM_ARTIFACT_BYTES = 131_072
MAXIMUM_PROCESS_ENTRIES = 200
MAXIMUM_CMDLINE_CHARS = 256
TEMPORARY_PREFIX = ".tmp-"

# Nombre lógico -> (archivo, comando). Lista cerrada; no se amplía en tiempo
# de ejecución.
COMMAND_ARTIFACTS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("network_connections", "network_connections.txt", ("ss", "-tunap")),
    ("listening_sockets", "listening_sockets.txt", ("ss", "-tulpn")),
    ("logged_in_users", "logged_in_users.txt", ("who", "-u")),
    (
        "ssh_services",
        "ssh_services.txt",
        (
            "systemctl",
            "show",
            "ssh.service",
            "sshd.service",
            "--no-pager",
            "--property=Id,ActiveState,SubState,MainPID,ExecMainStartTimestamp",
        ),
    ),
    (
        "nftables_auditoria",
        "nftables_auditoria.txt",
        ("nft", "list", "table", "inet", "auditoria_response"),
    ),
)

SSH_JOURNAL_ARTIFACT: tuple[str, str, tuple[str, ...]] = (
    "ssh_journal",
    "ssh_journal.txt",
    (
        "journalctl",
        "--no-pager",
        "--output=short-iso-precise",
        "--lines=300",
        "--since=-15min",
        "--unit=ssh.service",
        "--unit=sshd.service",
    ),
)

_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?"
            r"-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        "[REDACTED PRIVATE KEY]",
    ),
    (
        re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}"),
        r"\1 [REDACTED]",
    ),
    (
        re.compile(
            r"(?i)\b(password|passwd|pwd|passphrase|secret|token|api[_-]?key"
            r"|access[_-]?key|credential|authorization)(\s*[=:]\s*)"
            r"(\"[^\"]*\"|'[^']*'|\S+)"
        ),
        r"\1\2[REDACTED]",
    ),
    (
        # Credenciales embebidas en URLs: esquema://usuario:clave@host
        re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^\s/:@]+):[^\s/@]+@"),
        r"\1:[REDACTED]@",
    ),
    (
        # curl -u usuario:clave
        re.compile(r"(\s-u\s+)([^\s:]+):(\S+)"),
        r"\1\2:[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)(--?(?:password|passwd|pass|token|secret|api-key|apikey))"
            r"(\s+|=)(\S+)"
        ),
        r"\1\2[REDACTED]",
    ),
)

CommandRunner = Callable[[list[str], int], tuple[int, str, str]]
ProcessProvider = Callable[[str | None], list[dict[str, Any]]]
QuickProvider = Callable[[str | None], dict[str, Any]]
MAXIMUM_QUICK_ENTRIES = 50
Clock = Callable[[], datetime]


def sanitize_text(text: str) -> str:
    sanitized = text
    for pattern, replacement in _REDACTIONS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def is_valid_capture_id(value: str) -> bool:
    try:
        return str(UUID(value)) == value
    except (ValueError, AttributeError, TypeError):
        return False


@dataclass(frozen=True)
class EvidenceSettings:
    enabled: bool
    base_dir: Path
    retention_days: int = 7
    max_bytes: int = 262_144
    max_total_bytes: int = 52_428_800
    command_timeout_seconds: int = 5


@dataclass
class EvidenceArtifact:
    name: str
    file: str | None
    status: str
    bytes: int = 0
    sha256: str | None = None
    truncated: bool = False
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "file": self.file,
            "status": self.status,
            "bytes": self.bytes,
            "sha256": self.sha256,
            "truncated": self.truncated,
            "error": self.error,
        }


@dataclass
class EvidenceCaptureResult:
    capture_id: str
    status: str
    metadata: dict[str, Any]
    artifacts: list[EvidenceArtifact] = field(default_factory=list)
    directory: Path | None = None

    def event_evidence(self) -> dict[str, Any]:
        """Metadatos que viajan al central (sin contenido ni rutas del host)."""

        return {
            "action": "COLLECT_FORENSIC_EVIDENCE",
            "capture_id": self.capture_id,
            "status": self.status,
            "incident_id": self.metadata.get("incident_id"),
            "detection_event_id": self.metadata.get("detection_event_id"),
            "detection_type": self.metadata.get("detection_type"),
            "severity": self.metadata.get("severity"),
            "source_ip": self.metadata.get("source_ip"),
            "captured_at": self.metadata.get("captured_at"),
            "completed_at": self.metadata.get("completed_at"),
            "total_bytes": self.metadata.get("total_bytes", 0),
            "max_bytes": self.metadata.get("max_bytes"),
            "truncated": self.metadata.get("truncated", False),
            "storage": "agent-local",
            "artifacts": [artifact.as_dict() for artifact in self.artifacts],
        }


class ForensicEvidenceError(RuntimeError):
    pass


class ForensicEvidenceCollector:
    def __init__(
        self,
        settings: EvidenceSettings,
        *,
        runner: CommandRunner | None = None,
        process_provider: ProcessProvider | None = None,
        quick_provider: QuickProvider | None = None,
        clock: Clock | None = None,
    ) -> None:
        self.settings = settings
        self._runner = runner or self._default_runner
        self._process_provider = process_provider or self._default_processes
        self._quick_provider = quick_provider or self._default_quick_snapshot
        self.clock = clock or (lambda: datetime.now(UTC))

    # ------------------------------------------------------------------
    # Ejecución segura
    # ------------------------------------------------------------------

    @staticmethod
    def _default_runner(
        command: list[str],
        timeout_seconds: int,
    ) -> tuple[int, str, str]:
        executable = shutil.which(command[0], path=SAFE_PATH)

        if executable is None:
            raise FileNotFoundError(f"{command[0]} no está disponible.")

        result = subprocess.run(  # noqa: S603 - lista fija, sin shell
            [executable, *command[1:]],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout_seconds,
            check=False,
            env=dict(SAFE_ENVIRONMENT),
            stdin=subprocess.DEVNULL,
        )

        return result.returncode, result.stdout, result.stderr

    @staticmethod
    def _default_processes(source_ip: str | None) -> list[dict[str, Any]]:
        """Procesos relevantes: SSH y procesos con sockets hacia el origen."""

        related_pids: set[int] = set()

        if source_ip is not None:
            try:
                for connection in psutil.net_connections(kind="inet"):
                    if (
                        connection.pid is not None
                        and connection.raddr
                        and _normalize_ip(connection.raddr.ip) == source_ip
                    ):
                        related_pids.add(connection.pid)
            except (psutil.AccessDenied, OSError):
                pass

        entries: list[dict[str, Any]] = []

        for process in psutil.process_iter(
            ["pid", "ppid", "name", "username", "status", "create_time"]
        ):
            info = process.info
            name = str(info.get("name") or "")
            relevant = name.startswith("sshd") or info.get("pid") in related_pids

            if not relevant:
                continue

            try:
                cmdline = " ".join(process.cmdline())
            except (psutil.Error, OSError):
                cmdline = ""

            entries.append(
                {
                    "pid": info.get("pid"),
                    "ppid": info.get("ppid"),
                    "name": name,
                    "username": info.get("username"),
                    "status": info.get("status"),
                    "create_time": info.get("create_time"),
                    "connected_to_source": info.get("pid") in related_pids,
                    "cmdline": cmdline,
                }
            )

            if len(entries) >= MAXIMUM_PROCESS_ENTRIES:
                break

        return entries

    # ------------------------------------------------------------------
    # Captura
    # ------------------------------------------------------------------

    @staticmethod
    def should_capture(event: SecurityEvent) -> bool:
        return event.category == "detection" and event.severity in CAPTURE_SEVERITIES

    # ------------------------------------------------------------------
    # Evidencia mínima rápida (sin subprocesos)
    # ------------------------------------------------------------------

    @staticmethod
    def _default_quick_snapshot(source_ip: str | None) -> dict[str, Any]:
        """Conexiones hacia el origen y sesiones activas, solo con psutil.

        No ejecuta comandos ni escribe en disco; está acotada en cantidad de
        entradas para que su costo sea predecible antes de la contención.
        """

        connections: list[dict[str, Any]] = []
        users: list[dict[str, Any]] = []
        errors: list[str] = []

        try:
            for connection in psutil.net_connections(kind="inet"):
                remote = connection.raddr
                if not remote or _normalize_ip(remote.ip) != source_ip:
                    continue
                connections.append(
                    {
                        "local": f"{connection.laddr.ip}:{connection.laddr.port}"
                        if connection.laddr
                        else None,
                        "remote": f"{remote.ip}:{remote.port}",
                        "status": connection.status,
                        "pid": connection.pid,
                    }
                )
                if len(connections) >= MAXIMUM_QUICK_ENTRIES:
                    break
        except (psutil.AccessDenied, OSError) as exc:
            errors.append(_short_error(str(exc)))

        try:
            for user in psutil.users()[:MAXIMUM_QUICK_ENTRIES]:
                users.append(
                    {
                        "name": user.name,
                        "terminal": user.terminal,
                        "host": user.host,
                        "started": user.started,
                    }
                )
        except (psutil.Error, OSError) as exc:
            errors.append(_short_error(str(exc)))

        return {
            "connections_to_source": connections,
            "logged_in_users": users,
            "errors": errors,
        }

    def quick_snapshot(self, detection: SecurityEvent) -> dict[str, Any] | None:
        if not self.settings.enabled or not self.should_capture(detection):
            return None

        source_ip = _normalize_ip(detection.evidence.get("source_ip"))
        captured_at = self.clock().astimezone(UTC)

        try:
            data = self._quick_provider(source_ip)
        except Exception as exc:
            data = {"errors": [_short_error(str(exc))]}

        return {
            "captured_at": captured_at.isoformat(),
            "source_ip": source_ip,
            **data,
        }

    def capture(
        self,
        detection: SecurityEvent,
        *,
        incident_id: str | None,
        quick_snapshot: dict[str, Any] | None = None,
    ) -> EvidenceCaptureResult | None:
        if not self.settings.enabled or not self.should_capture(detection):
            return None

        capture_id = str(detection.event_id)

        if not is_valid_capture_id(capture_id):
            raise ForensicEvidenceError("Identificador de captura no válido.")

        base_dir = self._ensure_base_dir()
        final_dir = base_dir / capture_id

        if os.path.lexists(final_dir):
            raise ForensicEvidenceError("La captura ya existe para esta detección.")

        temporary_dir = base_dir / f"{TEMPORARY_PREFIX}{capture_id}"
        self._remove_entry(temporary_dir)
        os.mkdir(temporary_dir, 0o700)
        os.chmod(temporary_dir, 0o700)

        captured_at = self.clock().astimezone(UTC)
        source_ip = _normalize_ip(detection.evidence.get("source_ip"))
        budget = _Budget(self.settings.max_bytes)
        artifacts: list[EvidenceArtifact] = []

        artifact_plan = list(COMMAND_ARTIFACTS)
        if detection.event_type.startswith("SSH_"):
            artifact_plan.insert(3, SSH_JOURNAL_ARTIFACT)

        try:
            if quick_snapshot is not None:
                artifacts.append(
                    self._store_text(
                        temporary_dir,
                        name="quick_snapshot",
                        filename="quick_snapshot.json",
                        content=sanitize_text(
                            json.dumps(
                                quick_snapshot,
                                ensure_ascii=False,
                                indent=2,
                                sort_keys=True,
                                default=str,
                            )
                        ),
                        budget=budget,
                        status="ok",
                        error=None,
                    )
                )

            for name, filename, command in artifact_plan:
                artifacts.append(
                    self._capture_command(
                        temporary_dir,
                        name=name,
                        filename=filename,
                        command=list(command),
                        budget=budget,
                    )
                )

            artifacts.append(
                self._capture_processes(
                    temporary_dir,
                    source_ip=source_ip,
                    budget=budget,
                )
            )

            completed_at = self.clock().astimezone(UTC)
            statuses = {artifact.status for artifact in artifacts}

            if statuses <= {"ok"}:
                status = "complete"
            elif "ok" in statuses:
                status = "partial"
            else:
                status = "failed"

            metadata = {
                "schema_version": EVIDENCE_SCHEMA_VERSION,
                "action": "COLLECT_FORENSIC_EVIDENCE",
                "capture_id": capture_id,
                "incident_id": incident_id,
                "detection_event_id": str(detection.event_id),
                "detection_type": detection.event_type,
                "severity": detection.severity,
                "source_ip": source_ip,
                "hostname": detection.hostname,
                "agent_id": detection.agent_id,
                "captured_at": captured_at.isoformat(),
                "completed_at": completed_at.isoformat(),
                "status": status,
                "max_bytes": self.settings.max_bytes,
                "total_bytes": budget.used,
                "truncated": any(artifact.truncated for artifact in artifacts),
                "artifacts": [artifact.as_dict() for artifact in artifacts],
            }

            self._write_file(
                temporary_dir / "metadata.json",
                json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True),
            )
            os.rename(temporary_dir, final_dir)
        except Exception:
            self._remove_entry(temporary_dir)
            raise

        return EvidenceCaptureResult(
            capture_id=capture_id,
            status=status,
            metadata=metadata,
            artifacts=artifacts,
            directory=final_dir,
        )

    def _capture_command(
        self,
        directory: Path,
        *,
        name: str,
        filename: str,
        command: list[str],
        budget: _Budget,
    ) -> EvidenceArtifact:
        if budget.exhausted:
            return EvidenceArtifact(
                name=name,
                file=None,
                status="skipped",
                truncated=True,
                error="Se alcanzó el tamaño máximo de la captura.",
            )

        try:
            returncode, stdout, stderr = self._runner(
                command,
                self.settings.command_timeout_seconds,
            )
        except FileNotFoundError:
            return EvidenceArtifact(
                name=name,
                file=None,
                status="unavailable",
                error=f"{command[0]} no está disponible.",
            )
        except subprocess.TimeoutExpired:
            return EvidenceArtifact(
                name=name,
                file=None,
                status="error",
                error="El comando excedió el tiempo máximo.",
            )
        except Exception as exc:  # pragma: no cover - defensivo
            return EvidenceArtifact(
                name=name,
                file=None,
                status="error",
                error=_short_error(str(exc)),
            )

        content = stdout
        status = "ok"
        error: str | None = None

        if returncode != 0:
            status = "error"
            error = _short_error(sanitize_text(stderr) or f"exit={returncode}")
            content = stdout or ""

        if not content:
            # Salida vacía válida (por ejemplo, sin usuarios conectados).
            return EvidenceArtifact(
                name=name,
                file=None,
                status=status,
                error=error,
            )

        return self._store_text(
            directory,
            name=name,
            filename=filename,
            content=sanitize_text(content),
            budget=budget,
            status=status,
            error=error,
        )

    def _capture_processes(
        self,
        directory: Path,
        *,
        source_ip: str | None,
        budget: _Budget,
    ) -> EvidenceArtifact:
        if budget.exhausted:
            return EvidenceArtifact(
                name="relevant_processes",
                file=None,
                status="skipped",
                truncated=True,
                error="Se alcanzó el tamaño máximo de la captura.",
            )

        try:
            processes = self._process_provider(source_ip)
        except Exception as exc:
            return EvidenceArtifact(
                name="relevant_processes",
                file=None,
                status="error",
                error=_short_error(str(exc)),
            )

        lines = ["PID\tPPID\tUSER\tSTATUS\tSOURCE_CONN\tNAME\tCMDLINE"]

        for entry in processes[:MAXIMUM_PROCESS_ENTRIES]:
            cmdline = sanitize_text(str(entry.get("cmdline") or ""))
            if len(cmdline) > MAXIMUM_CMDLINE_CHARS:
                cmdline = cmdline[:MAXIMUM_CMDLINE_CHARS] + "…"
            lines.append(
                "\t".join(
                    (
                        str(entry.get("pid", "")),
                        str(entry.get("ppid", "")),
                        str(entry.get("username") or ""),
                        str(entry.get("status") or ""),
                        "yes" if entry.get("connected_to_source") else "no",
                        _single_line(str(entry.get("name") or "")),
                        _single_line(cmdline),
                    )
                )
            )

        return self._store_text(
            directory,
            name="relevant_processes",
            filename="relevant_processes.txt",
            content="\n".join(lines) + "\n",
            budget=budget,
            status="ok",
            error=None,
        )

    def _store_text(
        self,
        directory: Path,
        *,
        name: str,
        filename: str,
        content: str,
        budget: _Budget,
        status: str,
        error: str | None,
    ) -> EvidenceArtifact:
        encoded = content.encode("utf-8", errors="replace")
        limit = min(MAXIMUM_ARTIFACT_BYTES, budget.remaining)
        truncated = len(encoded) > limit

        if truncated:
            encoded = encoded[:limit]

        if not encoded:
            return EvidenceArtifact(
                name=name,
                file=None,
                status="skipped",
                truncated=True,
                error="Se alcanzó el tamaño máximo de la captura.",
            )

        self._write_bytes(directory / filename, encoded)
        budget.consume(len(encoded))

        return EvidenceArtifact(
            name=name,
            file=filename,
            status=status,
            bytes=len(encoded),
            sha256=hashlib.sha256(encoded).hexdigest(),
            truncated=truncated,
            error=error,
        )

    # ------------------------------------------------------------------
    # Sistema de archivos seguro
    # ------------------------------------------------------------------

    def _ensure_base_dir(self) -> Path:
        base_dir = self.settings.base_dir

        if os.path.islink(base_dir):
            raise ForensicEvidenceError(
                "El directorio de evidencia no puede ser un enlace simbólico."
            )

        base_dir.parent.mkdir(parents=True, exist_ok=True)

        try:
            os.mkdir(base_dir, 0o700)
        except FileExistsError:
            pass

        info = os.lstat(base_dir)

        if not stat.S_ISDIR(info.st_mode):
            raise ForensicEvidenceError("La ruta de evidencia no es un directorio.")

        if stat.S_IMODE(info.st_mode) != 0o700:
            os.chmod(base_dir, 0o700)

        return base_dir

    def _write_file(self, path: Path, content: str) -> None:
        self._write_bytes(path, content.encode("utf-8"))

    @staticmethod
    def _write_bytes(path: Path, data: bytes) -> None:
        # O_NOFOLLOW (POSIX) y O_BINARY (Windows) solo existen en su
        # plataforma; en las demás valen 0 y no alteran la apertura.
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_BINARY", 0)
        )
        fchmod = getattr(os, "fchmod", None)
        descriptor = os.open(path, flags, 0o600)
        try:
            if fchmod is not None:
                # POSIX: permisos 0600 fijados sobre el descriptor abierto.
                fchmod(descriptor, 0o600)
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
        finally:
            os.close(descriptor)

        if fchmod is None:
            # Plataformas sin fchmod (Windows): os.chmod sobre la ruta solo
            # controla el atributo de solo lectura; el acceso efectivo depende
            # de las ACL heredadas del directorio. No se emula POSIX y
            # cualquier error se propaga.
            os.chmod(path, 0o600)

    @staticmethod
    def _remove_entry(path: Path) -> None:
        if os.path.islink(path) or path.is_file():
            path.unlink(missing_ok=True)
        elif path.is_dir():
            shutil.rmtree(path)

    # ------------------------------------------------------------------
    # Retención
    # ------------------------------------------------------------------

    def purge(self, *, now: datetime | None = None) -> int:
        """Elimina capturas vencidas y aplica el límite total de bytes.

        Solo considera entradas cuyo nombre es un UUID (o temporal de un
        UUID); cualquier otro archivo del directorio se ignora.
        """

        base_dir = self.settings.base_dir

        if not base_dir.is_dir() or os.path.islink(base_dir):
            return 0

        current = (now or self.clock()).astimezone(UTC)
        cutoff = current - timedelta(days=self.settings.retention_days)
        removed = 0
        captures: list[tuple[float, int, Path]] = []

        with os.scandir(base_dir) as entries:
            for entry in entries:
                name = entry.name
                temporary = name.startswith(TEMPORARY_PREFIX)
                capture_id = name[len(TEMPORARY_PREFIX) :] if temporary else name

                if not is_valid_capture_id(capture_id):
                    continue

                path = base_dir / name

                if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                    path.unlink(missing_ok=True)
                    removed += 1
                    continue

                modified = datetime.fromtimestamp(
                    entry.stat(follow_symlinks=False).st_mtime,
                    UTC,
                )

                if temporary or modified < cutoff:
                    shutil.rmtree(path)
                    removed += 1
                    continue

                captures.append((modified.timestamp(), _directory_size(path), path))

        total = sum(size for _, size, _ in captures)

        for _, size, path in sorted(captures):
            if total <= self.settings.max_total_bytes:
                break
            shutil.rmtree(path)
            total -= size
            removed += 1

        return removed


class _Budget:
    def __init__(self, limit: int) -> None:
        self.limit = max(limit, 0)
        self.used = 0

    @property
    def remaining(self) -> int:
        return max(self.limit - self.used, 0)

    @property
    def exhausted(self) -> bool:
        return self.remaining == 0

    def consume(self, amount: int) -> None:
        self.used += amount


def _directory_size(path: Path) -> int:
    total = 0
    for root, _directories, files in os.walk(path, followlinks=False):
        for filename in files:
            try:
                total += os.lstat(os.path.join(root, filename)).st_size
            except OSError:
                continue
    return total


def _normalize_ip(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ip_address(value.split("%", 1)[0]))
    except ValueError:
        return None


def _single_line(value: str) -> str:
    return " ".join(value.split())


def _short_error(value: str) -> str:
    return _single_line(value)[:300]
