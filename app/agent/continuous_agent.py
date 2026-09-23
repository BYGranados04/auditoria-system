from __future__ import annotations

import argparse
import hashlib
import json
import platform
import pwd
import signal
import socket
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psutil

from app.core.config import AgentSettings, load_agent_settings
from app.core.events import SecurityEvent
from app.detection.ssh_collector import SSHJournalCollector
from app.detection.ssh_correlation import SSHCorrelationEngine
from app.storage.event_repository import EventRepository

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
    ) -> SecurityEvent:
        event_model = SecurityEvent(
            timestamp=timestamp or datetime.now(UTC),
            hostname=self.hostname,
            source=source,
            category=category,
            event_type=event_type,
            severity=severity,
            description=description,
            evidence=evidence,
        )

        event = event_model.model_dump(mode="json")

        self._ensure_runtime_dirs()

        repository = EventRepository(self.settings.database_file)
        repository.initialize()
        repository.add(event_model)

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
                self.emit(
                    category="detection",
                    event_type=detection.event_type,
                    severity=detection.severity,
                    description=detection.description,
                    evidence=detection.evidence,
                    timestamp=record.timestamp,
                    source="detection-engine",
                )

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
        self.save_state(current)

    def run_forever(self) -> None:
        self.emit(
            category="agent",
            event_type="AGENT_STARTED",
            severity="low",
            description="El agente de monitoreo fue iniciado.",
            evidence={
                "interval_seconds": self.interval,
            },
        )

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

    def stop(self, *_: Any) -> None:
        self.running = False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Auditoria System continuous monitoring agent"
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
