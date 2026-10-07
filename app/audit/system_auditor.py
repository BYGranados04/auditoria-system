from __future__ import annotations

import json
import platform
import socket
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import psutil

try:
    import pwd
except ImportError:  # pragma: no cover - depende de la plataforma
    # `pwd` es exclusivo de Unix. En plataformas sin él (por ejemplo,
    # Windows en desarrollo) la enumeración de usuarios devuelve vacío.
    pwd = None  # type: ignore[assignment]


@dataclass
class Finding:
    code: str
    title: str
    severity: str
    description: str
    recommendation: str


class SystemAuditor:
    def __init__(self) -> None:
        self.findings: list[Finding] = []

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
    def _os_release() -> dict[str, str]:
        result: dict[str, str] = {}
        path = Path("/etc/os-release")

        if not path.exists():
            return result

        for line in path.read_text(errors="ignore").splitlines():
            if "=" not in line:
                continue

            key, value = line.split("=", 1)
            result[key] = value.strip().strip('"')

        return result

    def _network_interfaces(self) -> list[dict[str, Any]]:
        addresses = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        interfaces: list[dict[str, Any]] = []

        for name, addrs in addresses.items():
            interface = {
                "name": name,
                "up": stats.get(name).isup if name in stats else None,
                "addresses": [],
            }

            for addr in addrs:
                if addr.family == socket.AF_INET:
                    family = "ipv4"
                elif addr.family == socket.AF_INET6:
                    family = "ipv6"
                else:
                    continue

                interface["addresses"].append(
                    {
                        "family": family,
                        "address": addr.address,
                    }
                )

            interfaces.append(interface)

        return interfaces

    def _listening_ports(self) -> list[dict[str, Any]]:
        ports: set[tuple[str, str, int]] = set()

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

            ports.add(
                (
                    protocol,
                    conn.laddr.ip,
                    conn.laddr.port,
                )
            )

        return [
            {
                "protocol": protocol,
                "address": address,
                "port": port,
            }
            for protocol, address, port in sorted(
                ports,
                key=lambda item: (item[2], item[0], item[1]),
            )
        ]

    def _ufw(self) -> dict[str, Any]:
        rc, stdout, stderr = self._run(["ufw", "status", "verbose"])

        active = rc == 0 and "Status: active" in stdout

        if not active:
            self.findings.append(
                Finding(
                    code="FIREWALL_DISABLED",
                    title="Firewall UFW no activo",
                    severity="high",
                    description="No se detectó UFW en estado activo.",
                    recommendation=(
                        "Habilitar UFW y definir únicamente las reglas necesarias."
                    ),
                )
            )

        return {
            "active": active,
            "raw": stdout if stdout else stderr,
        }

    def _ssh(self) -> dict[str, Any]:
        rc, stdout, stderr = self._run(["sshd", "-T"])

        if rc != 0:
            return {
                "available": False,
                "error": stderr or stdout,
            }

        config: dict[str, str] = {}

        wanted = {
            "passwordauthentication",
            "permitrootlogin",
            "pubkeyauthentication",
        }

        for line in stdout.splitlines():
            if " " not in line:
                continue

            key, value = line.split(None, 1)

            if key in wanted:
                config[key] = value

        if config.get("passwordauthentication") == "yes":
            self.findings.append(
                Finding(
                    code="SSH_PASSWORD_AUTH",
                    title="Autenticación SSH por contraseña habilitada",
                    severity="medium",
                    description=(
                        "El servicio SSH acepta autenticación mediante contraseña."
                    ),
                    recommendation=(
                        "Usar claves públicas y deshabilitar PasswordAuthentication "
                        "cuando la operación del servidor lo permita."
                    ),
                )
            )

        root_login = config.get("permitrootlogin")

        if root_login and root_login != "no":
            self.findings.append(
                Finding(
                    code="SSH_ROOT_LOGIN",
                    title="Inicio de sesión SSH directo como root permitido",
                    severity="medium",
                    description=(
                        f"PermitRootLogin tiene el valor '{root_login}'. "
                        "Todavía puede existir acceso SSH directo como root "
                        "mediante métodos autorizados."
                    ),
                    recommendation=(
                        "Configurar PermitRootLogin no cuando la administración "
                        "mediante un usuario con sudo esté verificada."
                    ),
                )
            )

        return {
            "available": True,
            "password_authentication": config.get("passwordauthentication"),
            "permit_root_login": config.get("permitrootlogin"),
            "public_key_authentication": config.get("pubkeyauthentication"),
        }

    def _pending_updates(self) -> dict[str, Any]:
        rc, stdout, stderr = self._run(["apt", "list", "--upgradable"])

        if rc != 0:
            return {
                "available": False,
                "error": stderr,
            }

        packages = []

        for line in stdout.splitlines():
            line = line.strip()

            if not line or line.startswith("Listing"):
                continue

            packages.append(line.split("/", 1)[0])

        if packages:
            self.findings.append(
                Finding(
                    code="PENDING_UPDATES",
                    title="Actualizaciones pendientes",
                    severity="medium",
                    description=(
                        f"Se detectaron {len(packages)} paquetes actualizables."
                    ),
                    recommendation="Revisar y aplicar las actualizaciones disponibles.",
                )
            )

        return {
            "count": len(packages),
            "packages": packages,
        }

    @staticmethod
    def _users() -> list[dict[str, Any]]:
        users: list[dict[str, Any]] = []

        if pwd is None:
            return users

        for entry in pwd.getpwall():
            if entry.pw_uid == 0 or entry.pw_uid >= 1000:
                if entry.pw_uid == 65534:
                    continue

                users.append(
                    {
                        "username": entry.pw_name,
                        "uid": entry.pw_uid,
                        "gid": entry.pw_gid,
                        "shell": entry.pw_shell,
                        "home": entry.pw_dir,
                    }
                )

        return users

    def audit(self) -> dict[str, Any]:
        os_release = self._os_release()

        result = {
            "system": {
                "hostname": platform.node(),
                "os": os_release.get("PRETTY_NAME"),
                "kernel": platform.release(),
                "architecture": platform.machine(),
            },
            "network": {
                "interfaces": self._network_interfaces(),
                "listening_ports": self._listening_ports(),
            },
            "firewall": self._ufw(),
            "ssh": self._ssh(),
            "updates": self._pending_updates(),
            "users": self._users(),
        }

        result["findings"] = [asdict(item) for item in self.findings]
        result["summary"] = {
            "total_findings": len(self.findings),
            "high": sum(finding.severity == "high" for finding in self.findings),
            "medium": sum(finding.severity == "medium" for finding in self.findings),
            "low": sum(finding.severity == "low" for finding in self.findings),
        }

        return result


def main() -> None:
    auditor = SystemAuditor()
    print(
        json.dumps(
            auditor.audit(),
            indent=2,
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
