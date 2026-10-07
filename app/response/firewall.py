from __future__ import annotations

from dataclasses import dataclass
from ipaddress import (
    IPv4Address,
    IPv6Address,
    ip_address,
    ip_network,
)
from typing import Literal

FirewallFamily = Literal["ip", "ip6"]
FirewallProtocol = Literal["tcp", "udp"]

SUPPORTED_PROTOCOLS: frozenset[str] = frozenset({"tcp", "udp"})

TAILSCALE_IPV4 = ip_network("100.64.0.0/10")
TAILSCALE_IPV6 = ip_network("fd7a:115c:a1e0::/48")


class FirewallSafetyError(ValueError):
    pass


class ProtectedAddressError(FirewallSafetyError):
    """La dirección objetivo pertenece a una categoría protegida.

    Subclase de FirewallSafetyError para conservar la compatibilidad con
    quienes ya capturan la excepción base.
    """


def static_protection_reason(target_ip: str) -> str | None:
    """Motivo de protección estática (sin estado del host) o None."""

    try:
        NftablesFirewallPlanner._validate_address(ip_address(target_ip))
    except ProtectedAddressError as exc:
        return str(exc)
    except ValueError:
        return None
    return None


@dataclass(frozen=True)
class TemporaryBlockPlan:
    family: FirewallFamily
    target_ip: str
    duration_seconds: int
    table_family: str = "inet"
    table_name: str = "auditoria_response"

    @property
    def set_name(self) -> str:
        if self.family == "ip":
            return "blocked_ipv4"

        return "blocked_ipv6"

    def render_add_element(self) -> str:
        return (
            f"add element {self.table_family} "
            f"{self.table_name} {self.set_name} "
            f"{{ {self.target_ip} "
            f"timeout {self.duration_seconds}s }}"
        )

    def render_delete_element(self) -> str:
        return (
            f"delete element {self.table_family} "
            f"{self.table_name} {self.set_name} "
            f"{{ {self.target_ip} }}"
        )


@dataclass(frozen=True)
class TemporaryPortBlockPlan:
    """Bloqueo temporal de una IP hacia un único protocolo/puerto.

    Usa sets concatenados ``ipvX_addr . inet_proto . inet_service`` con
    ``flags timeout``; el kernel expira el elemento sin intervención.
    """

    family: FirewallFamily
    target_ip: str
    protocol: FirewallProtocol
    port: int
    duration_seconds: int
    table_family: str = "inet"
    table_name: str = "auditoria_response"

    @property
    def set_name(self) -> str:
        if self.family == "ip":
            return "blocked_ipv4_port"

        return "blocked_ipv6_port"

    @property
    def element(self) -> str:
        return f"{self.target_ip} . {self.protocol} . {self.port}"

    def render_add_element(self) -> str:
        return (
            f"add element {self.table_family} "
            f"{self.table_name} {self.set_name} "
            f"{{ {self.element} "
            f"timeout {self.duration_seconds}s }}"
        )

    def render_delete_element(self) -> str:
        return (
            f"delete element {self.table_family} "
            f"{self.table_name} {self.set_name} "
            f"{{ {self.element} }}"
        )


class NftablesFirewallPlanner:
    MINIMUM_DURATION_SECONDS = 60
    MAXIMUM_DURATION_SECONDS = 86400

    def __init__(
        self,
        *,
        protected_ips: set[str] | None = None,
    ) -> None:
        self.protected_ips = {
            str(ip_address(value)) for value in (protected_ips or set())
        }

    def plan_temporary_block(
        self,
        target_ip: str,
        duration_seconds: int,
    ) -> TemporaryBlockPlan:
        address = self._parse_address(target_ip)

        self._validate_duration(duration_seconds)
        self._validate_address(address)

        normalized_ip = str(address)

        if normalized_ip in self.protected_ips:
            raise ProtectedAddressError(
                "La dirección IP pertenece a la lista de direcciones protegidas."
            )

        family: FirewallFamily

        if isinstance(address, IPv4Address):
            family = "ip"
        else:
            family = "ip6"

        return TemporaryBlockPlan(
            family=family,
            target_ip=normalized_ip,
            duration_seconds=duration_seconds,
        )

    def plan_temporary_port_block(
        self,
        target_ip: str,
        protocol: str,
        port: int,
        duration_seconds: int,
    ) -> TemporaryPortBlockPlan:
        if protocol not in SUPPORTED_PROTOCOLS:
            raise FirewallSafetyError("El protocolo del bloqueo no está permitido.")

        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
        ):
            raise FirewallSafetyError("El puerto del bloqueo no es válido.")

        # Reutiliza exactamente las mismas validaciones del bloqueo por IP:
        # duración, categorías protegidas, Tailscale y protecciones dinámicas.
        base = self.plan_temporary_block(
            target_ip,
            duration_seconds,
        )

        return TemporaryPortBlockPlan(
            family=base.family,
            target_ip=base.target_ip,
            protocol="tcp" if protocol == "tcp" else "udp",
            port=port,
            duration_seconds=base.duration_seconds,
        )

    @staticmethod
    def render_prepare_port_ruleset() -> str:
        """Estructuras para bloqueo IP+puerto, idempotentes.

        ``add`` no falla si el objeto existe y ``flush chain`` + reinsertar
        reglas dentro de la misma transacción evita reglas duplicadas. No
        modifica ``blocked_ipv4``, ``blocked_ipv6`` ni la cadena ``input``.
        """

        return """add table inet auditoria_response
add set inet auditoria_response blocked_ipv4_port { type ipv4_addr . inet_proto . inet_service; flags timeout; }
add set inet auditoria_response blocked_ipv6_port { type ipv6_addr . inet_proto . inet_service; flags timeout; }
add chain inet auditoria_response input_port { type filter hook input priority -10; policy accept; }
flush chain inet auditoria_response input_port
add rule inet auditoria_response input_port iifname "lo" return
add rule inet auditoria_response input_port iifname "tailscale0" return
add rule inet auditoria_response input_port ip saddr . meta l4proto . th dport @blocked_ipv4_port counter drop
add rule inet auditoria_response input_port ip6 saddr . meta l4proto . th dport @blocked_ipv6_port counter drop
"""  # noqa: E501

    @staticmethod
    def render_prepare_ruleset() -> str:
        return """table inet auditoria_response {
    set blocked_ipv4 {
        type ipv4_addr;
        flags timeout;
    }

    set blocked_ipv6 {
        type ipv6_addr;
        flags timeout;
    }

    chain input {
        type filter hook input priority -10; policy accept;

        iifname "lo" return
        iifname "tailscale0" return

        ip saddr @blocked_ipv4 counter drop
        ip6 saddr @blocked_ipv6 counter drop
    }
}
"""

    @staticmethod
    def _parse_address(
        target_ip: str,
    ) -> IPv4Address | IPv6Address:
        try:
            return ip_address(target_ip)
        except ValueError as exc:
            raise FirewallSafetyError("La dirección IP objetivo no es válida.") from exc

    def _validate_duration(
        self,
        duration_seconds: int,
    ) -> None:
        if not (
            self.MINIMUM_DURATION_SECONDS
            <= duration_seconds
            <= self.MAXIMUM_DURATION_SECONDS
        ):
            raise FirewallSafetyError(
                "La duración del bloqueo está fuera del rango permitido."
            )

    @staticmethod
    def _validate_address(
        address: IPv4Address | IPv6Address,
    ) -> None:
        if any(
            (
                address.is_loopback,
                address.is_unspecified,
                address.is_multicast,
                address.is_link_local,
            )
        ):
            raise ProtectedAddressError(
                "La dirección IP pertenece a una categoría protegida."
            )

        if isinstance(address, IPv4Address):
            if address in TAILSCALE_IPV4:
                raise ProtectedAddressError(
                    "Las direcciones Tailscale están protegidas en esta versión."
                )
        elif address in TAILSCALE_IPV6:
            raise ProtectedAddressError(
                "Las direcciones Tailscale están protegidas en esta versión."
            )
