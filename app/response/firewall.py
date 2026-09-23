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

TAILSCALE_IPV4 = ip_network("100.64.0.0/10")
TAILSCALE_IPV6 = ip_network("fd7a:115c:a1e0::/48")


class FirewallSafetyError(ValueError):
    pass


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
            raise FirewallSafetyError(
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
            raise FirewallSafetyError(
                "La dirección IP pertenece a una categoría protegida."
            )

        if isinstance(address, IPv4Address):
            if address in TAILSCALE_IPV4:
                raise FirewallSafetyError(
                    "Las direcciones Tailscale están protegidas en esta versión."
                )
        elif address in TAILSCALE_IPV6:
            raise FirewallSafetyError(
                "Las direcciones Tailscale están protegidas en esta versión."
            )
