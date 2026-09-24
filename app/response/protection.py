from __future__ import annotations

import json
import socket
import subprocess
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any

import psutil


@dataclass(frozen=True)
class ProtectionSnapshot:
    configured_ips: frozenset[str]
    ssh_peer_ips: frozenset[str]
    local_ips: frozenset[str]
    gateway_ips: frozenset[str]

    @property
    def protected_ips(self) -> set[str]:
        return set(
            self.configured_ips | self.ssh_peer_ips | self.local_ips | self.gateway_ips
        )


RouteRunner = Callable[
    [list[str]],
    tuple[int, str, str],
]


class ResponseProtectionResolver:
    def __init__(
        self,
        *,
        trusted_admin_ips: Iterable[str] = (),
        route_runner: RouteRunner | None = None,
    ) -> None:
        self.trusted_admin_ips = tuple(trusted_admin_ips)
        self._route_runner = route_runner or self._default_route_runner

    @staticmethod
    def _normalize_ip(
        value: str,
    ) -> str | None:
        candidate = value.strip()

        if "%" in candidate:
            candidate = candidate.split(
                "%",
                1,
            )[0]

        try:
            return str(ip_address(candidate))
        except ValueError:
            return None

    @classmethod
    def _normalize_many(
        cls,
        values: Iterable[str],
    ) -> frozenset[str]:
        result: set[str] = set()

        for value in values:
            normalized = cls._normalize_ip(value)

            if normalized is not None:
                result.add(normalized)

        return frozenset(result)

    @staticmethod
    def _default_route_runner(
        command: list[str],
    ) -> tuple[int, str, str]:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )

        return (
            result.returncode,
            result.stdout,
            result.stderr,
        )

    def _configured_ips(
        self,
    ) -> frozenset[str]:
        return self._normalize_many(self.trusted_admin_ips)

    def _ssh_peer_ips(
        self,
    ) -> frozenset[str]:
        peers: set[str] = set()

        try:
            connections = psutil.net_connections(kind="tcp")
        except (psutil.AccessDenied, OSError):
            return frozenset()

        for connection in connections:
            if connection.status != psutil.CONN_ESTABLISHED:
                continue

            if not connection.laddr:
                continue

            if connection.laddr.port != 22:
                continue

            if not connection.raddr:
                continue

            normalized = self._normalize_ip(connection.raddr.ip)

            if normalized is not None:
                peers.add(normalized)

        return frozenset(peers)

    def _local_ips(
        self,
    ) -> frozenset[str]:
        addresses: set[str] = set()

        try:
            interfaces = psutil.net_if_addrs()
        except OSError:
            return frozenset()

        for entries in interfaces.values():
            for entry in entries:
                if entry.family not in (
                    socket.AF_INET,
                    socket.AF_INET6,
                ):
                    continue

                normalized = self._normalize_ip(entry.address)

                if normalized is not None:
                    addresses.add(normalized)

        return frozenset(addresses)

    def _gateway_ips(
        self,
    ) -> frozenset[str]:
        gateways: set[str] = set()

        commands = (
            [
                "/usr/sbin/ip",
                "-j",
                "route",
                "show",
                "default",
            ],
            [
                "/usr/sbin/ip",
                "-j",
                "-6",
                "route",
                "show",
                "default",
            ],
        )

        for command in commands:
            rc, stdout, _ = self._route_runner(command)

            if rc != 0 or not stdout.strip():
                continue

            try:
                routes: Any = json.loads(stdout)
            except json.JSONDecodeError:
                continue

            if not isinstance(routes, list):
                continue

            for route in routes:
                if not isinstance(route, dict):
                    continue

                gateway = route.get("gateway")

                if not isinstance(
                    gateway,
                    str,
                ):
                    continue

                normalized = self._normalize_ip(gateway)

                if normalized is not None:
                    gateways.add(normalized)

        return frozenset(gateways)

    def resolve(
        self,
    ) -> ProtectionSnapshot:
        return ProtectionSnapshot(
            configured_ips=(self._configured_ips()),
            ssh_peer_ips=(self._ssh_peer_ips()),
            local_ips=(self._local_ips()),
            gateway_ips=(self._gateway_ips()),
        )
