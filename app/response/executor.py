from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address, ip_address

from app.response.models import (
    ResponseDecision,
    ResponseExecutionResult,
)
from app.response.policy import ResponsePolicy


class ResponseExecutor:
    def __init__(
        self,
        policy: ResponsePolicy,
        *,
        dry_run: bool = True,
    ) -> None:
        if not dry_run:
            raise ValueError(
                "La ejecución real de respuestas todavía no está implementada."
            )

        self.policy = policy
        self.dry_run = dry_run

    def execute(
        self,
        decision: ResponseDecision,
    ) -> ResponseExecutionResult:
        if decision.action != "TEMPORARY_BLOCK_IP":
            return self._skipped(
                decision,
                reason=("La decisión no requiere una acción ejecutable."),
            )

        if not decision.execution_allowed:
            return self._skipped(
                decision,
                reason=("La decisión no está autorizada para ejecución."),
            )

        if decision.target_ip is None:
            return self._skipped(
                decision,
                reason=("La decisión no contiene una dirección IP objetivo."),
            )

        try:
            address = ip_address(decision.target_ip)
        except ValueError:
            return self._skipped(
                decision,
                reason=("La dirección IP objetivo no es válida."),
            )

        normalized_ip = str(address)

        if self._is_protected_address(address):
            return self._skipped(
                decision,
                target_ip=normalized_ip,
                reason=("El ejecutor rechazó una dirección IP protegida."),
            )

        if normalized_ip in self.policy.trusted_admin_ips:
            return self._skipped(
                decision,
                target_ip=normalized_ip,
                reason=("El ejecutor rechazó una fuente administrativa confiable."),
            )

        if decision.duration_seconds is None:
            return self._skipped(
                decision,
                target_ip=normalized_ip,
                reason=("La decisión no contiene duración para el bloqueo temporal."),
            )

        return ResponseExecutionResult(
            detection_event_id=decision.detection_event_id,
            action=decision.action,
            target_ip=normalized_ip,
            duration_seconds=decision.duration_seconds,
            status="DRY_RUN",
            dry_run=True,
            executed=False,
            reason=(
                "La acción fue validada en modo dry-run; no se modificó el sistema."
            ),
        )

    def _skipped(
        self,
        decision: ResponseDecision,
        *,
        reason: str,
        target_ip: str | None = None,
    ) -> ResponseExecutionResult:
        return ResponseExecutionResult(
            detection_event_id=decision.detection_event_id,
            action=decision.action,
            target_ip=(target_ip if target_ip is not None else decision.target_ip),
            duration_seconds=decision.duration_seconds,
            status="SKIPPED",
            dry_run=self.dry_run,
            executed=False,
            reason=reason,
        )

    @staticmethod
    def _is_protected_address(
        address: IPv4Address | IPv6Address,
    ) -> bool:
        return any(
            (
                address.is_loopback,
                address.is_unspecified,
                address.is_multicast,
                address.is_link_local,
            )
        )
