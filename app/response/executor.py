from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any
from uuid import UUID, uuid4

from app.response.firewall import (
    SUPPORTED_PROTOCOLS,
    FirewallSafetyError,
    NftablesFirewallPlanner,
    ProtectedAddressError,
    TemporaryBlockPlan,
    TemporaryPortBlockPlan,
    static_protection_reason,
)
from app.response.firewall_backend import (
    NftablesFirewallBackend,
)
from app.response.models import (
    EXECUTABLE_ACTIONS,
    PORT_SCOPED_ACTIONS,
    ResponseDecision,
    ResponseExecutionResult,
)
from app.response.policy import ResponsePolicy
from app.response.protection import (
    ResponseProtectionResolver,
)
from app.storage.event_repository import EventRepository

Clock = Callable[[], datetime]


class ResponseExecutor:
    def __init__(
        self,
        policy: ResponsePolicy,
        *,
        dry_run: bool = True,
        repository: EventRepository | None = None,
        backend: NftablesFirewallBackend | None = None,
        protection_resolver: ResponseProtectionResolver | None = None,
        clock: Clock | None = None,
    ) -> None:
        if not dry_run and repository is None:
            raise ValueError("La ejecución real requiere un repositorio.")

        if not dry_run and backend is None:
            raise ValueError("La ejecución real requiere un backend de firewall.")

        self.policy = policy
        self.dry_run = dry_run
        self.repository = repository
        self.backend = backend
        self.protection_resolver = protection_resolver or ResponseProtectionResolver(
            trusted_admin_ips=(policy.trusted_admin_ips)
        )
        self.clock = clock or (lambda: datetime.now(UTC))

    def execute(
        self,
        decision: ResponseDecision,
        *,
        response_event_id: UUID | None = None,
        execution_event_id: UUID | None = None,
    ) -> ResponseExecutionResult:
        if decision.action not in EXECUTABLE_ACTIONS:
            return self._skipped(
                decision,
                reason=("La decisión no requiere una acción ejecutable."),
            )

        port_block = decision.action == "TEMPORARY_BLOCK_IP_PORT"

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
                protection_rejected=True,
            )

        if normalized_ip in self.policy.trusted_admin_ips:
            return self._skipped(
                decision,
                target_ip=normalized_ip,
                reason=("El ejecutor rechazó una fuente administrativa confiable."),
                protection_rejected=True,
            )

        static_reason = static_protection_reason(normalized_ip)

        if static_reason is not None:
            # Tailscale y demás categorías estáticas: la decisión se conserva
            # y la capa de ejecución documenta por qué no se aplica.
            return self._skipped(
                decision,
                target_ip=normalized_ip,
                reason=(
                    f"El ejecutor rechazó una dirección protegida: {static_reason}"
                ),
                protection_rejected=True,
            )

        if decision.duration_seconds is None:
            return self._skipped(
                decision,
                target_ip=normalized_ip,
                reason=("La decisión no contiene duración para el bloqueo temporal."),
            )

        if port_block and (
            decision.protocol not in SUPPORTED_PROTOCOLS
            or decision.port is None
            or not 1 <= decision.port <= 65535
        ):
            return self._skipped(
                decision,
                target_ip=normalized_ip,
                reason=(
                    "La decisión de bloqueo por puerto no contiene "
                    "un protocolo y puerto válidos."
                ),
            )

        if self.dry_run:
            return ResponseExecutionResult(
                detection_event_id=(decision.detection_event_id),
                action=decision.action,
                target_ip=normalized_ip,
                duration_seconds=(decision.duration_seconds),
                status="DRY_RUN",
                dry_run=True,
                executed=False,
                reason=(
                    "La acción fue validada en modo dry-run; no se modificó el sistema."
                ),
                **self._service_fields(decision),
            )

        if response_event_id is None or execution_event_id is None:
            return self._failed(
                decision,
                target_ip=normalized_ip,
                reason=("La ejecución real requiere identificadores de correlación."),
            )

        assert self.repository is not None
        assert self.backend is not None

        try:
            snapshot = self.protection_resolver.resolve()

            planner = NftablesFirewallPlanner(protected_ips=(snapshot.protected_ips))

            plan: TemporaryBlockPlan | TemporaryPortBlockPlan
            if port_block:
                assert decision.protocol is not None
                assert decision.port is not None
                plan = planner.plan_temporary_port_block(
                    normalized_ip,
                    decision.protocol,
                    decision.port,
                    decision.duration_seconds,
                )
            else:
                plan = planner.plan_temporary_block(
                    normalized_ip,
                    decision.duration_seconds,
                )

        except FirewallSafetyError as exc:
            return self._skipped(
                decision,
                target_ip=normalized_ip,
                reason=(f"El bloqueo fue rechazado por protección dinámica: {exc}"),
                protection_rejected=isinstance(exc, ProtectedAddressError),
            )

        except Exception as exc:
            return self._failed(
                decision,
                target_ip=normalized_ip,
                reason=(f"No fue posible resolver las protecciones dinámicas: {exc}"),
            )

        requested_at = self.clock().astimezone(UTC)

        expires_at = requested_at + timedelta(seconds=plan.duration_seconds)

        block_id = uuid4()

        try:
            self.repository.expire_response_blocks(
                now=requested_at,
            )

            scope = self._block_scope_fields(plan)
            existing = self.repository.find_live_response_block(
                hostname=decision.hostname,
                target_ip=plan.target_ip,
                action=str(scope.get("action", "TEMPORARY_BLOCK_IP")),
                protocol=scope.get("protocol"),
                port=scope.get("port"),
                now=requested_at,
            )
        except Exception as exc:
            return self._failed(
                decision,
                target_ip=plan.target_ip,
                reason=(f"No fue posible consultar bloqueos vigentes: {exc}"),
            )

        if existing is not None:
            # Idempotencia: varias detecciones del mismo ataque no duplican
            # el bloqueo ni se registran como fallo.
            return self._skipped(
                decision,
                target_ip=plan.target_ip,
                reason=(
                    "Ya existe un bloqueo vigente equivalente "
                    f"({existing['block_id']}); no se duplicó."
                ),
            )

        try:

            self.repository.create_response_block(
                block_id=str(block_id),
                detection_event_id=str(decision.detection_event_id),
                response_event_id=str(response_event_id),
                hostname=decision.hostname,
                target_ip=plan.target_ip,
                family=plan.family,
                duration_seconds=(plan.duration_seconds),
                requested_at=requested_at,
                expires_at=expires_at,
                **self._block_scope_fields(plan),
            )

        except Exception as exc:
            return self._failed(
                decision,
                target_ip=plan.target_ip,
                reason=(f"No fue posible registrar el bloqueo como PENDING: {exc}"),
            )

        try:
            if isinstance(plan, TemporaryPortBlockPlan):
                self.backend.prepare_port_blocking()
            else:
                self.backend.prepare()

            self.backend.add_temporary_block(plan)

        except Exception as exc:
            error = f"No fue posible aplicar el bloqueo temporal: {exc}"

            self._mark_pending_failed(
                block_id,
                error=error,
            )

            return self._failed(
                decision,
                target_ip=plan.target_ip,
                block_id=block_id,
                reason=error,
            )

        try:
            applied_at = self.clock().astimezone(UTC)

            self.repository.mark_response_block_active(
                str(block_id),
                execution_event_id=str(execution_event_id),
                applied_at=applied_at,
            )

        except Exception as exc:
            activation_error = (
                f"El bloqueo fue aplicado, pero no pudo confirmarse como ACTIVE: {exc}"
            )

            rollback_error: str | None = None

            try:
                self.backend.remove_block(plan)
            except Exception as rollback_exc:
                rollback_error = str(rollback_exc)

            final_error = activation_error

            if rollback_error is not None:
                final_error += (
                    f" Además, falló la reversión del bloqueo: {rollback_error}"
                )
            else:
                final_error += " El bloqueo fue revertido."

            self._mark_pending_failed(
                block_id,
                error=final_error,
            )

            return self._failed(
                decision,
                target_ip=plan.target_ip,
                block_id=block_id,
                reason=final_error,
            )

        return ResponseExecutionResult(
            detection_event_id=(decision.detection_event_id),
            action=decision.action,
            target_ip=plan.target_ip,
            duration_seconds=(plan.duration_seconds),
            status="EXECUTED",
            dry_run=False,
            executed=True,
            reason=("El bloqueo temporal fue aplicado y registrado como ACTIVE."),
            block_id=block_id,
            **self._service_fields(decision),
        )

    def _mark_pending_failed(
        self,
        block_id: UUID,
        *,
        error: str,
    ) -> None:
        assert self.repository is not None

        try:
            self.repository.mark_response_block_failed(
                str(block_id),
                error=error,
            )
        except Exception:
            # La falla original conserva prioridad.
            # Recovery podrá reconciliar un PENDING
            # persistente durante el siguiente inicio.
            pass

    def _failed(
        self,
        decision: ResponseDecision,
        *,
        reason: str,
        target_ip: str | None = None,
        block_id: UUID | None = None,
    ) -> ResponseExecutionResult:
        return ResponseExecutionResult(
            detection_event_id=(decision.detection_event_id),
            action=decision.action,
            target_ip=(target_ip if target_ip is not None else decision.target_ip),
            duration_seconds=(decision.duration_seconds),
            status="FAILED",
            dry_run=self.dry_run,
            executed=False,
            reason=reason,
            block_id=block_id,
            **self._service_fields(decision),
        )

    def _skipped(
        self,
        decision: ResponseDecision,
        *,
        reason: str,
        target_ip: str | None = None,
        protection_rejected: bool = False,
    ) -> ResponseExecutionResult:
        return ResponseExecutionResult(
            detection_event_id=(decision.detection_event_id),
            action=decision.action,
            target_ip=(target_ip if target_ip is not None else decision.target_ip),
            duration_seconds=(decision.duration_seconds),
            status="SKIPPED",
            dry_run=self.dry_run,
            executed=False,
            reason=reason,
            protection_rejected=protection_rejected,
            **self._service_fields(decision),
        )

    @staticmethod
    def _service_fields(
        decision: ResponseDecision,
    ) -> dict[str, Any]:
        fields: dict[str, Any] = {"approval_id": decision.approval_id}

        if decision.action not in PORT_SCOPED_ACTIONS:
            return fields

        port = decision.port
        valid_port = port if port is not None and 1 <= port <= 65535 else None

        return {
            **fields,
            "protocol": decision.protocol,
            "port": valid_port,
        }

    @staticmethod
    def _block_scope_fields(
        plan: TemporaryBlockPlan | TemporaryPortBlockPlan,
    ) -> dict[str, Any]:
        if isinstance(plan, TemporaryPortBlockPlan):
            return {
                "action": "TEMPORARY_BLOCK_IP_PORT",
                "protocol": plan.protocol,
                "port": plan.port,
            }

        # El bloqueo por IP conserva exactamente la llamada histórica.
        return {}

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
