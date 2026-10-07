from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from math import ceil
from typing import Any

from app.response.firewall import (
    NftablesFirewallPlanner,
    TemporaryBlockPlan,
    TemporaryPortBlockPlan,
)
from app.response.firewall_backend import (
    NftablesFirewallBackend,
)
from app.storage.event_repository import EventRepository


@dataclass(frozen=True)
class ResponseRecoverySummary:
    table_created: bool
    expired_count: int
    failed_pending_count: int
    restored_count: int
    failed_restore_count: int


class ResponseRecoveryManager:
    PENDING_RECOVERY_REASON = (
        "La ejecución quedó pendiente durante "
        "un reinicio del agente y no puede "
        "confirmarse como aplicada."
    )

    def __init__(
        self,
        *,
        repository: EventRepository,
        backend: NftablesFirewallBackend,
        planner: NftablesFirewallPlanner,
    ) -> None:
        self.repository = repository
        self.backend = backend
        self.planner = planner

    @staticmethod
    def _normalize_now(
        now: datetime,
    ) -> datetime:
        if now.tzinfo is None:
            raise ValueError("La recuperación requiere una fecha con zona horaria.")

        return now.astimezone(UTC)

    @staticmethod
    def _parse_timestamp(
        value: Any,
    ) -> datetime:
        if not isinstance(value, str):
            raise ValueError("expires_at no contiene una fecha válida.")

        parsed = datetime.fromisoformat(value)

        if parsed.tzinfo is None:
            raise ValueError("expires_at no contiene zona horaria.")

        return parsed.astimezone(UTC)

    def _plan_restored_block(
        self,
        block: dict[str, Any],
        *,
        now: datetime,
    ) -> TemporaryBlockPlan | TemporaryPortBlockPlan:
        expires_at = self._parse_timestamp(block["expires_at"])

        remaining_seconds = ceil((expires_at - now).total_seconds())

        if remaining_seconds <= 0:
            raise ValueError("El bloqueo ya venció.")

        if remaining_seconds > 86400:
            raise ValueError(
                "El tiempo restante del bloqueo supera el máximo permitido."
            )

        validation_duration = max(
            60,
            remaining_seconds,
        )

        action = block.get("action") or "TEMPORARY_BLOCK_IP"

        plan: TemporaryBlockPlan | TemporaryPortBlockPlan
        if action == "TEMPORARY_BLOCK_IP_PORT":
            plan = self.planner.plan_temporary_port_block(
                block["target_ip"],
                str(block.get("protocol")),
                block.get("port"),  # type: ignore[arg-type]
                validation_duration,
            )
        elif action == "TEMPORARY_BLOCK_IP":
            plan = self.planner.plan_temporary_block(
                block["target_ip"],
                validation_duration,
            )
        else:
            raise ValueError("La acción almacenada del bloqueo no es soportada.")

        stored_family = block.get("family")

        if stored_family != plan.family:
            raise ValueError(
                "La familia IP almacenada no coincide con la dirección objetivo."
            )

        return replace(
            plan,
            duration_seconds=remaining_seconds,
        )

    def recover(
        self,
        *,
        now: datetime | None = None,
    ) -> ResponseRecoverySummary:
        current = self._normalize_now(now or datetime.now(UTC))

        expired_count = self.repository.expire_response_blocks(
            now=current,
        )

        failed_pending_count = self.repository.fail_pending_response_blocks(
            reason=self.PENDING_RECOVERY_REASON,
        )

        active_blocks = self.repository.list_active_response_blocks(
            now=current,
        )

        table_created = False

        if active_blocks:
            table_created = self.backend.prepare()

        if any(
            block.get("action") == "TEMPORARY_BLOCK_IP_PORT"
            for block in active_blocks
        ):
            # Si falla, cada bloqueo por puerto se marcará FAILED más abajo
            # porque add_temporary_block no encontrará su set.
            try:
                self.backend.prepare_port_blocking()
            except Exception:
                pass

        restored_count = 0
        failed_restore_count = 0

        for block in active_blocks:
            block_id = str(block["block_id"])

            try:
                plan = self._plan_restored_block(
                    block,
                    now=current,
                )

                self.backend.add_temporary_block(plan)

                restored_count += 1

            except Exception as exc:
                self.repository.mark_active_response_block_failed(
                    block_id,
                    error=(
                        f"No se pudo recuperar el bloqueo después del reinicio: {exc}"
                    ),
                )

                failed_restore_count += 1

        return ResponseRecoverySummary(
            table_created=table_created,
            expired_count=expired_count,
            failed_pending_count=failed_pending_count,
            restored_count=restored_count,
            failed_restore_count=failed_restore_count,
        )
