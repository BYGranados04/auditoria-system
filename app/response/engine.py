from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address, ip_address

from app.core.events import SecurityEvent
from app.response.models import ResponseDecision
from app.response.policy import ResponsePolicy


class ResponsePolicyEngine:
    BLOCK_CANDIDATE_DETECTIONS = {
        "SSH_USER_ENUMERATION_ATTEMPT",
        "SSH_BRUTE_FORCE_ATTEMPT",
        "SSH_REPEATED_PREAUTH_ACTIVITY",
    }

    def __init__(
        self,
        policy: ResponsePolicy,
    ) -> None:
        self.policy = policy

    def evaluate(
        self,
        event: SecurityEvent,
    ) -> ResponseDecision:
        if event.category != "detection":
            return self._no_action(
                event,
                reason=("El evento no pertenece a la categoría de detección."),
            )

        if event.event_type not in self.BLOCK_CANDIDATE_DETECTIONS:
            return self._no_action(
                event,
                reason=("La detección no tiene una política de respuesta configurada."),
            )

        source_ip = event.evidence.get("source_ip")

        if not isinstance(source_ip, str):
            return self._no_action(
                event,
                reason=("La detección no contiene una dirección IP de origen válida."),
            )

        try:
            address = ip_address(source_ip)
        except ValueError:
            return self._no_action(
                event,
                reason=("La dirección IP de origen no pudo ser validada."),
            )

        normalized_ip = str(address)

        if self._is_protected_address(address):
            return self._no_action(
                event,
                target_ip=normalized_ip,
                reason=(
                    "La dirección IP pertenece a una "
                    "categoría protegida y no puede "
                    "ser bloqueada."
                ),
            )

        if normalized_ip in self.policy.trusted_admin_ips:
            return self._no_action(
                event,
                target_ip=normalized_ip,
                reason=(
                    "La dirección IP pertenece a una fuente administrativa confiable."
                ),
            )

        if self.policy.mode == "audit_only":
            return ResponseDecision(
                detection_event_id=event.event_id,
                hostname=event.hostname,
                mode=self.policy.mode,
                action="RECOMMEND_BLOCK_IP",
                target_ip=normalized_ip,
                reason=(
                    "La actividad cumple una política "
                    "de respuesta, pero el sistema está "
                    "en modo audit_only."
                ),
                executed=False,
            )

        if self.policy.mode == "assisted":
            return ResponseDecision(
                detection_event_id=event.event_id,
                hostname=event.hostname,
                mode=self.policy.mode,
                action="RECOMMEND_BLOCK_IP",
                target_ip=normalized_ip,
                reason=(
                    "La actividad cumple una política "
                    "de respuesta y requiere aprobación."
                ),
                approval_required=True,
                executed=False,
            )

        if not self.policy.allow_temporary_ip_block:
            return ResponseDecision(
                detection_event_id=event.event_id,
                hostname=event.hostname,
                mode=self.policy.mode,
                action="RECOMMEND_BLOCK_IP",
                target_ip=normalized_ip,
                reason=(
                    "El modo automatic está activo, "
                    "pero el bloqueo temporal de IP no "
                    "ha sido autorizado."
                ),
                executed=False,
            )

        return ResponseDecision(
            detection_event_id=event.event_id,
            hostname=event.hostname,
            mode=self.policy.mode,
            action="TEMPORARY_BLOCK_IP",
            target_ip=normalized_ip,
            duration_seconds=self.policy.temporary_block_seconds,
            reason=(
                "La actividad cumple una política de respuesta automática autorizada."
            ),
            execution_allowed=True,
            executed=False,
        )

    def _no_action(
        self,
        event: SecurityEvent,
        *,
        reason: str,
        target_ip: str | None = None,
    ) -> ResponseDecision:
        return ResponseDecision(
            detection_event_id=event.event_id,
            hostname=event.hostname,
            mode=self.policy.mode,
            action="NO_ACTION",
            target_ip=target_ip,
            reason=reason,
            executed=False,
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
