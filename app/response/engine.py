from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address, ip_address

from app.core.events import SecurityEvent
from app.response.models import ResponseAction, ResponseDecision
from app.response.policy import ResponsePolicy
from app.response.recurrence import RecurrenceAssessment


class ResponsePolicyEngine:
    BLOCK_CANDIDATE_DETECTIONS = {
        "SSH_USER_ENUMERATION_ATTEMPT",
        "SSH_BRUTE_FORCE_ATTEMPT",
        "SSH_REPEATED_PREAUTH_ACTIVITY",
    }

    # Servicio afectado por cada detección. Se usa únicamente cuando el
    # alcance configurado es "ip_port". El puerto SSH proviene de la política.
    SSH_DETECTIONS = BLOCK_CANDIDATE_DETECTIONS

    def __init__(
        self,
        policy: ResponsePolicy,
    ) -> None:
        self.policy = policy

    def evaluate(
        self,
        event: SecurityEvent,
        *,
        recurrence: RecurrenceAssessment | None = None,
        incident_id: str | None = None,
    ) -> ResponseDecision:
        if event.category != "detection":
            return self._no_action(
                event,
                reason=("El evento no pertenece a la categoría de detección."),
                incident_id=incident_id,
            )

        if event.event_type not in self.BLOCK_CANDIDATE_DETECTIONS:
            return self._no_action(
                event,
                reason=("La detección no tiene una política de respuesta configurada."),
                incident_id=incident_id,
            )

        source_ip = event.evidence.get("source_ip")

        if not isinstance(source_ip, str):
            return self._no_action(
                event,
                reason=("La detección no contiene una dirección IP de origen válida."),
                incident_id=incident_id,
            )

        try:
            address = ip_address(source_ip)
        except ValueError:
            return self._no_action(
                event,
                reason=("La dirección IP de origen no pudo ser validada."),
                incident_id=incident_id,
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
                incident_id=incident_id,
            )

        if normalized_ip in self.policy.trusted_admin_ips:
            return self._no_action(
                event,
                target_ip=normalized_ip,
                reason=(
                    "La dirección IP pertenece a una fuente administrativa confiable."
                ),
                incident_id=incident_id,
            )

        # Separación de responsabilidades: el motor decide qué haría la
        # política. Tailscale y las protecciones dinámicas (sesiones SSH,
        # IPs locales, gateways) se validan en la capa de ejecución, que
        # registra SKIPPED con el motivo. Solo se conservan aquí las guardas
        # históricas (categorías no enrutables y trusted admin IPs).

        port_scope = self.policy.block_scope == "ip_port"
        protocol, port = self._service_for(event) if port_scope else (None, None)

        unknown_service = port_scope and (protocol is None or port is None)

        if unknown_service:
            # Sin servicio conocido no es posible acotar por puerto; se
            # degrada a recomendación por IP sin ejecución automática.
            port_scope = False

        recommend_action: ResponseAction = (
            "RECOMMEND_BLOCK_IP_PORT" if port_scope else "RECOMMEND_BLOCK_IP"
        )
        execute_action: ResponseAction = (
            "TEMPORARY_BLOCK_IP_PORT" if port_scope else "TEMPORARY_BLOCK_IP"
        )

        common = {
            "detection_event_id": event.event_id,
            "hostname": event.hostname,
            "mode": self.policy.mode,
            "target_ip": normalized_ip,
            "protocol": protocol if port_scope else None,
            "port": port if port_scope else None,
            "incident_id": incident_id,
            **self._recurrence_fields(recurrence),
        }

        if self.policy.mode == "audit_only":
            return ResponseDecision(
                action=recommend_action,
                reason=self._with_recurrence(
                    "La actividad cumple una política "
                    "de respuesta, pero el sistema está "
                    "en modo audit_only.",
                    recurrence,
                ),
                executed=False,
                **common,
            )

        if self.policy.mode == "assisted":
            # La acción propuesta queda registrada para el flujo de
            # aprobación; la decisión en sí no es ejecutable.
            proposal = dict(common)
            if not unknown_service:
                proposal["proposed_action"] = execute_action
                proposal["selected_duration_seconds"] = (
                    recurrence.selected_duration_seconds
                    if recurrence is not None
                    else self.policy.temporary_block_seconds
                )
            return ResponseDecision(
                action=recommend_action,
                reason=self._with_recurrence(
                    "La actividad cumple una política "
                    "de respuesta y requiere aprobación.",
                    recurrence,
                ),
                approval_required=True,
                executed=False,
                **proposal,
            )

        allowed = not unknown_service and (
            self.policy.allow_temporary_ip_port_block
            if port_scope
            else self.policy.allow_temporary_ip_block
        )

        if not allowed:
            reason = (
                "El modo automatic está activo, "
                "pero el bloqueo temporal por IP y puerto no "
                "ha sido autorizado."
                if port_scope
                else "El modo automatic está activo, "
                "pero el bloqueo temporal de IP no "
                "ha sido autorizado."
            )
            return ResponseDecision(
                action=recommend_action,
                reason=self._with_recurrence(reason, recurrence),
                executed=False,
                **common,
            )

        duration = (
            recurrence.selected_duration_seconds
            if recurrence is not None and recurrence.escalation_enabled
            else self.policy.temporary_block_seconds
        )

        return ResponseDecision(
            action=execute_action,
            duration_seconds=duration,
            reason=self._with_recurrence(
                "La actividad cumple una política de respuesta automática autorizada.",
                recurrence,
            ),
            execution_allowed=True,
            executed=False,
            **common,
        )

    def _service_for(
        self,
        event: SecurityEvent,
    ) -> tuple[str | None, int | None]:
        if event.event_type in self.SSH_DETECTIONS:
            return "tcp", self.policy.ssh_port

        return None, None

    @staticmethod
    def _recurrence_fields(
        recurrence: RecurrenceAssessment | None,
    ) -> dict[str, int | None]:
        if recurrence is None:
            return {}

        return {
            "recurrence_level": recurrence.recurrence_level,
            "previous_incidents": recurrence.previous_incidents,
            "selected_duration_seconds": recurrence.selected_duration_seconds,
        }

    @staticmethod
    def _with_recurrence(
        reason: str,
        recurrence: RecurrenceAssessment | None,
    ) -> str:
        if recurrence is None or not recurrence.escalation_enabled:
            return reason

        detail = (
            f" Reincidencia nivel {recurrence.recurrence_level}"
            f"/{recurrence.maximum_level} "
            f"({recurrence.previous_incidents} ofensas previas en "
            f"{recurrence.window_seconds} s); duración seleccionada "
            f"{recurrence.selected_duration_seconds} s."
        )
        return reason + detail

    def _no_action(
        self,
        event: SecurityEvent,
        *,
        reason: str,
        target_ip: str | None = None,
        incident_id: str | None = None,
    ) -> ResponseDecision:
        return ResponseDecision(
            detection_event_id=event.event_id,
            hostname=event.hostname,
            mode=self.policy.mode,
            action="NO_ACTION",
            target_ip=target_ip,
            reason=reason,
            executed=False,
            incident_id=incident_id,
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
