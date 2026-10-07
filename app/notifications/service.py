from __future__ import annotations

from html import escape

from app.core.events import SecurityEvent
from app.notifications.config import NotificationSettings
from app.notifications.models import NotificationAttempt, NotificationMessage
from app.notifications.policy import NotificationPolicy
from app.notifications.providers.base import NotificationProvider
from app.notifications.providers.resend import NotificationProviderError
from app.notifications.repository import NotificationRepository


class NotificationService:
    def __init__(
        self,
        *,
        settings: NotificationSettings,
        repository: NotificationRepository,
        provider: NotificationProvider,
    ) -> None:
        self.settings = settings
        self.repository = repository
        self.provider = provider
        self.policy = NotificationPolicy(settings.min_severity)

    @staticmethod
    def _message(event: SecurityEvent, recipient: str) -> NotificationMessage:
        source_ip = event.evidence.get("source_ip")
        details = (
            f"Servidor: {event.hostname}\nSeveridad: {event.severity}\n"
            f"Tipo: {event.event_type}\nFecha/hora: {event.timestamp.isoformat()}\n"
            f"Descripción: {event.description}\nEvent ID: {event.event_id}"
        )
        if source_ip:
            details += f"\nIP origen: {source_ip}"
        return NotificationMessage(
            recipient=recipient,
            subject=(
                f"[Nexora] Detección {event.severity.upper()} "
                f"en {event.hostname}"
            ),
            text=f"Nexora\nAlerta de seguridad\n\n{details}",
            html=(
                "<h1>Nexora</h1><p>Alerta de seguridad</p>"
                f"<pre>{escape(details)}</pre>"
            ),
        )

    def notify(self, event: SecurityEvent) -> NotificationAttempt | None:
        if not self.settings.enabled or not self.policy.should_notify(event):
            return None
        recipient = self.settings.recipient or ""
        attempt, created = self.repository.create_pending(
            event_id=str(event.event_id),
            agent_id=event.agent_id,
            provider=self.provider.name,
            recipient=recipient,
            hostname=event.hostname,
            severity=event.severity,
        )
        if not created:
            return attempt
        if not self.settings.complete:
            return self.repository.complete(
                attempt.id, error="Configuración de notificaciones incompleta."
            )
        try:
            result = self.provider.send(self._message(event, recipient))
        except NotificationProviderError as exc:
            return self.repository.complete(attempt.id, error=str(exc))
        except Exception:
            return self.repository.complete(
                attempt.id, error="Error inesperado al enviar la notificación."
            )
        return self.repository.complete(
            attempt.id, provider_message_id=result.provider_message_id
        )
