from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable

from app.notifications.models import NotificationMessage, ProviderResult


class NotificationProviderError(RuntimeError):
    pass


class ResendProvider:
    name = "resend"

    def __init__(
        self,
        *,
        api_key: str | None,
        sender: str | None,
        api_url: str,
        timeout_seconds: int,
        opener: Callable[..., object] = urllib.request.urlopen,
    ) -> None:
        self._api_key = api_key
        self._sender = sender
        self._api_url = api_url
        self._timeout_seconds = timeout_seconds
        self._opener = opener

    def send(self, message: NotificationMessage) -> ProviderResult:
        if not self._api_key or not self._sender or not self._api_url:
            raise NotificationProviderError("Configuración de Resend incompleta.")
        request = urllib.request.Request(
            self._api_url,
            data=json.dumps(
                {
                    "from": self._sender,
                    "to": [message.recipient],
                    "subject": message.subject,
                    "text": message.text,
                    "html": message.html,
                }
            ).encode(),
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with self._opener(request, timeout=self._timeout_seconds) as response:
                payload = json.loads(response.read().decode())
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            raise NotificationProviderError(
                "No fue posible enviar la notificación."
            ) from exc
        message_id = payload.get("id") if isinstance(payload, dict) else None
        if not isinstance(message_id, str) or not message_id:
            raise NotificationProviderError(
                "Respuesta inválida del proveedor de notificaciones."
            )
        return ProviderResult(provider_message_id=message_id)
