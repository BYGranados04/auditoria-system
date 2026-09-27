from typing import Protocol

from app.notifications.models import NotificationMessage, ProviderResult


class NotificationProvider(Protocol):
    name: str

    def send(self, message: NotificationMessage) -> ProviderResult: ...
