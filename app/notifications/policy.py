from app.core.events import SecurityEvent
from app.notifications.config import SEVERITIES


class NotificationPolicy:
    def __init__(self, min_severity: str) -> None:
        self.minimum = SEVERITIES.index(min_severity)

    def should_notify(self, event: SecurityEvent) -> bool:
        return (
            event.category == "detection"
            and SEVERITIES.index(event.severity) >= self.minimum
        )
