from __future__ import annotations

from pathlib import Path

from app.agent.registration import AgentIdentityError, load_identity
from app.core.events import SecurityEvent
from app.storage.event_repository import EventRepository


class LocalEventStore:
    def __init__(
        self,
        repository: EventRepository,
        identity_file: Path,
    ) -> None:
        self.repository = repository
        self.identity_file = identity_file

    def persist(self, event: SecurityEvent) -> SecurityEvent:
        try:
            identity = load_identity(self.identity_file)
        except AgentIdentityError:
            identity = None

        stored_event = event
        if identity is not None:
            stored_event = event.model_copy(
                update={"agent_id": identity.agent_id}
            )

        self.repository.initialize()
        self.repository.add(
            stored_event,
            enqueue_for_sync=identity is not None,
        )
        return stored_event
