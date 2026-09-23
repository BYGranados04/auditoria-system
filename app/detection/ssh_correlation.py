from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from app.core.events import SecurityEvent
from app.storage.event_repository import EventRepository


@dataclass(frozen=True)
class DetectionResult:
    event_type: str
    severity: str
    description: str
    evidence: dict[str, Any]


class SSHCorrelationEngine:
    BRUTE_FORCE_THRESHOLD = 10
    USER_ENUMERATION_THRESHOLD = 5
    PREAUTH_ACTIVITY_THRESHOLD = 10
    WINDOW_SECONDS = 60

    def __init__(
        self,
        repository: EventRepository,
    ) -> None:
        self.repository = repository

    def analyze(
        self,
        event: SecurityEvent,
    ) -> list[DetectionResult]:
        if event.event_type == "SSH_AUTH_FAILURE":
            result = self._detect_brute_force(event)

            return [result] if result is not None else []

        if event.event_type == "SSH_INVALID_USER":
            result = self._detect_user_enumeration(event)

            return [result] if result is not None else []

        if event.event_type == "SSH_PREAUTH_CONNECTION_CLOSED":
            result = self._detect_repeated_preauth(event)

            return [result] if result is not None else []

        return []

    def _authentication_events(
        self,
        *,
        event: SecurityEvent,
        event_type: str,
    ) -> list[dict[str, Any]]:
        source_ip = event.evidence.get("ip")

        if not isinstance(source_ip, str):
            return []

        since = event.timestamp - timedelta(seconds=self.WINDOW_SECONDS)

        events = self.repository.list_events(
            category="authentication",
            event_type=event_type,
            since=since,
            until=event.timestamp,
            limit=1000,
        )

        return [
            candidate
            for candidate in events
            if candidate["evidence"].get("ip") == source_ip
        ]

    def _recent_detection_exists(
        self,
        *,
        event: SecurityEvent,
        event_type: str,
    ) -> bool:
        source_ip = event.evidence.get("ip")

        if not isinstance(source_ip, str):
            return False

        since = event.timestamp - timedelta(seconds=self.WINDOW_SECONDS)

        detections = self.repository.list_events(
            category="detection",
            event_type=event_type,
            since=since,
            until=event.timestamp,
            limit=100,
        )

        return any(
            detection["evidence"].get("source_ip") == source_ip
            for detection in detections
        )

    def _detect_brute_force(
        self,
        event: SecurityEvent,
    ) -> DetectionResult | None:
        attempts = self._authentication_events(
            event=event,
            event_type="SSH_AUTH_FAILURE",
        )

        if len(attempts) < self.BRUTE_FORCE_THRESHOLD:
            return None

        if self._recent_detection_exists(
            event=event,
            event_type="SSH_BRUTE_FORCE_ATTEMPT",
        ):
            return None

        source_ip = str(event.evidence["ip"])

        users = sorted(
            {
                str(item["evidence"].get("user"))
                for item in attempts
                if item["evidence"].get("user")
            }
        )

        methods = sorted(
            {
                str(item["evidence"].get("method"))
                for item in attempts
                if item["evidence"].get("method")
            }
        )

        return DetectionResult(
            event_type="SSH_BRUTE_FORCE_ATTEMPT",
            severity="high",
            description=(
                "Se detectaron múltiples fallos de "
                "autenticación SSH desde un mismo origen."
            ),
            evidence={
                "source_ip": source_ip,
                "attempt_count": len(attempts),
                "window_seconds": self.WINDOW_SECONDS,
                "users": users,
                "methods": methods,
                "first_seen": attempts[-1]["timestamp"],
                "last_seen": attempts[0]["timestamp"],
                "triggering_event_id": str(event.event_id),
            },
        )

    def _detect_user_enumeration(
        self,
        event: SecurityEvent,
    ) -> DetectionResult | None:
        attempts = self._authentication_events(
            event=event,
            event_type="SSH_INVALID_USER",
        )

        users = {
            str(item["evidence"].get("user"))
            for item in attempts
            if item["evidence"].get("user")
        }

        if len(users) < self.USER_ENUMERATION_THRESHOLD:
            return None

        if self._recent_detection_exists(
            event=event,
            event_type="SSH_USER_ENUMERATION_ATTEMPT",
        ):
            return None

        source_ip = str(event.evidence["ip"])

        return DetectionResult(
            event_type="SSH_USER_ENUMERATION_ATTEMPT",
            severity="high",
            description=(
                "Se detectaron intentos SSH contra múltiples usuarios inexistentes."
            ),
            evidence={
                "source_ip": source_ip,
                "attempt_count": len(attempts),
                "distinct_user_count": len(users),
                "users": sorted(users),
                "window_seconds": self.WINDOW_SECONDS,
                "first_seen": attempts[-1]["timestamp"],
                "last_seen": attempts[0]["timestamp"],
                "triggering_event_id": str(event.event_id),
            },
        )

    def _detect_repeated_preauth(
        self,
        event: SecurityEvent,
    ) -> DetectionResult | None:
        attempts = self._authentication_events(
            event=event,
            event_type="SSH_PREAUTH_CONNECTION_CLOSED",
        )

        if len(attempts) < self.PREAUTH_ACTIVITY_THRESHOLD:
            return None

        if self._recent_detection_exists(
            event=event,
            event_type="SSH_REPEATED_PREAUTH_ACTIVITY",
        ):
            return None

        source_ip = str(event.evidence["ip"])

        users = sorted(
            {
                str(item["evidence"].get("user"))
                for item in attempts
                if item["evidence"].get("user")
            }
        )

        return DetectionResult(
            event_type="SSH_REPEATED_PREAUTH_ACTIVITY",
            severity="medium",
            description=(
                "Se detectaron múltiples conexiones SSH "
                "cerradas durante la preautenticación "
                "desde un mismo origen."
            ),
            evidence={
                "source_ip": source_ip,
                "attempt_count": len(attempts),
                "window_seconds": self.WINDOW_SECONDS,
                "users": users,
                "first_seen": attempts[-1]["timestamp"],
                "last_seen": attempts[0]["timestamp"],
                "triggering_event_id": str(event.event_id),
            },
        )

    def _detect_repeated_preauth(
        self,
        event: SecurityEvent,
    ) -> DetectionResult | None:
        attempts = self._authentication_events(
            event=event,
            event_type="SSH_PREAUTH_CONNECTION_CLOSED",
        )

        if len(attempts) < self.PREAUTH_ACTIVITY_THRESHOLD:
            return None

        if self._recent_detection_exists(
            event=event,
            event_type="SSH_REPEATED_PREAUTH_ACTIVITY",
        ):
            return None

        source_ip = str(event.evidence["ip"])

        users = sorted(
            {
                str(item["evidence"].get("user"))
                for item in attempts
                if item["evidence"].get("user")
            }
        )

        return DetectionResult(
            event_type="SSH_REPEATED_PREAUTH_ACTIVITY",
            severity="medium",
            description=(
                "Se detectaron múltiples conexiones SSH "
                "cerradas durante la preautenticación "
                "desde un mismo origen."
            ),
            evidence={
                "source_ip": source_ip,
                "attempt_count": len(attempts),
                "window_seconds": self.WINDOW_SECONDS,
                "users": users,
                "first_seen": attempts[-1]["timestamp"],
                "last_seen": attempts[0]["timestamp"],
                "triggering_event_id": str(event.event_id),
            },
        )
