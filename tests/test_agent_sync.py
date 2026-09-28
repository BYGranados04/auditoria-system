import json
import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.agent.event_store import LocalEventStore
from app.agent.registration import (
    AgentIdentityError,
    AgentRegistrationError,
    central_events_batch_url,
    load_identity,
    normalize_central_url,
    register_agent,
    save_identity,
)
from app.agent.sync import (
    AgentEventSynchronizer,
    AgentEventSyncWorker,
    SyncHttpResponse,
)
from app.agents.events import build_agent_event_router
from app.auth.config import AuthSettings
from app.auth.repository import AuthRepository
from app.auth.web import AuthManager
from app.central.config import CentralSettings
from app.central.repository import CentralEventRepository
from app.core.config import AgentSettings
from app.core.events import SecurityEvent
from app.storage.event_repository import EventRepository
from tests.api_test_helpers import TEST_PASSWORD, TEST_SCRYPT

NOW = datetime(2026, 9, 27, 15, 0, tzinfo=UTC)


class FakeTransport:
    def __init__(self, handler: Any) -> None:
        self.handler = handler
        self.calls: list[dict[str, Any]] = []

    def post_json(
        self,
        url: str,
        payload: dict[str, object],
        *,
        headers: dict[str, str],
        timeout_seconds: int,
    ) -> SyncHttpResponse:
        call = {
            "url": url,
            "payload": payload,
            "headers": headers,
            "timeout_seconds": timeout_seconds,
        }
        self.calls.append(call)
        result = self.handler(call) if callable(self.handler) else self.handler
        if isinstance(result, BaseException):
            raise result
        return result


class TestClientTransport:
    __test__ = False

    def __init__(self, client: TestClient) -> None:
        self.client = client

    def post_json(
        self,
        url: str,
        payload: dict[str, object],
        *,
        headers: dict[str, str],
        timeout_seconds: int,
    ) -> SyncHttpResponse:
        del timeout_seconds
        response = self.client.post(
            urlsplit(url).path,
            json=payload,
            headers=headers,
        )
        return SyncHttpResponse(
            status_code=response.status_code,
            body=response.content,
        )


def success_response(
    accepted: int,
    *,
    inserted: int | None = None,
    duplicates: int = 0,
) -> SyncHttpResponse:
    actual_inserted = accepted - duplicates if inserted is None else inserted
    return SyncHttpResponse(
        status_code=200,
        body=json.dumps(
            {
                "accepted": accepted,
                "inserted": actual_inserted,
                "duplicates": duplicates,
            }
        ).encode(),
    )


def settings(
    tmp_path: Path,
    *,
    batch_size: int = 50,
    retry_base: int = 5,
    retry_max: int = 300,
) -> AgentSettings:
    return AgentSettings(
        interval=1,
        state_dir=tmp_path / "state",
        log_dir=tmp_path / "logs",
        identity_file=tmp_path / "agent-identity.json",
        sync_interval=1,
        sync_timeout_seconds=7,
        sync_batch_size=batch_size,
        sync_retry_base_seconds=retry_base,
        sync_retry_max_seconds=retry_max,
    )


def install_identity(
    agent_settings: AgentSettings,
    *,
    agent_id: str = "agt_local",
    credential: str = "agc_super_secret",
    central_url: str = "https://central.example/",
) -> None:
    save_identity(
        {
            "agent_id": agent_id,
            "credential": credential,
            "central_url": central_url,
        },
        agent_settings.identity_file,
    )


def make_event(
    *,
    agent_id: str | None = None,
    event_id: UUID | None = None,
    event_type: str = "SSH_BRUTE_FORCE_ATTEMPT",
    description: str = "Detección local",
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id or uuid4(),
        timestamp=NOW,
        agent_id=agent_id,
        hostname="metadata-host",
        source="detection-engine",
        category="detection",
        event_type=event_type,
        severity="high",
        description=description,
        evidence={"source_ip": "192.0.2.10", "attempts": 12},
    )


def initialized_repository(agent_settings: AgentSettings) -> EventRepository:
    repository = EventRepository(agent_settings.database_file)
    repository.initialize()
    return repository


def enqueue(
    repository: EventRepository,
    *,
    count: int = 1,
    agent_id: str = "agt_local",
) -> list[SecurityEvent]:
    events = [make_event(agent_id=agent_id) for _ in range(count)]
    for event in events:
        repository.add(event, enqueue_for_sync=True)
    return events


def outbox_rows(repository: EventRepository) -> list[sqlite3.Row]:
    with sqlite3.connect(repository.database_path) as connection:
        connection.row_factory = sqlite3.Row
        return connection.execute(
            "SELECT * FROM event_outbox ORDER BY created_at, event_id"
        ).fetchall()


def synchronizer(
    agent_settings: AgentSettings,
    repository: EventRepository,
    transport: FakeTransport,
    clock: list[datetime] | None = None,
) -> AgentEventSynchronizer:
    current = clock or [NOW]
    return AgentEventSynchronizer(
        agent_settings,
        repository=repository,
        transport=transport,
        clock=lambda: current[0],
    )


def test_agent_without_identity_continues_local_without_outbox(
    tmp_path: Path,
) -> None:
    agent_settings = settings(tmp_path)
    repository = EventRepository(agent_settings.database_file)
    stored = LocalEventStore(repository, agent_settings.identity_file).persist(
        make_event()
    )
    transport = FakeTransport(success_response(1))
    result = synchronizer(agent_settings, repository, transport).run_once()

    assert stored.agent_id is None
    assert repository.count() == 1
    assert outbox_rows(repository) == []
    assert result.skipped is True
    assert transport.calls == []


def test_valid_identity_assigns_agent_id_and_creates_outbox_atomically(
    tmp_path: Path,
) -> None:
    agent_settings = settings(tmp_path)
    install_identity(agent_settings)
    repository = EventRepository(agent_settings.database_file)

    stored = LocalEventStore(repository, agent_settings.identity_file).persist(
        make_event(agent_id="agt_untrusted")
    )
    rows = outbox_rows(repository)

    assert stored.agent_id == "agt_local"
    assert repository.list_events()[0]["agent_id"] == "agt_local"
    assert len(rows) == 1
    assert rows[0]["status"] == "pending"


def test_identity_loader_normalizes_url_and_does_not_modify_file(
    tmp_path: Path,
) -> None:
    agent_settings = settings(tmp_path)
    install_identity(agent_settings, central_url="https://central.example///")
    original = agent_settings.identity_file.read_bytes()

    identity = load_identity(agent_settings.identity_file)

    assert identity is not None
    assert identity.central_url == "https://central.example"
    assert agent_settings.identity_file.read_bytes() == original


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://central.example", "https://central.example"),
        ("https://central.example/", "https://central.example"),
        ("https://central.example/base", "https://central.example/base"),
        ("https://central.example/auditoria/", "https://central.example/auditoria"),
        ("http://servidor-privado", "http://servidor-privado"),
        ("http://127.0.0.1:8000", "http://127.0.0.1:8000"),
    ],
)
def test_normalize_central_url_keeps_valid_base_paths(
    value: str,
    expected: str,
) -> None:
    assert normalize_central_url(value) == expected


@pytest.mark.parametrize(
    "central_url",
    [
        "https://central.example?foo=bar",
        "https://central.example#section",
        "https://user:pass@central.example",
        "https:///auditoria",
        "ftp://central.example",
    ],
)
def test_invalid_central_url_in_identity_is_rejected(
    tmp_path: Path,
    central_url: str,
) -> None:
    agent_settings = settings(tmp_path)
    install_identity(agent_settings, central_url=central_url)

    with pytest.raises(AgentIdentityError):
        load_identity(agent_settings.identity_file)


def test_registration_rejects_invalid_central_url_before_network(
    tmp_path: Path,
) -> None:
    identity_file = tmp_path / "agent.json"

    with pytest.raises(AgentRegistrationError):
        register_agent(
            server="https://central.example?foo=bar",
            token="art_test_token",
            identity_file=identity_file,
        )

    assert not identity_file.exists()


def test_batch_url_uses_normalized_base_path() -> None:
    assert central_events_batch_url("https://central.example/auditoria/") == (
        "https://central.example/auditoria/agent/events/batch"
    )


@pytest.mark.parametrize(
    "invalid_identity",
    [
        {"agent_id": "agt_local", "credential": "secret"},
        {
            "agent_id": "agt_local",
            "credential": "secret",
            "central_url": "ftp://central.example",
        },
    ],
)
def test_missing_or_invalid_central_url_fails_safe_for_monitoring(
    tmp_path: Path,
    invalid_identity: dict[str, str],
) -> None:
    agent_settings = settings(tmp_path)
    agent_settings.identity_file.write_text(json.dumps(invalid_identity))
    repository = EventRepository(agent_settings.database_file)

    stored = LocalEventStore(repository, agent_settings.identity_file).persist(
        make_event()
    )
    transport = FakeTransport(success_response(1))
    result = synchronizer(agent_settings, repository, transport).run_once()

    assert stored.agent_id is None
    assert repository.count() == 1
    assert outbox_rows(repository) == []
    assert result.skipped is True
    assert transport.calls == []


def test_pending_selection_respects_next_attempt_and_survives_restart(
    tmp_path: Path,
) -> None:
    agent_settings = settings(tmp_path)
    repository = initialized_repository(agent_settings)
    event = enqueue(repository)[0]
    repository.record_outbox_failure(
        str(event.event_id),
        error="Temporal",
        next_attempt_at=NOW + timedelta(seconds=10),
    )

    restarted = EventRepository(agent_settings.database_file)

    assert restarted.list_pending_outbox(now=NOW, limit=50) == []
    ready = restarted.list_pending_outbox(
        now=NOW + timedelta(seconds=10),
        limit=50,
    )
    assert [item.event.event_id for item in ready] == [event.event_id]
    assert ready[0].attempt_count == 1


def test_legacy_null_agent_id_is_never_sent_and_is_quarantined(
    tmp_path: Path,
) -> None:
    agent_settings = settings(tmp_path)
    install_identity(agent_settings)
    repository = initialized_repository(agent_settings)
    event = make_event()
    repository.add(event)
    with sqlite3.connect(repository.database_path) as connection:
        connection.execute(
            "INSERT INTO event_outbox (event_id) VALUES (?)",
            (str(event.event_id),),
        )
    transport = FakeTransport(success_response(1))

    result = synchronizer(agent_settings, repository, transport).run_once()
    row = outbox_rows(repository)[0]

    assert transport.calls == []
    assert result.permanently_failed == 1
    assert row["status"] == "permanently_failed"


def test_different_event_agent_id_is_never_sent(tmp_path: Path) -> None:
    agent_settings = settings(tmp_path)
    install_identity(agent_settings)
    repository = initialized_repository(agent_settings)
    enqueue(repository, agent_id="agt_other")
    transport = FakeTransport(success_response(1))

    synchronizer(agent_settings, repository, transport).run_once()
    row = outbox_rows(repository)[0]

    assert transport.calls == []
    assert row["status"] == "permanently_failed"
    assert "no coincide" in row["last_error"]


def test_batch_payload_authorization_url_timeout_and_size_match_contract(
    tmp_path: Path,
) -> None:
    agent_settings = settings(tmp_path, batch_size=2)
    install_identity(agent_settings, central_url="https://central.example/auditoria/")
    repository = initialized_repository(agent_settings)
    enqueue(repository, count=3)
    transport = FakeTransport(
        lambda call: success_response(len(call["payload"]["events"]))
    )
    service = synchronizer(agent_settings, repository, transport)

    service.run_once()
    service.run_once()

    assert [len(call["payload"]["events"]) for call in transport.calls] == [2, 1]
    first = transport.calls[0]
    assert first["url"] == "https://central.example/auditoria/agent/events/batch"
    assert first["headers"]["Authorization"] == "Bearer agc_super_secret"
    assert first["timeout_seconds"] == 7
    assert set(first["payload"]) == {"events"}
    assert set(first["payload"]["events"][0]) == {
        "event_id",
        "timestamp",
        "hostname",
        "source",
        "category",
        "event_type",
        "severity",
        "description",
        "evidence",
    }
    assert b"agc_super_secret" not in repository.database_path.read_bytes()


def test_batch_never_exceeds_central_hard_maximum(tmp_path: Path) -> None:
    agent_settings = settings(tmp_path, batch_size=500)
    install_identity(agent_settings)
    repository = initialized_repository(agent_settings)
    enqueue(repository, count=101)
    transport = FakeTransport(
        lambda call: success_response(len(call["payload"]["events"]))
    )
    service = synchronizer(agent_settings, repository, transport)

    service.run_once()
    service.run_once()

    assert [len(call["payload"]["events"]) for call in transport.calls] == [100, 1]


@pytest.mark.parametrize("duplicates", [0, 2])
def test_valid_200_acknowledges_new_and_duplicate_events(
    tmp_path: Path,
    duplicates: int,
) -> None:
    agent_settings = settings(tmp_path)
    install_identity(agent_settings)
    repository = initialized_repository(agent_settings)
    events = enqueue(repository, count=2)
    transport = FakeTransport(success_response(2, duplicates=duplicates))

    result = synchronizer(agent_settings, repository, transport).run_once()
    rows = outbox_rows(repository)

    assert result.acknowledged == 2
    assert {row["status"] for row in rows} == {"acknowledged"}
    assert all(row["acknowledged_at"] is not None for row in rows)
    assert repository.count() == 2
    assert {row["event_id"] for row in repository.list_events()} == {
        str(event.event_id) for event in events
    }


@pytest.mark.parametrize(
    "response",
    [
        SyncHttpResponse(200, b'{"accepted":0,"inserted":0,"duplicates":0}'),
        SyncHttpResponse(200, b'{"accepted":1,"inserted":1,"duplicates":1}'),
        SyncHttpResponse(200, b"not-json"),
    ],
)
def test_inconsistent_200_does_not_acknowledge(
    tmp_path: Path,
    response: SyncHttpResponse,
) -> None:
    agent_settings = settings(tmp_path)
    install_identity(agent_settings)
    repository = initialized_repository(agent_settings)
    enqueue(repository)

    synchronizer(
        agent_settings,
        repository,
        FakeTransport(response),
    ).run_once()
    row = outbox_rows(repository)[0]

    assert row["status"] == "pending"
    assert row["attempt_count"] == 1
    assert row["last_error"] == "Respuesta 200 inconsistente del central."


@pytest.mark.parametrize(
    "failure",
    [
        TimeoutError("credential agc_super_secret"),
        ConnectionError("credential agc_super_secret"),
        SyncHttpResponse(500, b"server error"),
        SyncHttpResponse(429, b"rate limited"),
    ],
)
def test_temporary_failures_remain_pending_and_sanitize_errors(
    tmp_path: Path,
    failure: BaseException | SyncHttpResponse,
) -> None:
    agent_settings = settings(tmp_path)
    install_identity(agent_settings)
    repository = initialized_repository(agent_settings)
    enqueue(repository)

    synchronizer(
        agent_settings,
        repository,
        FakeTransport(failure),
    ).run_once()
    row = outbox_rows(repository)[0]

    assert row["status"] == "pending"
    assert row["attempt_count"] == 1
    assert row["next_attempt_at"] == (NOW + timedelta(seconds=5)).isoformat()
    assert "agc_super_secret" not in row["last_error"]


def test_retry_uses_exponential_backoff_and_respects_maximum(tmp_path: Path) -> None:
    agent_settings = settings(tmp_path, retry_base=5, retry_max=12)
    install_identity(agent_settings)
    repository = initialized_repository(agent_settings)
    enqueue(repository)
    current = [NOW]
    service = synchronizer(
        agent_settings,
        repository,
        FakeTransport(SyncHttpResponse(500, b"error")),
        current,
    )

    service.run_once()
    assert outbox_rows(repository)[0]["next_attempt_at"] == (
        NOW + timedelta(seconds=5)
    ).isoformat()
    current[0] += timedelta(seconds=5)
    service.run_once()
    assert outbox_rows(repository)[0]["next_attempt_at"] == (
        NOW + timedelta(seconds=15)
    ).isoformat()
    current[0] += timedelta(seconds=10)
    service.run_once()
    assert outbox_rows(repository)[0]["next_attempt_at"] == (
        NOW + timedelta(seconds=27)
    ).isoformat()
    assert outbox_rows(repository)[0]["attempt_count"] == 3


@pytest.mark.parametrize("status_code", [401, 403])
def test_authentication_errors_do_not_ack_and_use_maximum_delay(
    tmp_path: Path,
    status_code: int,
) -> None:
    agent_settings = settings(tmp_path, retry_max=300)
    install_identity(agent_settings)
    repository = initialized_repository(agent_settings)
    enqueue(repository)

    synchronizer(
        agent_settings,
        repository,
        FakeTransport(SyncHttpResponse(status_code, b"denied")),
    ).run_once()
    row = outbox_rows(repository)[0]

    assert row["status"] == "pending"
    assert row["next_attempt_at"] == (NOW + timedelta(seconds=300)).isoformat()
    assert row["attempt_count"] == 1


def test_authentication_error_defers_the_entire_pending_queue(
    tmp_path: Path,
) -> None:
    agent_settings = settings(tmp_path, batch_size=1, retry_max=300)
    install_identity(agent_settings)
    repository = initialized_repository(agent_settings)
    enqueue(repository, count=2)

    synchronizer(
        agent_settings,
        repository,
        FakeTransport(SyncHttpResponse(401, b"denied")),
    ).run_once()
    rows = outbox_rows(repository)

    assert {row["status"] for row in rows} == {"pending"}
    assert {row["next_attempt_at"] for row in rows} == {
        (NOW + timedelta(seconds=300)).isoformat()
    }
    assert sorted(row["attempt_count"] for row in rows) == [0, 1]


def test_422_isolates_bad_event_without_blocking_valid_events(
    tmp_path: Path,
) -> None:
    agent_settings = settings(tmp_path)
    install_identity(agent_settings)
    repository = initialized_repository(agent_settings)
    valid_before = make_event(agent_id="agt_local", event_type="VALID_BEFORE")
    invalid = make_event(agent_id="agt_local", event_type="INVALID")
    valid_after = make_event(agent_id="agt_local", event_type="VALID_AFTER")
    for event in (valid_before, invalid, valid_after):
        repository.add(event, enqueue_for_sync=True)

    def handler(call: dict[str, Any]) -> SyncHttpResponse:
        events = call["payload"]["events"]
        if len(events) > 1 or events[0]["event_type"] == "INVALID":
            return SyncHttpResponse(422, b"invalid")
        return success_response(1)

    transport = FakeTransport(handler)
    synchronizer(agent_settings, repository, transport).run_once()
    rows = {row["event_id"]: row for row in outbox_rows(repository)}

    assert rows[str(valid_before.event_id)]["status"] == "acknowledged"
    assert rows[str(valid_after.event_id)]["status"] == "acknowledged"
    assert rows[str(invalid.event_id)]["status"] == "permanently_failed"
    assert len(transport.calls) == 4


def test_409_is_recorded_as_permanent_conflict_without_ack(tmp_path: Path) -> None:
    agent_settings = settings(tmp_path)
    install_identity(agent_settings)
    repository = initialized_repository(agent_settings)
    enqueue(repository)

    synchronizer(
        agent_settings,
        repository,
        FakeTransport(SyncHttpResponse(409, b"conflict")),
    ).run_once()
    row = outbox_rows(repository)[0]

    assert row["status"] == "permanently_failed"
    assert row["acknowledged_at"] is None
    assert "Conflicto" in row["last_error"]


def test_acknowledged_events_are_not_sent_again(tmp_path: Path) -> None:
    agent_settings = settings(tmp_path)
    install_identity(agent_settings)
    repository = initialized_repository(agent_settings)
    enqueue(repository)
    transport = FakeTransport(success_response(1))
    service = synchronizer(agent_settings, repository, transport)

    service.run_once()
    service.run_once()

    assert len(transport.calls) == 1
    assert repository.count() == 1


def test_offline_events_recover_after_restart_without_losing_local_evidence(
    tmp_path: Path,
) -> None:
    agent_settings = settings(tmp_path)
    current = [NOW]
    auth_repository = AuthRepository(
        tmp_path / "central-auth" / "auth.db",
        scrypt_parameters=TEST_SCRYPT,
    )
    owner = auth_repository.create_user(
        username="sync-owner",
        password=TEST_PASSWORD,
        role="viewer",
    )
    registration = auth_repository.create_agent_registration_token(
        int(owner["id"]),
        now=NOW,
    )
    enrolled = auth_repository.enroll_agent(
        registration_token=registration.token,
        hostname="sync-host",
        now=NOW,
    )
    install_identity(
        agent_settings,
        agent_id=str(enrolled.agent["agent_id"]),
        credential=enrolled.credential,
    )
    repository = initialized_repository(agent_settings)
    events = enqueue(
        repository,
        count=4,
        agent_id=str(enrolled.agent["agent_id"]),
    )

    offline = synchronizer(
        agent_settings,
        repository,
        FakeTransport(ConnectionError("offline")),
        current,
    )
    offline.run_once()
    assert {row["status"] for row in outbox_rows(repository)} == {"pending"}

    current[0] += timedelta(seconds=5)
    central_settings = CentralSettings(
        database_file=tmp_path / "central" / "central.db"
    )
    central_repository = CentralEventRepository(
        central_settings.database_file,
        clock=lambda: current[0],
    )
    manager = AuthManager(
        auth_repository,
        AuthSettings(database_file=auth_repository.database_path),
        clock=lambda: current[0],
    )
    central_app = FastAPI()
    central_app.include_router(
        build_agent_event_router(
            manager,
            central_repository,
            central_settings,
        )
    )
    after_restart = synchronizer(
        agent_settings,
        EventRepository(agent_settings.database_file),
        TestClientTransport(TestClient(central_app)),
        current,
    )
    result = after_restart.run_once()

    assert result.acknowledged == 4
    assert {row["status"] for row in outbox_rows(repository)} == {"acknowledged"}
    assert repository.count() == 4
    assert {row["event_id"] for row in repository.list_events()} == {
        str(event.event_id) for event in events
    }
    central_events = central_repository.list_events(
        agent_id=str(enrolled.agent["agent_id"])
    )
    assert {row["event_id"] for row in central_events} == {
        str(event.event_id) for event in events
    }


def test_worker_survives_unexpected_sync_exception() -> None:
    completed_second_run = threading.Event()

    class ExplodingSynchronizer:
        def __init__(self) -> None:
            self.settings = SimpleNamespace(sync_interval=0.01)
            self.calls = 0

        def run_once(self) -> None:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("unexpected")
            completed_second_run.set()

    service = ExplodingSynchronizer()
    worker = AgentEventSyncWorker(service)  # type: ignore[arg-type]
    worker.start()
    try:
        assert completed_second_run.wait(timeout=1)
    finally:
        worker.stop()
        worker.join(timeout=1)

    assert service.calls >= 2
