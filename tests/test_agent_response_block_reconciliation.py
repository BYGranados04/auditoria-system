"""Reconciliación periódica de response_blocks vencidos en run_once()."""

from __future__ import annotations

import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from app.agent.continuous_agent import ContinuousAgent
from app.response.firewall_backend import NftablesFirewallBackend
from app.response.recovery import ResponseRecoveryManager
from app.storage.event_repository import EventRepository
from tests.test_agent_response_recovery import settings
from tests.test_response_recovery import create_block

SAME_BOOT = {"boot_id": "mismo-boot", "listening_ports": []}


def prepare_agent(
    tmp_path: Path,
    monkeypatch,
    *,
    previous: dict[str, Any] | None = SAME_BOOT,
    current: dict[str, Any] | None = None,
    initialize: bool = True,
) -> tuple[ContinuousAgent, EventRepository, dict[str, list[Any]]]:
    agent = ContinuousAgent(interval=1, settings=settings(tmp_path))
    repo = EventRepository(agent.settings.database_file)

    if initialize:
        repo.initialize()

    calls: dict[str, list[Any]] = {
        "events": [],
        "saved": [],
        "comparisons": [],
        "baselines": [],
    }
    snapshot = dict(current if current is not None else SAME_BOOT)

    monkeypatch.setattr(agent.ssh_collector, "latest_cursor", lambda: None)
    monkeypatch.setattr(agent, "emit", lambda **kw: calls["events"].append(kw))
    monkeypatch.setattr(agent, "load_state", lambda: previous)
    monkeypatch.setattr(agent, "snapshot", lambda: snapshot)
    monkeypatch.setattr(agent, "save_state", calls["saved"].append)
    monkeypatch.setattr(
        agent,
        "compare",
        lambda old, new: calls["comparisons"].append((old, new)),
    )
    monkeypatch.setattr(agent, "_collect_ssh_events", lambda old, new: None)
    monkeypatch.setattr(
        agent,
        "initialize_baseline",
        lambda: calls["baselines"].append(True),
    )

    return agent, repo, calls


def status(repo: EventRepository, block_id: str) -> str:
    row = repo.get_response_block(block_id)
    assert row is not None
    return row["status"]


@pytest.mark.parametrize(
    ("previous", "current"),
    [
        pytest.param(None, None, id="sin-linea-base"),
        pytest.param(
            {"listening_ports": []},
            {"boot_id": "boot-actual"},
            id="linea-base-legacy",
        ),
        pytest.param(
            {"boot_id": "boot-anterior"},
            {"boot_id": "boot-actual"},
            id="reinicio-detectado",
        ),
        pytest.param(SAME_BOOT, SAME_BOOT, id="mismo-arranque"),
    ],
)
def test_run_once_expires_active_block_on_every_path(
    tmp_path: Path,
    monkeypatch,
    previous,
    current,
) -> None:
    agent, repo, _ = prepare_agent(
        tmp_path, monkeypatch, previous=previous, current=current
    )
    now = datetime.now(UTC)
    create_block(
        repo,
        block_id="vencido",
        target_ip="198.51.100.20",
        now=now - timedelta(seconds=600),
        expires_at=now - timedelta(seconds=1),
        active=True,
    )
    assert status(repo, "vencido") == "ACTIVE"

    agent.run_once()

    assert status(repo, "vencido") == "EXPIRED"


def test_run_once_expires_ip_port_block_from_qa_reproduction(
    tmp_path: Path,
    monkeypatch,
) -> None:
    agent, repo, calls = prepare_agent(tmp_path, monkeypatch)
    now = datetime.now(UTC)
    requested_at = now - timedelta(seconds=900)
    repo.create_response_block(
        block_id="qa-ssh",
        detection_event_id="detection-qa-ssh",
        response_event_id="response-qa-ssh",
        hostname="auditoria-clean-server",
        target_ip="192.168.1.247",
        family="ip",
        duration_seconds=600,
        requested_at=requested_at,
        expires_at=requested_at + timedelta(seconds=600),
        action="TEMPORARY_BLOCK_IP_PORT",
        protocol="tcp",
        port=22,
    )
    repo.mark_response_block_active(
        "qa-ssh",
        execution_event_id="execution-qa-ssh",
        applied_at=requested_at,
    )

    agent.run_once()

    assert status(repo, "qa-ssh") == "EXPIRED"
    # Sin nuevos tipos de evento: la reconciliación no emite nada.
    assert calls["events"] == []


def test_run_once_keeps_block_that_is_still_valid(
    tmp_path: Path,
    monkeypatch,
) -> None:
    agent, repo, _ = prepare_agent(tmp_path, monkeypatch)
    now = datetime.now(UTC)
    create_block(
        repo,
        block_id="vigente",
        target_ip="198.51.100.21",
        now=now,
        expires_at=now + timedelta(seconds=600),
        active=True,
    )

    agent.run_once()

    assert status(repo, "vigente") == "ACTIVE"


def test_run_once_expires_pending_block_like_repository(
    tmp_path: Path,
    monkeypatch,
) -> None:
    agent, repo, _ = prepare_agent(tmp_path, monkeypatch)
    now = datetime.now(UTC)
    create_block(
        repo,
        block_id="pendiente-vencido",
        target_ip="198.51.100.22",
        now=now - timedelta(seconds=600),
        expires_at=now - timedelta(seconds=1),
        active=False,
    )
    create_block(
        repo,
        block_id="pendiente-vigente",
        target_ip="198.51.100.23",
        now=now,
        expires_at=now + timedelta(seconds=600),
        active=False,
    )

    agent.run_once()

    assert status(repo, "pendiente-vencido") == "EXPIRED"
    # PENDING vigente no se toca: fallar PENDING es tarea exclusiva del
    # recovery de arranque.
    assert status(repo, "pendiente-vigente") == "PENDING"


def test_reconciliation_does_not_touch_firewall_or_recovery(
    tmp_path: Path,
    monkeypatch,
) -> None:
    agent, repo, _ = prepare_agent(tmp_path, monkeypatch)
    now = datetime.now(UTC)
    create_block(
        repo,
        block_id="vencido",
        target_ip="198.51.100.24",
        now=now - timedelta(seconds=600),
        expires_at=now - timedelta(seconds=1),
        active=True,
    )

    def forbidden(*_: Any, **__: Any) -> None:
        raise AssertionError("la reconciliación periódica no debe invocar esto")

    for name in (
        "prepare",
        "prepare_port_blocking",
        "add_temporary_block",
        "remove_block",
    ):
        monkeypatch.setattr(NftablesFirewallBackend, name, forbidden)

    monkeypatch.setattr(NftablesFirewallBackend, "__init__", forbidden)
    monkeypatch.setattr(ResponseRecoveryManager, "__init__", forbidden)
    monkeypatch.setattr(ResponseRecoveryManager, "recover", forbidden)
    monkeypatch.setattr(agent, "_recover_response_state", forbidden)

    assert agent._reconcile_expired_response_blocks() == 1
    assert status(repo, "vencido") == "EXPIRED"

    agent.run_once()


def test_run_once_works_without_expired_blocks(
    tmp_path: Path,
    monkeypatch,
) -> None:
    agent, _, calls = prepare_agent(tmp_path, monkeypatch)

    agent.run_once()

    assert agent._reconcile_expired_response_blocks() == 0
    assert calls["comparisons"] == [(SAME_BOOT, SAME_BOOT)]
    assert calls["saved"] == [SAME_BOOT]
    assert calls["events"] == []


def test_reconciliation_does_not_create_missing_database(
    tmp_path: Path,
    monkeypatch,
) -> None:
    agent, repo, calls = prepare_agent(
        tmp_path, monkeypatch, previous=None, initialize=False
    )

    agent.run_once()

    assert not repo.database_path.exists()
    assert calls["baselines"] == [True]


@pytest.mark.parametrize(
    "error",
    [
        RuntimeError("base bloqueada"),
        sqlite3.OperationalError("database is locked"),
        PermissionError(13, "Permission denied"),
    ],
    ids=["runtime", "sqlite", "permission"],
)
def test_reconciliation_failure_does_not_break_run_once(
    tmp_path: Path,
    monkeypatch,
    error: Exception,
) -> None:
    agent, _, calls = prepare_agent(tmp_path, monkeypatch)

    def failing(**_: Any) -> int:
        raise error

    monkeypatch.setattr(agent.event_repository, "expire_response_blocks", failing)

    agent.run_once()

    assert calls["saved"] == [SAME_BOOT]
    assert calls["events"] == []


@pytest.mark.parametrize(
    "error",
    [
        PermissionError(13, "Permission denied"),
        OSError(5, "Input/output error"),
    ],
    ids=["permission-denied", "io-error"],
)
def test_inaccessible_database_path_does_not_break_run_once(
    tmp_path: Path,
    monkeypatch,
    error: OSError,
) -> None:
    # Reproduce el fallo de G4: stat() de la ruta lanza en lugar de devolver
    # False (por ejemplo, /var/lib/auditoria-system en 0700 de otro usuario).
    agent, repo, calls = prepare_agent(tmp_path, monkeypatch)

    def denied_exists(self, *_: Any, **__: Any) -> bool:
        raise error

    denied_path = type(
        "DeniedPath", (type(repo.database_path),), {"exists": denied_exists}
    )
    monkeypatch.setattr(
        agent.event_repository, "database_path", denied_path(repo.database_path)
    )

    assert agent._reconcile_expired_response_blocks() == 0

    agent.run_once()

    assert calls["comparisons"] == [(SAME_BOOT, SAME_BOOT)]
    assert calls["saved"] == [SAME_BOOT]
    assert calls["events"] == []


@pytest.mark.skipif(
    os.name != "posix" or os.geteuid() == 0,
    reason="Requiere permisos POSIX reales y un usuario sin privilegios.",
)
def test_untraversable_state_dir_does_not_break_run_once(
    tmp_path: Path,
    monkeypatch,
) -> None:
    # Misma condición que el Dell, pero bajo tmp_path: el directorio de estado
    # existe y no puede recorrerse, así que Path.exists() lanza EACCES.
    agent, repo, calls = prepare_agent(tmp_path, monkeypatch)
    state_dir = repo.database_path.parent
    state_dir.chmod(0)
    try:
        with pytest.raises(PermissionError):
            repo.database_path.exists()

        assert agent._reconcile_expired_response_blocks() == 0

        agent.run_once()
    finally:
        state_dir.chmod(0o700)

    assert calls["comparisons"] == [(SAME_BOOT, SAME_BOOT)]
    assert calls["saved"] == [SAME_BOOT]
