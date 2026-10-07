from __future__ import annotations

import shutil
import sqlite3
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.core.events import SecurityEvent
from app.response.engine import ResponsePolicyEngine
from app.response.executor import ResponseExecutor
from app.response.firewall import (
    FirewallSafetyError,
    NftablesFirewallPlanner,
    TemporaryBlockPlan,
    TemporaryPortBlockPlan,
)
from app.response.firewall_backend import (
    FirewallCommandResult,
    NftablesFirewallBackend,
)
from app.response.models import ResponseDecision
from app.response.policy import ResponsePolicy
from app.response.protection import ResponseProtectionResolver
from app.response.recovery import ResponseRecoveryManager
from app.storage.event_repository import EventRepository

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)


def detection(
    source_ip: str = "192.168.1.50",
    event_type: str = "SSH_USER_ENUMERATION_ATTEMPT",
) -> SecurityEvent:
    return SecurityEvent(
        hostname="server-test",
        source="detection-engine",
        category="detection",
        event_type=event_type,
        severity="high",
        description="Detección de prueba",
        evidence={"source_ip": source_ip},
    )


def port_decision(
    *,
    target_ip: str = "192.168.1.50",
    protocol: str | None = "tcp",
    port: int | None = 22,
    duration_seconds: int = 120,
) -> ResponseDecision:
    return ResponseDecision(
        detection_event_id=uuid4(),
        hostname="server-test",
        mode="automatic",
        action="TEMPORARY_BLOCK_IP_PORT",
        target_ip=target_ip,
        reason="Decisión de prueba.",
        duration_seconds=duration_seconds,
        execution_allowed=True,
        executed=False,
        protocol=protocol,
        port=port,
    )


class FakeProtectionResolver:
    def __init__(self, protected_ips: set[str] | None = None) -> None:
        self.protected_ips = protected_ips or set()

    def resolve(self):
        return SimpleNamespace(protected_ips=set(self.protected_ips))


class FakeBackend:
    def __init__(self) -> None:
        self.prepare_calls = 0
        self.port_prepare_calls = 0
        self.added: list[object] = []
        self.removed: list[object] = []

    def prepare(self) -> bool:
        self.prepare_calls += 1
        return False

    def prepare_port_blocking(self) -> bool:
        self.port_prepare_calls += 1
        return False

    def add_temporary_block(self, plan) -> None:
        self.added.append(plan)

    def remove_block(self, plan) -> None:
        self.removed.append(plan)


def repository(tmp_path: Path) -> EventRepository:
    repo = EventRepository(tmp_path / "auditoria.db")
    repo.initialize()
    return repo


def executor(
    tmp_path: Path,
    *,
    protected: set[str] | None = None,
    trusted: set[str] | None = None,
) -> tuple[ResponseExecutor, FakeBackend, EventRepository]:
    repo = repository(tmp_path)
    backend = FakeBackend()
    policy = ResponsePolicy(
        mode="automatic",
        trusted_admin_ips=trusted or set(),
        block_scope="ip_port",
        allow_temporary_ip_port_block=True,
    )
    instance = ResponseExecutor(
        policy,
        dry_run=False,
        repository=repo,
        backend=backend,  # type: ignore[arg-type]
        protection_resolver=FakeProtectionResolver(protected),  # type: ignore[arg-type]
        clock=lambda: NOW,
    )
    return instance, backend, repo


# --------------------------------------------------------------------------
# Planner y render nftables
# --------------------------------------------------------------------------


def test_plans_ipv4_port_block_with_timeout() -> None:
    plan = NftablesFirewallPlanner().plan_temporary_port_block(
        "192.168.1.50", "tcp", 22, 120
    )

    assert plan == TemporaryPortBlockPlan(
        family="ip",
        target_ip="192.168.1.50",
        protocol="tcp",
        port=22,
        duration_seconds=120,
    )
    assert plan.render_add_element() == (
        "add element inet auditoria_response blocked_ipv4_port "
        "{ 192.168.1.50 . tcp . 22 timeout 120s }"
    )
    assert plan.render_delete_element() == (
        "delete element inet auditoria_response blocked_ipv4_port "
        "{ 192.168.1.50 . tcp . 22 }"
    )


def test_plans_ipv6_port_block_with_normalized_address() -> None:
    plan = NftablesFirewallPlanner().plan_temporary_port_block(
        "2001:DB8:0:0::50", "udp", 53, 600
    )

    assert plan.family == "ip6"
    assert plan.set_name == "blocked_ipv6_port"
    assert plan.render_add_element() == (
        "add element inet auditoria_response blocked_ipv6_port "
        "{ 2001:db8::50 . udp . 53 timeout 600s }"
    )


@pytest.mark.parametrize(
    ("target_ip", "protocol", "port", "duration"),
    [
        ("100.64.0.1", "tcp", 22, 120),
        ("100.127.255.254", "tcp", 22, 120),
        ("fd7a:115c:a1e0::1", "tcp", 22, 120),
        ("127.0.0.1", "tcp", 22, 120),
        ("::1", "tcp", 22, 120),
        ("fe80::1", "tcp", 22, 120),
        ("192.168.1.50", "icmp", 22, 120),
        ("192.168.1.50", "tcp", 0, 120),
        ("192.168.1.50", "tcp", 65536, 120),
        ("192.168.1.50", "tcp", 22, 59),
        ("192.168.1.50", "tcp", 22, 86401),
        ("no-es-ip", "tcp", 22, 120),
    ],
)
def test_port_planner_rejects_unsafe_requests(
    target_ip: str,
    protocol: str,
    port: int,
    duration: int,
) -> None:
    with pytest.raises(FirewallSafetyError):
        NftablesFirewallPlanner().plan_temporary_port_block(
            target_ip, protocol, port, duration
        )


def test_port_planner_rejects_dynamically_protected_addresses() -> None:
    planner = NftablesFirewallPlanner(protected_ips={"203.0.113.7", "2001:db8::7"})

    for address in ("203.0.113.7", "2001:db8::7"):
        with pytest.raises(FirewallSafetyError):
            planner.plan_temporary_port_block(address, "tcp", 22, 120)


def test_ip_block_rendering_is_unchanged() -> None:
    plan = NftablesFirewallPlanner().plan_temporary_block("192.168.1.50", 900)

    assert plan == TemporaryBlockPlan(
        family="ip",
        target_ip="192.168.1.50",
        duration_seconds=900,
    )
    assert plan.render_add_element() == (
        "add element inet auditoria_response blocked_ipv4 { 192.168.1.50 timeout 900s }"
    )
    ruleset = NftablesFirewallPlanner.render_prepare_ruleset()
    assert "blocked_ipv4_port" not in ruleset
    assert "ip saddr @blocked_ipv4 counter drop" in ruleset


def test_port_ruleset_is_idempotent_and_does_not_touch_ip_sets() -> None:
    script = NftablesFirewallPlanner.render_prepare_port_ruleset()
    lines = script.strip().splitlines()

    assert "flush chain inet auditoria_response input_port" in lines
    flush_index = lines.index("flush chain inet auditoria_response input_port")
    assert all(not line.startswith("add rule") for line in lines[:flush_index])
    assert all(line.split()[0] == "add" or line.startswith("flush") for line in lines)
    assert "type ipv4_addr . inet_proto . inet_service; flags timeout;" in script
    assert "type ipv6_addr . inet_proto . inet_service; flags timeout;" in script
    assert 'iifname "lo" return' in script
    assert 'iifname "tailscale0" return' in script
    assert "@blocked_ipv4_port counter drop" in script
    assert "@blocked_ipv6_port counter drop" in script
    for forbidden in ("delete", "flush table", "flush ruleset", " input {"):
        assert forbidden not in script
    assert "blocked_ipv4 " not in script.replace("blocked_ipv4_port", "")


# --------------------------------------------------------------------------
# Backend
# --------------------------------------------------------------------------


class RecordingRunner:
    def __init__(self, *, table_exists: bool) -> None:
        self.table_exists = table_exists
        self.calls: list[tuple[list[str], str | None]] = []

    def __call__(self, command: list[str], input_text: str | None):
        self.calls.append((list(command), input_text))
        if command[1:] == ["list", "table", "inet", "auditoria_response"]:
            if self.table_exists:
                return FirewallCommandResult(0, "table", "")
            return FirewallCommandResult(1, "", "Error: No such file or directory")
        return FirewallCommandResult(0, "", "")


def test_prepare_port_blocking_creates_base_table_then_port_structures() -> None:
    runner = RecordingRunner(table_exists=False)
    backend = NftablesFirewallBackend(runner=runner)

    created = backend.prepare_port_blocking()

    scripts = [input_text for _, input_text in runner.calls if input_text]
    assert created is True
    assert scripts[0] == NftablesFirewallPlanner.render_prepare_ruleset()
    assert scripts[-1] == NftablesFirewallPlanner.render_prepare_port_ruleset()
    assert [command[1] for command, text in runner.calls if text][-2:] == [
        "--check",
        "--file",
    ]


def test_prepare_port_blocking_is_repeatable_on_existing_table() -> None:
    runner = RecordingRunner(table_exists=True)
    backend = NftablesFirewallBackend(runner=runner)

    assert backend.prepare_port_blocking() is False
    assert backend.prepare_port_blocking() is False

    scripts = [input_text for _, input_text in runner.calls if input_text]
    port_script = NftablesFirewallPlanner.render_prepare_port_ruleset()
    assert scripts == [port_script] * 4
    assert NftablesFirewallPlanner.render_prepare_ruleset() not in scripts


def test_backend_adds_and_removes_port_elements() -> None:
    runner = RecordingRunner(table_exists=True)
    backend = NftablesFirewallBackend(runner=runner)
    plan = NftablesFirewallPlanner().plan_temporary_port_block(
        "192.168.1.50", "tcp", 22, 120
    )

    backend.add_temporary_block(plan)
    backend.remove_block(plan)

    scripts = [input_text for _, input_text in runner.calls]
    assert scripts == [
        plan.render_add_element(),
        plan.render_add_element(),
        plan.render_delete_element(),
        plan.render_delete_element(),
    ]


def _namespace_nft_available() -> bool:
    if shutil.which("nft") is None or shutil.which("unshare") is None:
        return False
    try:
        result = subprocess.run(
            ["unshare", "-rn", "nft", "list", "ruleset"],
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


@pytest.mark.skipif(
    not _namespace_nft_available(),
    reason="Requiere nft y namespaces de red sin privilegios.",
)
def test_real_nftables_port_structures_are_idempotent_in_namespace(
    tmp_path: Path,
) -> None:
    base = NftablesFirewallPlanner.render_prepare_ruleset()
    port = NftablesFirewallPlanner.render_prepare_port_ruleset()
    planner = NftablesFirewallPlanner()
    element = planner.plan_temporary_port_block(
        "192.168.1.50", "tcp", 22, 120
    ).render_add_element()
    ip_element = planner.plan_temporary_block("192.168.1.51", 120).render_add_element()
    script = tmp_path / "run.sh"
    script.write_text(
        "set -e\n"
        f"nft -f - <<'EOF'\n{base}EOF\n"
        + "".join(f"nft -f - <<'EOF'\n{port}EOF\n" for _ in range(3))
        + f"echo '{element}' | nft -f -\n"
        + f"echo '{element}' | nft -f -\n"
        + f"echo '{ip_element}' | nft -f -\n"
        + "nft list table inet auditoria_response\n"
    )

    result = subprocess.run(
        ["unshare", "-rn", "bash", str(script)],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    output = result.stdout
    assert output.count("@blocked_ipv4_port counter") == 1
    assert output.count("@blocked_ipv6_port counter") == 1
    assert output.count("ip saddr @blocked_ipv4 counter") == 1
    assert "192.168.1.50 . tcp . 22 timeout 2m" in output
    assert "192.168.1.51 timeout 2m" in output


# --------------------------------------------------------------------------
# Ejecutor y persistencia
# --------------------------------------------------------------------------


def test_executor_applies_ipv4_port_block_and_persists_scope(tmp_path: Path) -> None:
    instance, backend, repo = executor(tmp_path)

    result = instance.execute(
        port_decision(),
        response_event_id=uuid4(),
        execution_event_id=uuid4(),
    )

    assert result.status == "EXECUTED"
    assert result.action == "TEMPORARY_BLOCK_IP_PORT"
    assert (result.protocol, result.port) == ("tcp", 22)
    assert result.duration_seconds == 120
    assert backend.port_prepare_calls == 1
    assert backend.prepare_calls == 0
    assert isinstance(backend.added[0], TemporaryPortBlockPlan)
    stored = repo.get_response_block(str(result.block_id))
    assert stored is not None
    assert stored["status"] == "ACTIVE"
    assert stored["action"] == "TEMPORARY_BLOCK_IP_PORT"
    assert (stored["protocol"], stored["port"]) == ("tcp", 22)
    assert stored["duration_seconds"] == 120


def test_executor_applies_ipv6_port_block(tmp_path: Path) -> None:
    instance, backend, _ = executor(tmp_path)

    result = instance.execute(
        port_decision(target_ip="2001:db8::50"),
        response_event_id=uuid4(),
        execution_event_id=uuid4(),
    )

    assert result.status == "EXECUTED"
    assert backend.added[0].set_name == "blocked_ipv6_port"


@pytest.mark.parametrize(
    ("target_ip", "protected", "trusted"),
    [
        ("100.64.12.34", None, None),
        ("fd7a:115c:a1e0::99", None, None),
        ("203.0.113.9", None, {"203.0.113.9"}),
        ("198.51.100.4", {"198.51.100.4"}, None),
        ("127.0.0.1", None, None),
    ],
    ids=[
        "tailscale-ipv4",
        "tailscale-ipv6",
        "trusted-admin",
        "ssh-session-or-local",
        "loopback",
    ],
)
def test_executor_never_blocks_protected_addresses_by_port(
    tmp_path: Path,
    target_ip: str,
    protected: set[str] | None,
    trusted: set[str] | None,
) -> None:
    instance, backend, repo = executor(
        tmp_path,
        protected=protected,
        trusted=trusted,
    )

    result = instance.execute(
        port_decision(target_ip=target_ip),
        response_event_id=uuid4(),
        execution_event_id=uuid4(),
    )

    assert result.status == "SKIPPED"
    assert result.executed is False
    assert backend.added == []
    assert repo.list_live_response_blocks(now=NOW) == []


def test_protection_resolver_protects_active_ssh_sessions_on_custom_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connections = [
        SimpleNamespace(
            status="ESTABLISHED",
            laddr=SimpleNamespace(ip="10.0.0.5", port=2222),
            raddr=SimpleNamespace(ip="198.51.100.20", port=50000),
        ),
        SimpleNamespace(
            status="ESTABLISHED",
            laddr=SimpleNamespace(ip="10.0.0.5", port=22),
            raddr=SimpleNamespace(ip="198.51.100.21", port=50001),
        ),
    ]
    monkeypatch.setattr(
        "app.response.protection.psutil.net_connections",
        lambda kind: connections,
    )
    monkeypatch.setattr(
        "app.response.protection.psutil.CONN_ESTABLISHED", "ESTABLISHED"
    )

    default = ResponseProtectionResolver(route_runner=lambda _c: (1, "", ""))
    custom = ResponseProtectionResolver(
        route_runner=lambda _c: (1, "", ""),
        ssh_ports=(2222,),
    )

    assert default._ssh_peer_ips() == frozenset({"198.51.100.21"})
    assert custom._ssh_peer_ips() == frozenset({"198.51.100.20", "198.51.100.21"})


def test_executor_rejects_port_decision_without_valid_service(tmp_path: Path) -> None:
    instance, backend, _ = executor(tmp_path)

    result = instance.execute(
        port_decision(protocol=None, port=None),
        response_event_id=uuid4(),
        execution_event_id=uuid4(),
    )

    assert result.status == "SKIPPED"
    assert backend.added == []


def test_port_and_ip_blocks_coexist_and_duplicates_are_rejected(
    tmp_path: Path,
) -> None:
    repo = repository(tmp_path)
    common = {
        "detection_event_id": str(uuid4()),
        "response_event_id": str(uuid4()),
        "hostname": "server-test",
        "target_ip": "192.168.1.50",
        "family": "ip",
        "duration_seconds": 120,
        "requested_at": NOW,
        "expires_at": NOW + timedelta(seconds=120),
    }

    repo.create_response_block(block_id=str(uuid4()), **common)
    repo.create_response_block(
        block_id=str(uuid4()),
        action="TEMPORARY_BLOCK_IP_PORT",
        protocol="tcp",
        port=22,
        **common,
    )
    repo.create_response_block(
        block_id=str(uuid4()),
        action="TEMPORARY_BLOCK_IP_PORT",
        protocol="tcp",
        port=443,
        **common,
    )

    with pytest.raises(sqlite3.IntegrityError):
        repo.create_response_block(
            block_id=str(uuid4()),
            action="TEMPORARY_BLOCK_IP_PORT",
            protocol="tcp",
            port=22,
            **common,
        )

    with pytest.raises(sqlite3.IntegrityError):
        repo.create_response_block(block_id=str(uuid4()), **common)

    with pytest.raises(ValueError):
        repo.create_response_block(
            block_id=str(uuid4()),
            action="TEMPORARY_BLOCK_IP_PORT",
            **common,
        )

    assert len(repo.list_live_response_blocks(now=NOW)) == 3


def test_port_block_expires_logically(tmp_path: Path) -> None:
    instance, _, repo = executor(tmp_path)
    result = instance.execute(
        port_decision(duration_seconds=120),
        response_event_id=uuid4(),
        execution_event_id=uuid4(),
    )

    assert repo.expire_response_blocks(now=NOW + timedelta(seconds=119)) == 0
    assert repo.expire_response_blocks(now=NOW + timedelta(seconds=120)) == 1
    stored = repo.get_response_block(str(result.block_id))
    assert stored is not None
    assert stored["status"] == "EXPIRED"


def test_recovery_restores_port_blocks_with_remaining_time(tmp_path: Path) -> None:
    instance, _, repo = executor(tmp_path)
    instance.execute(
        port_decision(duration_seconds=600),
        response_event_id=uuid4(),
        execution_event_id=uuid4(),
    )
    backend = FakeBackend()
    manager = ResponseRecoveryManager(
        repository=repo,
        backend=backend,  # type: ignore[arg-type]
        planner=NftablesFirewallPlanner(),
    )

    summary = manager.recover(now=NOW + timedelta(seconds=100))

    assert summary.restored_count == 1
    assert backend.port_prepare_calls == 1
    plan = backend.added[0]
    assert isinstance(plan, TemporaryPortBlockPlan)
    assert (plan.protocol, plan.port, plan.duration_seconds) == ("tcp", 22, 500)


def test_recovery_marks_port_block_failed_if_address_became_protected(
    tmp_path: Path,
) -> None:
    instance, _, repo = executor(tmp_path)
    result = instance.execute(
        port_decision(duration_seconds=600),
        response_event_id=uuid4(),
        execution_event_id=uuid4(),
    )
    backend = FakeBackend()
    manager = ResponseRecoveryManager(
        repository=repo,
        backend=backend,  # type: ignore[arg-type]
        planner=NftablesFirewallPlanner(protected_ips={"192.168.1.50"}),
    )

    summary = manager.recover(now=NOW + timedelta(seconds=10))

    assert summary.failed_restore_count == 1
    assert backend.added == []
    stored = repo.get_response_block(str(result.block_id))
    assert stored is not None
    assert stored["status"] == "FAILED"


# --------------------------------------------------------------------------
# Motor de políticas
# --------------------------------------------------------------------------


def test_engine_selects_port_block_in_automatic_when_authorized() -> None:
    engine = ResponsePolicyEngine(
        ResponsePolicy(
            mode="automatic",
            block_scope="ip_port",
            allow_temporary_ip_port_block=True,
            temporary_block_seconds=300,
            ssh_port=2222,
        )
    )

    decision = engine.evaluate(detection())

    assert decision.action == "TEMPORARY_BLOCK_IP_PORT"
    assert (decision.protocol, decision.port) == ("tcp", 2222)
    assert decision.duration_seconds == 300
    assert decision.execution_allowed is True


def test_engine_requires_specific_authorization_for_port_block() -> None:
    engine = ResponsePolicyEngine(
        ResponsePolicy(
            mode="automatic",
            block_scope="ip_port",
            allow_temporary_ip_block=True,
        )
    )

    decision = engine.evaluate(detection())

    assert decision.action == "RECOMMEND_BLOCK_IP_PORT"
    assert decision.execution_allowed is False


@pytest.mark.parametrize("mode", ["audit_only", "assisted"])
def test_engine_only_recommends_port_block_outside_automatic(mode: str) -> None:
    engine = ResponsePolicyEngine(
        ResponsePolicy(
            mode=mode,
            block_scope="ip_port",
            allow_temporary_ip_port_block=True,
        )
    )

    decision = engine.evaluate(detection())

    assert decision.action == "RECOMMEND_BLOCK_IP_PORT"
    assert decision.execution_allowed is False
    assert decision.approval_required is (mode == "assisted")


@pytest.mark.parametrize(
    ("source_ip", "protected"),
    [
        ("100.100.1.1", None),
        ("fd7a:115c:a1e0::5", None),
        ("203.0.113.5", {"203.0.113.5"}),
    ],
    ids=["tailscale-ipv4", "tailscale-ipv6", "dynamic-protection"],
)
def test_engine_decides_and_execution_layer_rejects_protected_addresses(
    tmp_path: Path,
    source_ip: str,
    protected: set[str] | None,
) -> None:
    engine = ResponsePolicyEngine(
        ResponsePolicy(
            mode="automatic",
            block_scope="ip_port",
            allow_temporary_ip_port_block=True,
        )
    )
    instance, backend, repo = executor(tmp_path, protected=protected)

    decision = engine.evaluate(detection(source_ip))
    result = instance.execute(
        decision,
        response_event_id=uuid4(),
        execution_event_id=uuid4(),
    )

    # El motor documenta su intención; la capa de ejecución la rechaza.
    assert decision.action == "TEMPORARY_BLOCK_IP_PORT"
    assert decision.execution_allowed is True
    assert result.status == "SKIPPED"
    assert result.protection_rejected is True
    assert "proteg" in result.reason
    assert backend.added == []
    assert repo.list_live_response_blocks(now=NOW) == []


def test_dry_run_executor_also_rejects_tailscale_without_touching_system() -> None:
    policy = ResponsePolicy(
        mode="automatic",
        block_scope="ip_port",
        allow_temporary_ip_port_block=True,
    )
    decision = ResponsePolicyEngine(policy).evaluate(detection("100.64.0.9"))

    result = ResponseExecutor(policy).execute(decision)

    assert decision.action == "TEMPORARY_BLOCK_IP_PORT"
    assert result.status == "SKIPPED"
    assert result.protection_rejected is True


def test_default_policy_keeps_legacy_temporary_ip_block_decision() -> None:
    engine = ResponsePolicyEngine(
        ResponsePolicy(mode="automatic", allow_temporary_ip_block=True)
    )

    decision = engine.evaluate(detection())

    assert decision.action == "TEMPORARY_BLOCK_IP"
    assert decision.duration_seconds == 900
    assert decision.protocol is None
    assert decision.port is None
    assert decision.reason == (
        "La actividad cumple una política de respuesta automática autorizada."
    )


def test_engine_without_known_service_never_executes(monkeypatch) -> None:
    engine = ResponsePolicyEngine(
        ResponsePolicy(
            mode="automatic",
            block_scope="ip_port",
            allow_temporary_ip_block=True,
            allow_temporary_ip_port_block=True,
        )
    )
    monkeypatch.setattr(engine, "_service_for", lambda _event: (None, None))

    decision = engine.evaluate(detection())

    assert decision.action == "RECOMMEND_BLOCK_IP"
    assert decision.execution_allowed is False


def test_equivalent_live_block_is_idempotent_for_both_actions(tmp_path: Path) -> None:
    instance, backend, repo = executor(tmp_path)
    legacy = ResponseDecision(
        detection_event_id=uuid4(),
        hostname="server-test",
        mode="automatic",
        action="TEMPORARY_BLOCK_IP",
        target_ip="192.168.1.60",
        reason="Decisión de prueba.",
        duration_seconds=900,
        execution_allowed=True,
    )

    results = [
        instance.execute(item, response_event_id=uuid4(), execution_event_id=uuid4())
        for item in (port_decision(), port_decision(), legacy, legacy)
    ]

    assert [result.status for result in results] == [
        "EXECUTED",
        "SKIPPED",
        "EXECUTED",
        "SKIPPED",
    ]
    assert "vigente equivalente" in results[1].reason
    assert len(backend.added) == 2
    assert len(repo.list_live_response_blocks(now=NOW)) == 2
