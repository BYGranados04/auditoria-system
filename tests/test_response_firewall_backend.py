from __future__ import annotations

import pytest

from app.response.firewall import (
    NftablesFirewallPlanner,
)
from app.response.firewall_backend import (
    FirewallBackendError,
    FirewallCommandResult,
    NftablesFirewallBackend,
)


class FakeRunner:
    def __init__(
        self,
        results: list[FirewallCommandResult],
    ) -> None:
        self.results = list(results)
        self.calls: list[tuple[list[str], str | None]] = []

    def __call__(
        self,
        command: list[str],
        input_text: str | None,
    ) -> FirewallCommandResult:
        self.calls.append(
            (
                list(command),
                input_text,
            )
        )

        if not self.results:
            raise AssertionError("FakeRunner recibió más llamadas de las esperadas.")

        return self.results.pop(0)


def ok(
    stdout: str = "",
) -> FirewallCommandResult:
    return FirewallCommandResult(
        returncode=0,
        stdout=stdout,
        stderr="",
    )


def fail(
    stderr: str = "error",
) -> FirewallCommandResult:
    return FirewallCommandResult(
        returncode=1,
        stdout="",
        stderr=stderr,
    )


def test_prepare_does_nothing_when_table_exists() -> None:
    runner = FakeRunner(
        [
            ok("table inet auditoria_response"),
        ]
    )

    backend = NftablesFirewallBackend(
        runner=runner,
    )

    created = backend.prepare()

    assert created is False
    assert len(runner.calls) == 1

    command, input_text = runner.calls[0]

    assert command == [
        "/usr/sbin/nft",
        "list",
        "table",
        "inet",
        "auditoria_response",
    ]
    assert input_text is None


def test_prepare_creates_table_when_missing() -> None:
    runner = FakeRunner(
        [
            fail("No such file or directory"),
            ok(),
            ok(),
        ]
    )

    backend = NftablesFirewallBackend(
        runner=runner,
    )

    created = backend.prepare()

    assert created is True
    assert len(runner.calls) == 3

    check_command, check_script = runner.calls[1]

    assert check_command == [
        "/usr/sbin/nft",
        "--check",
        "--file",
        "-",
    ]

    assert "table inet auditoria_response" in check_script

    apply_command, apply_script = runner.calls[2]

    assert apply_command == [
        "/usr/sbin/nft",
        "--file",
        "-",
    ]

    assert apply_script == check_script


def test_add_temporary_block_checks_then_applies() -> None:
    runner = FakeRunner(
        [
            ok(),
            ok(),
        ]
    )

    backend = NftablesFirewallBackend(
        runner=runner,
    )

    planner = NftablesFirewallPlanner()

    plan = planner.plan_temporary_block(
        "198.51.100.77",
        60,
    )

    backend.add_temporary_block(plan)

    assert len(runner.calls) == 2

    check_command, check_script = runner.calls[0]
    apply_command, apply_script = runner.calls[1]

    assert check_command == [
        "/usr/sbin/nft",
        "--check",
        "--file",
        "-",
    ]

    assert apply_command == [
        "/usr/sbin/nft",
        "--file",
        "-",
    ]

    expected = (
        "add element inet auditoria_response blocked_ipv4 { 198.51.100.77 timeout 60s }"
    )

    assert check_script == expected
    assert apply_script == expected


def test_remove_block_checks_then_applies() -> None:
    runner = FakeRunner(
        [
            ok(),
            ok(),
        ]
    )

    backend = NftablesFirewallBackend(
        runner=runner,
    )

    planner = NftablesFirewallPlanner()

    plan = planner.plan_temporary_block(
        "198.51.100.77",
        60,
    )

    backend.remove_block(plan)

    assert len(runner.calls) == 2

    _, check_script = runner.calls[0]
    _, apply_script = runner.calls[1]

    expected = "delete element inet auditoria_response blocked_ipv4 { 198.51.100.77 }"

    assert check_script == expected
    assert apply_script == expected


def test_backend_raises_on_failed_check() -> None:
    runner = FakeRunner(
        [
            fail("permission denied"),
        ]
    )

    backend = NftablesFirewallBackend(
        runner=runner,
    )

    planner = NftablesFirewallPlanner()

    plan = planner.plan_temporary_block(
        "198.51.100.77",
        60,
    )

    with pytest.raises(
        FirewallBackendError,
        match="permission denied",
    ):
        backend.add_temporary_block(plan)

    assert len(runner.calls) == 1


def test_backend_never_invokes_shell() -> None:
    runner = FakeRunner(
        [
            ok(),
            ok(),
        ]
    )

    backend = NftablesFirewallBackend(
        runner=runner,
    )

    planner = NftablesFirewallPlanner()

    plan = planner.plan_temporary_block(
        "198.51.100.77",
        60,
    )

    backend.add_temporary_block(plan)

    for command, _ in runner.calls:
        assert isinstance(command, list)
        assert command[0] == "/usr/sbin/nft"


def test_table_exists_returns_false_only_when_missing() -> None:
    runner = FakeRunner(
        [
            fail("No such file or directory"),
        ]
    )

    backend = NftablesFirewallBackend(
        runner=runner,
    )

    assert backend.table_exists() is False


def test_table_exists_raises_on_unexpected_error() -> None:
    runner = FakeRunner(
        [
            fail("Operation not permitted"),
        ]
    )

    backend = NftablesFirewallBackend(
        runner=runner,
    )

    with pytest.raises(
        FirewallBackendError,
        match="Operation not permitted",
    ):
        backend.table_exists()
