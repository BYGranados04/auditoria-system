from __future__ import annotations

import pytest

from app.response.firewall import (
    FirewallSafetyError,
    NftablesFirewallPlanner,
)


def test_plans_ipv4_temporary_block() -> None:
    planner = NftablesFirewallPlanner()

    plan = planner.plan_temporary_block(
        "192.168.1.50",
        900,
    )

    assert plan.family == "ip"
    assert plan.target_ip == "192.168.1.50"
    assert plan.set_name == "blocked_ipv4"
    assert plan.duration_seconds == 900

    assert plan.render_add_element() == (
        "add element inet auditoria_response blocked_ipv4 { 192.168.1.50 timeout 900s }"
    )


def test_plans_ipv6_temporary_block() -> None:
    planner = NftablesFirewallPlanner()

    plan = planner.plan_temporary_block(
        "2001:db8::50",
        1200,
    )

    assert plan.family == "ip6"
    assert plan.target_ip == "2001:db8::50"
    assert plan.set_name == "blocked_ipv6"


@pytest.mark.parametrize(
    "target_ip",
    [
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        "::",
        "224.0.0.1",
        "ff02::1",
        "169.254.1.1",
        "fe80::1",
    ],
)
def test_rejects_protected_address_categories(
    target_ip: str,
) -> None:
    planner = NftablesFirewallPlanner()

    with pytest.raises(FirewallSafetyError):
        planner.plan_temporary_block(
            target_ip,
            900,
        )


@pytest.mark.parametrize(
    "target_ip",
    [
        "100.64.0.1",
        "100.91.227.41",
        "100.97.134.41",
        "fd7a:115c:a1e0::1",
        "fd7a:115c:a1e0::d832:e32a",
    ],
)
def test_rejects_tailscale_addresses(
    target_ip: str,
) -> None:
    planner = NftablesFirewallPlanner()

    with pytest.raises(
        FirewallSafetyError,
        match="Tailscale",
    ):
        planner.plan_temporary_block(
            target_ip,
            900,
        )


@pytest.mark.parametrize(
    "target_ip",
    [
        "192.168.1.1",
        "192.168.1.2",
        "192.168.1.68",
        "2001:db8::25",
    ],
)
def test_rejects_explicitly_protected_ips(
    target_ip: str,
) -> None:
    planner = NftablesFirewallPlanner(
        protected_ips={
            "192.168.1.1",
            "192.168.1.2",
            "192.168.1.68",
            "2001:db8::25",
        }
    )

    with pytest.raises(
        FirewallSafetyError,
        match="lista",
    ):
        planner.plan_temporary_block(
            target_ip,
            900,
        )


@pytest.mark.parametrize(
    "duration",
    [
        0,
        59,
        86401,
    ],
)
def test_rejects_invalid_block_duration(
    duration: int,
) -> None:
    planner = NftablesFirewallPlanner()

    with pytest.raises(
        FirewallSafetyError,
        match="duración",
    ):
        planner.plan_temporary_block(
            "192.168.1.50",
            duration,
        )


def test_rejects_invalid_ip() -> None:
    planner = NftablesFirewallPlanner()

    with pytest.raises(
        FirewallSafetyError,
        match="no es válida",
    ):
        planner.plan_temporary_block(
            "esto-no-es-una-ip",
            900,
        )


def test_renders_delete_element() -> None:
    planner = NftablesFirewallPlanner()

    plan = planner.plan_temporary_block(
        "192.168.1.50",
        900,
    )

    assert plan.render_delete_element() == (
        "delete element inet auditoria_response blocked_ipv4 { 192.168.1.50 }"
    )


def test_renders_isolated_nftables_ruleset() -> None:
    planner = NftablesFirewallPlanner()

    ruleset = planner.render_prepare_ruleset()

    assert "table inet auditoria_response" in ruleset
    assert "set blocked_ipv4" in ruleset
    assert "type ipv4_addr;" in ruleset
    assert "set blocked_ipv6" in ruleset
    assert "type ipv6_addr;" in ruleset
    assert "flags timeout;" in ruleset

    assert 'iifname "lo" return' in ruleset
    assert 'iifname "tailscale0" return' in ruleset

    assert "ip saddr @blocked_ipv4 counter drop" in ruleset
    assert "ip6 saddr @blocked_ipv6 counter drop" in ruleset
