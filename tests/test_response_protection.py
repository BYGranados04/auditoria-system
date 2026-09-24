from __future__ import annotations

import json

from app.response.protection import (
    ResponseProtectionResolver,
)


def fake_route_runner(
    command: list[str],
) -> tuple[int, str, str]:
    if "-6" in command:
        return (
            0,
            json.dumps(
                [
                    {
                        "gateway": "fe80::1",
                        "dev": "eno1",
                    }
                ]
            ),
            "",
        )

    return (
        0,
        json.dumps(
            [
                {
                    "gateway": "192.168.1.1",
                    "dev": "eno1",
                }
            ]
        ),
        "",
    )


def test_normalizes_configured_ips() -> None:
    resolver = ResponseProtectionResolver(
        trusted_admin_ips={
            "192.168.1.2",
            "2800:98:1902:a53::1",
            "invalid",
        },
        route_runner=fake_route_runner,
    )

    configured = resolver._configured_ips()

    assert "192.168.1.2" in configured
    assert "2800:98:1902:a53::1" in configured
    assert "invalid" not in configured


def test_normalizes_scoped_ipv6() -> None:
    normalized = ResponseProtectionResolver._normalize_ip("fe80::1234%eno1")

    assert normalized == "fe80::1234"


def test_reads_ipv4_and_ipv6_gateways() -> None:
    resolver = ResponseProtectionResolver(
        route_runner=fake_route_runner,
    )

    gateways = resolver._gateway_ips()

    assert gateways == frozenset(
        {
            "192.168.1.1",
            "fe80::1",
        }
    )


def test_resolve_combines_all_sources(
    monkeypatch,
) -> None:
    resolver = ResponseProtectionResolver(
        trusted_admin_ips={
            "192.168.1.2",
        },
        route_runner=fake_route_runner,
    )

    monkeypatch.setattr(
        resolver,
        "_ssh_peer_ips",
        lambda: frozenset(
            {
                "2001:db8::20",
            }
        ),
    )

    monkeypatch.setattr(
        resolver,
        "_local_ips",
        lambda: frozenset(
            {
                "192.168.1.68",
                "2001:db8::68",
            }
        ),
    )

    snapshot = resolver.resolve()

    assert snapshot.protected_ips == {
        "192.168.1.2",
        "2001:db8::20",
        "192.168.1.68",
        "2001:db8::68",
        "192.168.1.1",
        "fe80::1",
    }


def test_invalid_route_output_is_ignored() -> None:
    def bad_runner(
        command: list[str],
    ) -> tuple[int, str, str]:
        return 0, "not-json", ""

    resolver = ResponseProtectionResolver(
        route_runner=bad_runner,
    )

    assert resolver._gateway_ips() == frozenset()
