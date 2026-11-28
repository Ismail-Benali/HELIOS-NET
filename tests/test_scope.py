"""
HELIOS-NET :: tests/test_scope.py
Unit tests for enterprise scope enforcement and CIDR validation.
"""

from __future__ import annotations

import pytest

from core.scope import ScopeEnforcer, ScopeError


def test_scope_enforcement_ip():
    enforcer = ScopeEnforcer(allowed_cidrs=["192.168.1.0/24", "10.0.0.0/8"])

    # Allowed
    assert enforcer.is_target_allowed("192.168.1.50") is True
    assert enforcer.is_target_allowed("10.5.5.5") is True

    # Out of scope
    assert enforcer.is_target_allowed("8.8.8.8") is False
    assert enforcer.is_target_allowed("192.168.2.1") is False


def test_scope_enforcement_domain():
    enforcer = ScopeEnforcer(
        allowed_cidrs=["0.0.0.0/0"], allowed_domains=["example.com", "test.org"]
    )

    assert enforcer.is_target_allowed("example.com") is True
    assert enforcer.is_target_allowed("sub.example.com") is True
    assert enforcer.is_target_allowed("malicious.com") is False


def test_default_scope_file_loads_with_decimal_rate_limit():
    enforcer = ScopeEnforcer.from_config()
    assert enforcer.is_target_allowed("127.0.0.1")
    assert not enforcer.is_target_allowed("192.0.2.1")
    assert 443 in enforcer.ports


def test_scope_rejects_non_finite_rate_limit_values(tmp_path):
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        "scope:\n  rate_limit:\n    timeout_seconds: 1e309\n",
        encoding="utf-8",
    )
    with pytest.raises(ScopeError, match="must be a number"):
        ScopeEnforcer.from_config(scope_file)


def test_resolve_authorized_ips_filters_out_of_scope_dns_answers():
    enforcer = ScopeEnforcer(
        allowed_cidrs=["10.0.0.0/8"],
        allowed_domains=["app.example.test"],
    )

    resolved = enforcer.resolve_authorized_ips(
        "app.example.test",
        resolver=lambda _name: ["203.0.113.8", "10.2.3.4", "10.2.3.4"],
    )

    assert resolved == ["10.2.3.4"]


def test_resolve_authorized_ips_rejects_domain_without_authorized_cidr():
    enforcer = ScopeEnforcer(allowed_domains=["app.example.test"])

    with pytest.raises(ScopeError, match="no addresses inside the authorized CIDRs"):
        enforcer.resolve_authorized_ips(
            "app.example.test", resolver=lambda _name: ["10.2.3.4"]
        )


def test_resolve_authorized_ips_rejects_unresolvable_target():
    enforcer = ScopeEnforcer(
        allowed_cidrs=["10.0.0.0/8"],
        allowed_domains=["app.example.test"],
    )

    with pytest.raises(ScopeError, match="could not resolve"):
        enforcer.resolve_authorized_ips(
            "app.example.test",
            resolver=lambda _name: (_ for _ in ()).throw(OSError("DNS unavailable")),
        )


def test_resolve_authorized_ips_checks_literal_addresses_without_dns():
    enforcer = ScopeEnforcer(allowed_cidrs=["10.0.0.0/8"])

    assert enforcer.resolve_authorized_ips("10.1.2.3") == ["10.1.2.3"]
    with pytest.raises(ScopeError, match="outside the authorized scope"):
        enforcer.resolve_authorized_ips("192.0.2.3")
