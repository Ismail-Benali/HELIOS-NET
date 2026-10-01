"""
HELIOS-NET :: tests/test_scope.py
Unit tests for enterprise scope enforcement and CIDR validation.
"""

from __future__ import annotations

import pytest
from core.scope import ScopeEnforcer


def test_scope_enforcement_ip():
    enforcer = ScopeEnforcer(allowed_cidrs=["192.168.1.0/24", "10.0.0.0/8"])
    
    # Allowed
    assert enforcer.is_target_allowed("192.168.1.50") is True
    assert enforcer.is_target_allowed("10.5.5.5") is True

    # Out of scope
    assert enforcer.is_target_allowed("8.8.8.8") is False
    assert enforcer.is_target_allowed("192.168.2.1") is False


def test_scope_enforcement_domain():
    enforcer = ScopeEnforcer(allowed_cidrs=["0.0.0.0/0"], allowed_domains=["example.com", "test.org"])
    
    assert enforcer.is_target_allowed("example.com") is True
    assert enforcer.is_target_allowed("sub.example.com") is True
    assert enforcer.is_target_allowed("malicious.com") is False
