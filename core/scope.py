"""
HELIOS-NET :: core/scope.py
Enterprise Target Scope Enforcement & CIDR Allowlisting Engine.
Ensures authorized boundaries and prevents out-of-scope scanning.
"""

from __future__ import annotations

import ipaddress
from typing import List, Union


class ScopeEnforcer:
    """Validates targets against strict authorized CIDR scopes and allowlists."""

    def __init__(self, allowed_cidrs: List[str] | None = None, allowed_domains: List[str] | None = None):
        self.networks = [ipaddress.ip_network(cidr, strict=False) for cidr in (allowed_cidrs or ["0.0.0.0/0", "::/0"])]
        self.domains = [d.lower() for d in (allowed_domains or [])]

    def is_target_allowed(self, target: str) -> bool:
        """Checks if an IP address or domain is within authorized scope."""
        target = target.strip().lower()
        if not target:
            return False

        # Check if target is IP
        try:
            ip_obj = ipaddress.ip_address(target)
            return any(ip_obj in net for net in self.networks)
        except ValueError:
            pass

        # Check domain allowlist if configured
        if not self.domains or "*" in self.domains:
            return True

        return any(target == d or target.endswith("." + d) for d in self.domains)
