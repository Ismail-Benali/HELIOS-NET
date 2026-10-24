"""HELIOS-NET :: core/scope.py

Enterprise target scope enforcement.

The enforcer is fail-closed: an instance built without an allowlist denies every
target instead of silently granting the internet. Scanning an address that the
engagement does not cover is a legal problem, not a configuration preference, so
the default must be "deny" and the reason must travel with the refusal.

The scope file is dependency-free on purpose: the project keeps its control
plane on the standard library. `config/scope.yaml` therefore uses a deliberately
small YAML subset (one top-level `scope` mapping with `domains`, `cidrs` and
`ports` lists), parsed strictly here. Anything outside that shape is rejected
rather than guessed at, because a parser that half-understands its input is how
a typo becomes an unauthorized scan.
"""

from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_SCOPE_FILE = Path(__file__).resolve().parents[1] / "config" / "scope.yaml"
SCOPE_ENV_VAR = "HELIOS_SCOPE_FILE"

_SCOPE_KEYS = frozenset({"domains", "cidrs", "ports", "rate_limit"})
_NESTED_SCOPE_KEYS = frozenset({"rate_limit"})


class ScopeError(ValueError):
    """A target is out of scope, or the scope file cannot be trusted."""


@dataclass(frozen=True)
class ScopeConfig:
    """The authorized surface as written in the scope file."""

    domains: tuple[str, ...] = ()
    cidrs: tuple[str, ...] = ()
    ports: tuple[int, ...] = ()

    def is_empty(self) -> bool:
        return not (self.domains or self.cidrs)


class ScopeEnforcer:
    """Validates targets against strict authorized CIDR scopes and allowlists."""

    def __init__(
        self,
        allowed_cidrs: list[str] | None = None,
        allowed_domains: list[str] | None = None,
        ports: list[int] | None = None,
        source: str = "explicit allowlist",
    ):
        self.networks = [
            ipaddress.ip_network(cidr, strict=False) for cidr in (allowed_cidrs or [])
        ]
        self.domains = [d.strip().lower().rstrip(".") for d in (allowed_domains or [])]
        self.ports = tuple(int(p) for p in (ports or []))
        self.source = source

    def is_target_allowed(self, target: str) -> bool:
        """True only when `target` is inside one of the configured allowlists."""
        name = (target or "").strip().lower().rstrip(".")
        if not name:
            return False

        try:
            address = ipaddress.ip_address(name)
        except ValueError:
            if not self.domains:
                return False
            return any(name == d or name.endswith("." + d) for d in self.domains)

        return any(address in network for network in self.networks)

    def check(self, target: str) -> None:
        """Raises `ScopeError` unless `target` is authorized."""
        if not self.is_target_allowed(target):
            raise ScopeError(
                f"target {target!r} is outside the authorized scope "
                f"(source: {self.source}; {self.describe()})"
            )

    def check_ports(self, ports: list[int] | tuple[int, ...]) -> None:
        """Raises `ScopeError` if any requested port is outside the allowlist.

        An empty port allowlist means "any port", which is the common case; the
        target allowlist is still the gate.
        """
        if not self.ports:
            return
        offending = sorted({int(p) for p in ports} - set(self.ports))
        if offending:
            raise ScopeError(
                f"ports {offending} are outside the authorized scope "
                f"(source: {self.source}; allowed: {list(self.ports)})"
            )

    def describe(self) -> str:
        parts: list[str] = []
        if self.networks:
            parts.append("cidrs=" + ",".join(str(n) for n in self.networks))
        if self.domains:
            parts.append("domains=" + ",".join(self.domains))
        if self.ports:
            parts.append("ports=" + ",".join(str(p) for p in self.ports))
        return "; ".join(parts) or "empty allowlist (deny all)"

    @classmethod
    def from_config(cls, path: str | Path | None = None) -> ScopeEnforcer:
        """Loads a scope file, raising `ScopeError` if it cannot be trusted."""
        resolved = resolve_scope_path(path)
        config = load_scope_config(resolved)
        return cls(
            allowed_cidrs=list(config.cidrs),
            allowed_domains=list(config.domains),
            ports=list(config.ports),
            source=str(resolved),
        )


def resolve_scope_path(path: str | Path | None = None) -> Path:
    if path is not None:
        return Path(path)
    from_env = os.environ.get(SCOPE_ENV_VAR)
    if from_env:
        return Path(from_env)
    return DEFAULT_SCOPE_FILE


def load_scope_config(path: str | Path | None = None) -> ScopeConfig:
    """Reads a JSON or documented-subset YAML scope file."""
    resolved = resolve_scope_path(path)
    try:
        text = resolved.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise ScopeError(f"scope file {resolved} cannot be read: {exc}") from exc

    if resolved.suffix.lower() == ".json":
        try:
            document = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ScopeError(f"scope file {resolved} is not valid JSON: {exc}") from exc
    else:
        document = _parse_scope_yaml(text, resolved)

    return _validate_document(document, resolved)


def _validate_document(document: Any, path: Path) -> ScopeConfig:
    if not isinstance(document, dict) or set(document) != {"scope"}:
        raise ScopeError(f"scope file {path}: expected a single top-level 'scope' key")
    body = document["scope"]
    if not isinstance(body, dict):
        raise ScopeError(f"scope file {path}: 'scope' must be a mapping")

    unknown = set(body) - _SCOPE_KEYS
    if unknown:
        raise ScopeError(
            f"scope file {path}: unsupported keys {sorted(unknown)}; "
            f"expected {sorted(_SCOPE_KEYS)}"
        )

    domains = _strings(body.get("domains", []), "domains", path)
    cidrs = _strings(body.get("cidrs", []), "cidrs", path)
    ports = _ports(body.get("ports", []), path)

    rate_limit = body.get("rate_limit", {})
    if not isinstance(rate_limit, dict):
        raise ScopeError(f"scope file {path}: rate_limit must be a mapping")
    for key, value in rate_limit.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ScopeError(
                f"scope file {path}: rate_limit.{key} must be a number, got {value!r}"
            )
        if value < 0:
            raise ScopeError(f"scope file {path}: rate_limit.{key} cannot be negative")

    return ScopeConfig(
        domains=tuple(d.lower().rstrip(".") for d in domains),
        cidrs=tuple(cidrs),
        ports=tuple(ports),
    )


def _strings(value: Any, key: str, path: Path) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ScopeError(f"scope file {path}: {key} must be a list of strings")
    cleaned = [v.strip() for v in value]
    if any(not v for v in cleaned):
        raise ScopeError(f"scope file {path}: {key} contains an empty entry")
    if any(v == "*" for v in cleaned):
        raise ScopeError(
            f"scope file {path}: '*' in {key} would authorize every target; "
            "write the engagement's actual range instead"
        )
    return cleaned


def _ports(value: Any, path: Path) -> list[int]:
    if not isinstance(value, list):
        raise ScopeError(f"scope file {path}: ports must be a list of integers")
    ports: list[int] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int):
            raise ScopeError(f"scope file {path}: port {item!r} is not an integer")
        if not 1 <= item <= 65535:
            raise ScopeError(f"scope file {path}: port {item} is out of range")
        ports.append(item)
    return ports


def _parse_scope_yaml(text: str, path: Path) -> dict[str, Any]:
    """Parses the small YAML subset the project ships and documents.

    Accepted shape, and nothing else:

        scope:
          domains:
            - "example.test"
          cidrs:
            - "127.0.0.0/24"
          ports:
            - 80

    Indentation is fixed (two spaces for keys, four for items), quoting is
    optional, and comments start at `#` on their own line or after a value.
    """
    body: dict[str, Any] = {}
    seen_scope = False
    current: str | None = None

    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            if stripped != "scope:":
                raise ScopeError(
                    f"scope file {path}:{lineno}: expected 'scope:' at column 0"
                )
            if seen_scope:
                raise ScopeError(f"scope file {path}:{lineno}: duplicate 'scope:'")
            seen_scope = True
            continue

        if not seen_scope:
            raise ScopeError(
                f"scope file {path}:{lineno}: entry before the 'scope:' mapping"
            )

        if stripped.endswith(":"):
            if indent != 2:
                raise ScopeError(
                    f"scope file {path}:{lineno}: keys must be indented two spaces"
                )
            key = stripped[:-1].strip()
            if key not in _SCOPE_KEYS:
                raise ScopeError(f"scope file {path}:{lineno}: unsupported key {key!r}")
            if key in body:
                raise ScopeError(f"scope file {path}:{lineno}: duplicate key {key!r}")
            body[key] = {} if key in _NESTED_SCOPE_KEYS else []
            current = key
            continue

        if current in _NESTED_SCOPE_KEYS:
            if indent != 4:
                raise ScopeError(
                    f"scope file {path}:{lineno}: nested keys must be indented "
                    "four spaces"
                )
            sub, sep, value = stripped.partition(":")
            if not sep or not sub.strip():
                raise ScopeError(
                    f"scope file {path}:{lineno}: expected 'key: value' under {current}"
                )
            sub = sub.strip()
            if sub in body[current]:
                raise ScopeError(
                    f"scope file {path}:{lineno}: duplicate key {sub!r} under {current}"
                )
            body[current][sub] = _scalar(value.strip(), lineno, path)
            continue

        if not stripped.startswith("- "):
            raise ScopeError(f"scope file {path}:{lineno}: expected a '- ' list item")
        if indent != 4:
            raise ScopeError(
                f"scope file {path}:{lineno}: list items must be indented four spaces"
            )
        if current is None:
            raise ScopeError(f"scope file {path}:{lineno}: list item before any key")
        body[current].append(_scalar(stripped[2:].strip(), lineno, path))

    if not seen_scope:
        raise ScopeError(f"scope file {path}: missing 'scope:' mapping")
    return {"scope": body}


def _scalar(token: str, lineno: int, path: Path) -> Any:
    if not token:
        raise ScopeError(f"scope file {path}:{lineno}: empty value")
    if token[0] in {'"', "'"}:
        quote = token[0]
        if len(token) < 2 or not token.endswith(quote):
            raise ScopeError(f"scope file {path}:{lineno}: unterminated quote")
        return token[1:-1]

    if " #" in token:
        token = token.split(" #", 1)[0].rstrip()
    if token.lstrip("-").isdigit():
        return int(token)
    return token
