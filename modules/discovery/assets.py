"""HELIOS-NET :: modules/discovery/assets.py

Scope-bound asset discovery.

This is the difference between scanning a host you were told about and mapping
the surface an engagement actually covers. Starting from seed names it:

  1. resolves each name and **drops every address the scope does not authorize**
     before a socket is opened (a name is not permission to reach its IPs);
  2. optionally expands through Certificate Transparency, one hop at a time;
  3. fetches HTTP metadata (status, server, title, technologies) and TLS
     metadata (protocol, cipher, certificate dates);
  4. compares each virtual host against the address-default response, so a
     name served from a shared IP is recorded as a vhost rather than a guess.

Every loop is bounded by `max_hosts` and `max_requests`, and every request is
optional-paced by the caller. Failure to resolve, to connect, or to parse is
recorded as evidence, never raised into the campaign.

TLS notes: the probe collects metadata with certificate verification disabled
(it must be able to describe a broken or self-signed endpoint), so `verified` is
reported as False and must not be read as a trust decision.
"""

from __future__ import annotations

import contextlib
import http.client
import os
import re
import socket
import ssl
import tempfile
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from core.input_guard import sanitize_banner
from core.scope import ScopeEnforcer
from modules.discovery.ct import fetch_ct_names

WEB_PORTS = (80, 443, 8080, 8443)
DEFAULT_TIMEOUT = 2.0
MAX_BODY_BYTES = 16 * 1024
MAX_TITLE_CHARS = 120
MAX_REDIRECTS = 2
MAX_DOCUMENT_CHARS = 400
USER_AGENT = "HELIOS-NET/1.0 (+authorized reconnaissance)"

_SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
)

_TITLE_RE = re.compile(r"(?is)<title[^>]*>(.*?)</title>")
_TECH_MARKERS = {
    "nginx": "nginx",
    "apache": "apache",
    "microsoft-iis": "iis",
    "cloudflare": "cloudflare",
    "wordpress": "wp-content",
    "drupal": "drupal",
    "joomla": "joomla",
    "php": "php",
    "asp.net": "asp.net",
    "react": "react",
    "angular": "angular",
    "vue": "vue.js",
}

Resolver = Callable[[str], list[str]]
Probe = Callable[..., dict[str, Any]]


@dataclass(frozen=True)
class _Target:
    host: str
    ip: str
    port: int
    scheme: str


def resolve_host(name: str, timeout: float = 3.0) -> list[str]:
    """Returns unique A records for `name`, or an empty list on failure."""
    try:
        infos = socket.getaddrinfo(
            name, None, family=socket.AF_INET, type=socket.SOCK_STREAM
        )
    except OSError:
        return []
    seen: set[str] = set()
    addresses: list[str] = []
    for info in infos:
        address = str(info[4][0])
        if address not in seen:
            seen.add(address)
            addresses.append(address)
    return addresses


def _title(body: str) -> str:
    match = _TITLE_RE.search(body)
    if not match:
        return ""
    text = re.sub(r"\s+", " ", match.group(1)).strip()
    return sanitize_banner(text)[:MAX_TITLE_CHARS]


def _technologies(server: str, powered: str, body: str) -> list[str]:
    haystack = f"{server} {powered} {body[:4096]}".lower()
    found = [name for name, marker in _TECH_MARKERS.items() if marker in haystack]
    return sorted(set(found))


def _flatten_name(entries: Any) -> str:
    if not isinstance(entries, (list, tuple)):
        return ""
    for entry in entries:
        if isinstance(entry, (list, tuple)) and len(entry) == 2:
            label, value = entry
            if label == "commonName":
                return value if isinstance(value, str) else str(value)
    for entry in entries:
        flat = _flatten_name(entry)
        if flat:
            return flat
    return ""


def decode_certificate(der: bytes) -> dict[str, str]:
    """Best-effort certificate fields from a DER blob.

    Python exposes no public DER-to-dict API. `ssl._ssl._test_decode_cert` is
    the decoder the stdlib itself uses, so it is called through `getattr` and
    any absence or failure degrades to an empty mapping.
    """
    decoder = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
    if decoder is None or not der:
        return {}
    path = ""
    try:
        with tempfile.NamedTemporaryFile(
            "w", suffix=".pem", delete=False, encoding="ascii"
        ) as fh:
            fh.write(ssl.DER_cert_to_PEM_cert(der))
            path = fh.name
        info: Any = decoder(path)
        if not isinstance(info, dict):
            return {}
        return {
            "subject": _flatten_name(info.get("subject")),
            "issuer": _flatten_name(info.get("issuer")),
            "not_before": str(info.get("notBefore", "")),
            "not_after": str(info.get("notAfter", "")),
        }
    except Exception:
        return {}
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


class _SNIConnection(http.client.HTTPSConnection):
    """HTTPS connection to an IP that presents the name's SNI."""

    def __init__(self, ip: str, port: int, server_name: str, timeout: float):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        super().__init__(ip, port, timeout=timeout, context=context)
        self._server_name = server_name
        self._tls_context = context

    def connect(self) -> None:
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._tls_context.wrap_socket(
            sock, server_hostname=self._server_name
        )


def _tls_info(conn: http.client.HTTPSConnection) -> dict[str, Any]:
    sock = conn.sock
    if sock is None:
        return {}
    cipher = sock.cipher()
    info: dict[str, Any] = {
        "version": sock.version() or "",
        "cipher": cipher[0] if cipher else "",
        "verified": False,
        "note": "certificate chain was not validated; metadata only",
    }
    try:
        der = sock.getpeercert(binary_form=True)
    except (ValueError, OSError):
        der = None
    info.update(decode_certificate(der or b""))
    not_after = info.get("not_after", "")
    if not_after:
        try:
            expires = ssl.cert_time_to_seconds(not_after)
            info["days_left"] = int((expires - time.time()) // 86400)
        except ValueError:
            pass
    return info


def probe_http(
    host: str,
    ip: str,
    port: int,
    *,
    scheme: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    host_header: str | None = None,
    path: str = "/",
    capture_body: bool = False,
) -> dict[str, Any]:
    """Fetches HTTP metadata for one `host`/`ip`/`port` triple.

    Metadata is deliberately factual: response status, server banner, title,
    technologies, TLS facts, redirect target, cookies presence, the security
    headers the endpoint actually returned, and (optionally) a bounded body
    excerpt for well-known documents.
    """
    scheme = scheme or ("https" if port in (443, 8443) else "http")
    result: dict[str, Any] = {
        "host": host,
        "ip": ip,
        "port": port,
        "scheme": scheme,
        "path": path,
        "open": False,
        "source": "asset-discovery",
    }
    header = host_header or host
    https_conn: _SNIConnection | None = None
    if scheme == "https":
        https_conn = _SNIConnection(ip, port, host, timeout)
        conn: http.client.HTTPConnection = https_conn
    else:
        conn = http.client.HTTPConnection(ip, port, timeout=timeout)

    try:
        conn.request(
            "GET",
            path,
            headers={
                "Host": header,
                "User-Agent": USER_AGENT,
                "Accept": "*/*",
                "Connection": "close",
            },
        )
        response = conn.getresponse()
        body = response.read(MAX_BODY_BYTES).decode("utf-8", errors="replace")
        server = sanitize_banner(response.getheader("Server", "") or "")
        powered = sanitize_banner(response.getheader("X-Powered-By", "") or "")
        security_headers = {
            name: sanitize_banner(response.getheader(name, "") or "")[:200]
            for name in _SECURITY_HEADERS
            if response.getheader(name)
        }
        cookies = response.getheaders()
        cookie_names = sorted(
            {
                value.split("=", 1)[0].strip()
                for key, value in cookies
                if key.lower() == "set-cookie"
            }
        )
        result.update(
            {
                "open": True,
                "state": "open",
                "status": int(response.status),
                "server": server,
                "title": _title(body),
                "technologies": _technologies(server, powered, body),
                "content_type": sanitize_banner(
                    response.getheader("Content-Type", "") or ""
                ),
                "content_length": sanitize_banner(
                    response.getheader("Content-Length", "") or ""
                ),
                "security_headers": security_headers,
                "security_headers_count": len(security_headers),
                "cookies": cookie_names,
            }
        )
        location = response.getheader("Location", "") or ""
        if location:
            result["location"] = sanitize_banner(location)[:300]
        if capture_body:
            result["body_excerpt"] = sanitize_banner(body)[:MAX_DOCUMENT_CHARS]
        if https_conn is not None:
            result["tls"] = _tls_info(https_conn)
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        with contextlib.suppress(OSError):
            conn.close()
    return result


def _fingerprint(meta: dict[str, Any]) -> tuple[Any, ...]:
    return (meta.get("status"), meta.get("server"), meta.get("title"))


def _is_vhost(candidate: dict[str, Any], baseline: dict[str, Any]) -> bool:
    if not candidate.get("open"):
        return False
    if not baseline.get("open"):
        return True
    return _fingerprint(candidate) != _fingerprint(baseline)


def _redirect_target(
    location: str, host: str, port: int, scheme: str
) -> tuple[str, int, str, str] | None:
    """Resolves a Location header into (host, port, scheme, path).

    Relative locations stay on the current authority; absolute ones are parsed
    only for their authority and path. The caller still has to scope-check the
    resulting host and every address it resolves to.
    """
    try:
        parts = urlsplit(location)
    except ValueError:
        return None
    next_scheme = parts.scheme or scheme
    next_host = (parts.hostname or host).strip().lower().rstrip(".")
    next_port = parts.port or (443 if next_scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    return next_host, next_port, next_scheme, path


def _contacts(excerpt: str) -> list[str]:
    contacts: list[str] = []
    for line in excerpt.splitlines():
        key, _, value = line.partition(":")
        if key.strip().lower() in {"contact", "security-contact"} and value.strip():
            contact = sanitize_banner(value.strip())[:200]
            if contact and contact not in contacts:
                contacts.append(contact)
    return contacts[:5]


def _follow_redirects(
    scope: ScopeEnforcer,
    candidate: dict[str, Any],
    *,
    name: str,
    ip: str,
    port: int,
    scheme: str,
    probe: Probe,
    resolve: Resolver,
    timeout: float,
    pace: Callable[[], None] | None,
    budget: Callable[[], bool],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    """Follows at most MAX_REDIRECTS in-scope hops from an open response.

    Returns (chain, blocked, requests_used). A redirect that leaves the scope is
    recorded and never followed; the chain survives so the operator can see the
    boundary decision instead of a silently truncated walk.
    """
    chain: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    used = 0
    current = candidate
    current_host, current_ip, current_port = name, ip, port
    current_scheme = scheme

    for _ in range(MAX_REDIRECTS):
        status = int(current.get("status") or 0)
        location = str(current.get("location") or "")
        if status not in {301, 302, 303, 307, 308} or not location or not budget():
            break
        target = _redirect_target(location, current_host, current_port, current_scheme)
        if target is None:
            blocked.append(
                {"host": name, "reason": "redirect-unparseable", "location": location}
            )
            break
        next_host, next_port, next_scheme, path = target
        addresses = resolve(next_host) if next_host != current_host else [current_ip]
        allowed = [address for address in addresses if scope.is_target_allowed(address)]
        if not addresses or not allowed or not scope.is_target_allowed(next_host):
            blocked.append(
                {
                    "host": name,
                    "reason": "redirect-outside-scope",
                    "location": location,
                    "target_host": next_host,
                }
            )
            break
        if pace is not None:
            pace()
        current = probe(
            next_host,
            allowed[0],
            next_port,
            scheme=next_scheme,
            path=path,
            timeout=timeout,
        )
        used += 1
        chain.append(
            {
                "from": f"{current_scheme}://{current_host}:{current_port}",
                "to": f"{next_scheme}://{next_host}:{next_port}{path}",
                "status": current.get("status"),
            }
        )
        current_host, current_ip = next_host, allowed[0]
        current_port, current_scheme = next_port, next_scheme
        if not current.get("open"):
            break
    return chain, blocked, used


def _probe_documents(
    probe: Probe,
    *,
    host: str,
    ip: str,
    port: int,
    scheme: str,
    timeout: float,
    pace: Callable[[], None] | None,
    budget: Callable[[], bool],
) -> tuple[dict[str, Any], int]:
    """Fetches the two well-known documents that carry ownership signals."""
    documents: dict[str, Any] = {}
    used = 0
    for path in ("/.well-known/security.txt", "/robots.txt"):
        if not budget():
            break
        if pace is not None:
            pace()
        document = probe(
            host,
            ip,
            port,
            scheme=scheme,
            path=path,
            timeout=timeout,
            capture_body=True,
        )
        used += 1
        if not document.get("open"):
            continue
        entry: dict[str, Any] = {
            "status": document.get("status"),
            "content_type": document.get("content_type", ""),
        }
        excerpt = str(document.get("body_excerpt") or "")
        if path.endswith("security.txt"):
            entry["contacts"] = _contacts(excerpt)
        documents[path] = entry
    return documents, used


def discover_assets(
    scope: ScopeEnforcer,
    seeds: list[str],
    *,
    ct: bool = False,
    fetcher: Callable[[str], bytes] | None = None,
    depth: int = 1,
    max_hosts: int = 50,
    max_requests: int = 200,
    web_ports: list[int] | tuple[int, ...] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    resolve: Resolver | None = None,
    probe: Probe | None = None,
    pace: Callable[[], None] | None = None,
    deep: bool = False,
) -> dict[str, Any]:
    """Walks the authorized surface starting from `seeds`.

    Returns a summary plus a `findings` list the caller can merge into its
    campaign context. Out-of-scope names and out-of-scope resolved addresses are
    reported under `blocked`; they are never probed. Redirects are followed only
    while every hop stays in scope, and `deep` adds the well-known documents
    that carry ownership signals.
    """
    resolve = resolve or resolve_host
    probe = probe or probe_http
    depth = max(0, int(depth))
    max_hosts = max(1, int(max_hosts))
    max_requests = max(0, int(max_requests))
    if web_ports is None:
        web_ports = [p for p in WEB_PORTS if not scope.ports or p in scope.ports]
    web_ports = [int(p) for p in web_ports]

    queue: deque[tuple[str, int]] = deque()
    seen: set[str] = set()
    for seed in seeds:
        name = (seed or "").strip().lower().rstrip(".")
        if name and name not in seen:
            queue.append((name, 0))

    hosts: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    requests = 0
    plan = list(dict.fromkeys(web_ports))

    def _budget() -> bool:
        return requests < max_requests

    while queue and len(seen) < max_hosts and requests < max_requests:
        name, level = queue.popleft()
        if name in seen:
            continue
        seen.add(name)

        if not scope.is_target_allowed(name):
            blocked.append({"host": name, "reason": "name-outside-scope"})
            continue

        addresses = resolve(name)
        allowed = [ip for ip in addresses if scope.is_target_allowed(ip)]
        if addresses and not allowed:
            blocked.append(
                {
                    "host": name,
                    "reason": "resolved-outside-scope",
                    "addresses": list(addresses),
                }
            )
            continue
        if not allowed:
            blocked.append({"host": name, "reason": "unresolved"})
        else:
            hosts.append({"host": name, "addresses": allowed, "depth": level})

            for ip in allowed:
                for port in plan:
                    if requests >= max_requests:
                        break
                    if pace is not None:
                        pace()
                    candidate = probe(name, ip, port, timeout=timeout)
                    requests += 1
                    if not candidate.get("open"):
                        continue

                    if requests < max_requests:
                        if pace is not None:
                            pace()
                        baseline = probe(
                            name, ip, port, timeout=timeout, host_header=ip
                        )
                        requests += 1
                        if _is_vhost(candidate, baseline):
                            candidate["vhost"] = True

                    chain, redirect_blocked, used = _follow_redirects(
                        scope,
                        candidate,
                        name=name,
                        ip=ip,
                        port=port,
                        scheme=str(candidate["scheme"]),
                        probe=probe,
                        resolve=resolve,
                        timeout=timeout,
                        pace=pace,
                        budget=_budget,
                    )
                    requests += used
                    blocked.extend(redirect_blocked)
                    if chain:
                        candidate["redirects"] = chain

                    if deep and requests < max_requests:
                        documents, used = _probe_documents(
                            probe,
                            host=name,
                            ip=ip,
                            port=port,
                            scheme=str(candidate["scheme"]),
                            timeout=timeout,
                            pace=pace,
                            budget=_budget,
                        )
                        requests += used
                        if documents:
                            candidate["documents"] = documents

                    finding = {
                        "module": "asset",
                        "host": name,
                        "ip": ip,
                        "port": port,
                        "open": True,
                        "state": "open",
                        "service": candidate["scheme"],
                        "engine": "stdlib-http",
                        "source": "asset-discovery",
                    }
                    for key in (
                        "status",
                        "server",
                        "title",
                        "technologies",
                        "tls",
                        "vhost",
                        "content_type",
                        "content_length",
                        "security_headers",
                        "security_headers_count",
                        "cookies",
                        "redirects",
                        "documents",
                    ):
                        if candidate.get(key) not in (None, "", []):
                            finding[key] = candidate[key]
                    findings.append(finding)

        if ct and level < depth and len(seen) + len(queue) < max_hosts:
            for child in fetch_ct_names(name, fetcher=fetcher):
                if child in seen:
                    continue
                if not scope.is_target_allowed(child):
                    blocked.append({"host": child, "reason": "name-outside-scope"})
                    continue
                queue.append((child, level + 1))

    return {
        "module": "asset",
        "source": "asset-discovery",
        "hosts": [entry["host"] for entry in hosts],
        "assets": len(findings),
        "requests": requests,
        "blocked": blocked,
        "findings": findings,
    }
