"""Import Nmap XML without touching the network.

The point of ingesting someone else's scan is interoperability: it lets a team
keep using Nmap for collection and HELIOS-NET for the graph, risk and reporting
layers. Parsing is strict about the document root and tolerant about optional
attributes, because Nmap's own output varies with the options used.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path


class NmapError(ValueError):
    """Raised when a file is not an Nmap XML document."""


@dataclass(frozen=True)
class NmapPort:
    port: int
    protocol: str
    state: str
    service: str
    product: str
    version: str
    cpes: tuple[str, ...]

    def to_finding(self, host: str, hostname: str, reference: str) -> dict[str, object]:
        finding: dict[str, object] = {
            "host": host,
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "source": "nmap",
            "evidence": {"source": "nmap", "reference": reference},
        }
        if hostname:
            finding["hostname"] = hostname
        if self.cpes:
            finding["cpe"] = list(self.cpes)
        return finding


@dataclass(frozen=True)
class NmapHost:
    address: str
    hostname: str
    status: str
    ports: tuple[NmapPort, ...]


def _port(element: ET.Element) -> NmapPort | None:
    raw_port = element.get("portid", "")
    try:
        port = int(raw_port)
    except ValueError:
        return None
    state = element.find("state")
    service = element.find("service")
    return NmapPort(
        port=port,
        protocol=element.get("protocol", ""),
        state=state.get("state", "") if state is not None else "",
        service=service.get("name", "") if service is not None else "",
        product=service.get("product", "") if service is not None else "",
        version=service.get("version", "") if service is not None else "",
        cpes=tuple(
            cpe.text.strip()
            for cpe in element.findall("service/cpe")
            if cpe.text and cpe.text.strip()
        ),
    )


def _host(element: ET.Element) -> NmapHost | None:
    addresses = element.findall("address")
    chosen = next(
        (
            item.get("addr", "")
            for item in addresses
            if item.get("addrtype") in {"ipv4", "ipv6"}
        ),
        addresses[0].get("addr", "") if addresses else "",
    )
    if not chosen:
        return None
    status = element.find("status")
    hostname_element = element.find("hostnames/hostname")
    ports = tuple(
        port for port in (_port(item) for item in element.findall("ports/port")) if port
    )
    return NmapHost(
        address=chosen,
        hostname=hostname_element.get("name", "")
        if hostname_element is not None
        else "",
        status=status.get("state", "") if status is not None else "",
        ports=ports,
    )


def parse_nmap_xml(text: str) -> tuple[NmapHost, ...]:
    """Parses an Nmap XML document into hosts and ports."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise NmapError(f"not valid XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise NmapError(f"unexpected root element {root.tag!r}; expected 'nmaprun'")
    hosts = tuple(
        host for host in (_host(item) for item in root.findall("host")) if host
    )
    if not hosts:
        raise NmapError("the document contains no host records")
    return hosts


def read_nmap_xml(path: str | Path) -> tuple[NmapHost, ...]:
    """Reads and parses an Nmap XML file."""
    source = Path(path)
    try:
        text = source.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise NmapError(f"cannot read {source}: {exc}") from exc
    return parse_nmap_xml(text)


def findings(
    hosts: tuple[NmapHost, ...] | list[NmapHost],
    *,
    reference: str = "",
    states: frozenset[str] | set[str] | None = frozenset({"open"}),
) -> list[dict[str, object]]:
    """Flattens hosts to port findings, optionally filtered by port state.

    Open ports are the default because they are what an asset inventory cares
    about; pass ``states=None`` to keep every recorded state.
    """
    allowed = states
    rows: list[dict[str, object]] = []
    for host in hosts:
        for port in host.ports:
            if allowed is not None and port.state not in allowed:
                continue
            rows.append(port.to_finding(host.address, host.hostname, reference))
    return rows
