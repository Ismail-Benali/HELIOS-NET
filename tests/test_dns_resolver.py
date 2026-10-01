"""Tests for the DNS wire-format code and the resolver's failover and cache.

The query builder and the response parser are pure byte manipulation, so they
are verified against packets constructed independently here rather than against
a live nameserver. Responses in this file are assembled by hand from the DNS
layout, which means a shared misreading of that layout would have to be
reproduced in two places to hide a bug.

The resolver's network path is exercised by replacing the thread offload, so
failover order and cache behaviour are checked without touching the network.
"""

from __future__ import annotations

import asyncio
import struct

import pytest

from modules.discovery.dns_resolver import EliteDNSResolver


# --------------------------------------------------------------------------- #
# helpers that build DNS packets the long way round
# --------------------------------------------------------------------------- #

def encode_name(domain: str) -> bytes:
    out = bytearray()
    for label in domain.split("."):
        if label:
            out.append(len(label))
            out += label.encode("ascii")
    out.append(0)
    return bytes(out)


def build_response(
    domain: str,
    addresses: list[str],
    rcode: int = 0,
    ancount: int | None = None,
    qdcount: int = 1,
    truncation: bytes = b"",
) -> bytes:
    """A minimal but well-formed A-record response."""
    flags = 0x8180 | (rcode & 0x000F)
    count = len(addresses) if ancount is None else ancount
    header = struct.pack("!HHHHHH", 0x1234, flags, qdcount, count, 0, 0)
    body = encode_name(domain) + struct.pack("!HH", 1, 1) if qdcount else b""

    for address in addresses:
        body += b"\xc0\x0c"                                  # pointer to the question name
        body += struct.pack("!HHIH", 1, 1, 300, 4)          # A, IN, TTL 300, rdlength 4
        body += bytes(int(octet) for octet in address.split("."))
    return header + body + truncation


# --------------------------------------------------------------------------- #
# query construction
# --------------------------------------------------------------------------- #

def test_query_header_declares_one_question_and_one_additional():
    resolver = EliteDNSResolver()
    packet = resolver._build_edns_query("example.test")

    tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])
    assert 0 <= tx_id <= 0xFFFF
    assert flags & 0x0100, "the recursion-desired bit must be set"
    assert qdcount == 1
    assert arcount == 1, "one additional record: the EDNS0 OPT pseudo-record"
    assert nscount == 0 and ancount == 0


def test_query_name_is_length_prefixed_and_terminated():
    packet = EliteDNSResolver()._build_edns_query("www.example.test")

    assert packet[12] == 3, "first label length"
    assert packet[13:16] == b"www"
    assert packet[16] == 7, "second label length"
    assert packet[17:24] == b"example"
    assert packet[24] == 4
    assert packet[25:29] == b"test"
    assert packet[29] == 0, "the name must be zero terminated"

    offset = 12 + len(encode_name("www.example.test"))
    qtype, qclass = struct.unpack("!HH", packet[offset:offset + 4])
    assert qtype == 1 and qclass == 1, "default is an A query in the IN class"


def test_query_type_is_configurable():
    resolver = EliteDNSResolver()
    packet = resolver._build_edns_query("example.test", qtype=28)
    offset = 12 + len(encode_name("example.test"))
    qtype, qclass = struct.unpack("!HH", packet[offset:offset + 4])
    assert qtype == 28, "AAAA is type 28"
    assert qclass == 1


def test_edns_opt_record_advertises_a_4096_byte_buffer():
    packet = EliteDNSResolver()._build_edns_query("example.test")
    opt = packet[-(1 + 10):]

    assert opt[0] == 0, "the OPT owner name is the root"
    # OPT is NAME(1) TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) = 11 bytes. The TTL
    # field carries extended-rcode, version and flags, so it is read as one
    # 32-bit value rather than three separate ones.
    opt_type, udp_size, ttl, rdlength = struct.unpack("!HHIH", opt[1:11])
    assert opt_type == 41, "OPT pseudo-record type"
    assert udp_size == 4096, "the class field carries the advertised UDP payload size"
    assert rdlength == 0, "no EDNS0 options are attached"
    assert ttl == 0, "extended rcode, version and flags are all zero"


def test_an_empty_label_does_not_produce_a_zero_length_prefix():
    """A trailing or doubled dot must not encode as a length-0 label."""
    packet = EliteDNSResolver()._build_edns_query("a..b")
    assert packet[12] == 1 and packet[13:14] == b"a"
    # the skipped empty label means "b" follows immediately as a 1-byte label
    assert packet[14] == 1 and packet[15:16] == b"b"
    assert packet[16] == 0


# --------------------------------------------------------------------------- #
# response parsing
# --------------------------------------------------------------------------- #

def test_a_valid_a_response_yields_its_addresses():
    resolver = EliteDNSResolver()
    packet = build_response("example.test", ["93.184.216.34", "93.184.216.35"])
    assert resolver._parse_response(packet) == ["93.184.216.34", "93.184.216.35"]


def test_a_truncated_packet_is_rejected_not_crashed():
    resolver = EliteDNSResolver()
    for length in range(0, 12):
        assert resolver._parse_response(b"\x00" * length) == []


def test_a_nonzero_rcode_yields_nothing():
    resolver = EliteDNSResolver()
    # NXDOMAIN is rcode 3; a refusal (5) must behave the same way.
    assert resolver._parse_response(build_response("example.test", ["1.2.3.4"], rcode=3)) == []
    assert resolver._parse_response(build_response("example.test", ["1.2.3.4"], rcode=5)) == []


def test_a_response_with_no_answers_yields_nothing():
    resolver = EliteDNSResolver()
    assert resolver._parse_response(build_response("example.test", [], ancount=0)) == []


def test_a_aaaa_only_answer_yields_no_a_records():
    """Only A records are collected, and the record walk must still land on the
    end of the message rather than misreading AAAA rdata as IPv4."""
    resolver = EliteDNSResolver()
    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    body = encode_name("example.test") + struct.pack("!HH", 28, 1)
    body += b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 300, 16)
    body += bytes(16)
    assert resolver._parse_response(header + body) == []


def test_a_compressed_owner_name_is_followed():
    """0xC0-prefixed labels are pointers, not lengths, and must not be treated
    as a 192-byte label."""
    resolver = EliteDNSResolver()
    packet = build_response("example.test", ["10.0.0.7"])
    assert resolver._parse_response(packet) == ["10.0.0.7"]


def test_truncated_rdata_does_not_produce_a_phantom_address():
    resolver = EliteDNSResolver()
    # Header and question are complete; the answer is cut off mid-record.
    packet = build_response("example.test", ["1.2.3.4"])[:20]
    assert resolver._parse_response(packet) == []


def test_parsing_is_deterministic_for_the_same_packet():
    resolver = EliteDNSResolver()
    packet = build_response("example.test", ["8.8.8.8", "8.8.4.4"])
    assert resolver._parse_response(packet) == resolver._parse_response(packet)


# --------------------------------------------------------------------------- #
# failover and caching
# --------------------------------------------------------------------------- #

def _with_fake_transport(monkeypatch, answers: dict[str, list[str]], calls: list[str]):
    """Replaces the thread offload so _query_sync never touches a socket.

    Keyed by nameserver, so a nameserver absent from `answers` behaves like an
    unreachable one and returns nothing.
    """
    async def fake_to_thread(func, *args):
        nameserver = args[0]
        calls.append(nameserver)
        return answers.get(nameserver, [])

    monkeypatch.setattr(asyncio, "to_thread", fake_to_thread)


def test_the_first_nameserver_is_tried_first(monkeypatch):
    resolver = EliteDNSResolver(nameservers=["1.1.1.1", "8.8.8.8", "9.9.9.9"])
    calls: list[str] = []
    _with_fake_transport(monkeypatch, {"1.1.1.1": ["1.2.3.4"]}, calls)

    assert asyncio.run(resolver.resolve("example.test")) == ["1.2.3.4"]
    assert calls == ["1.1.1.1"], "no failover is needed once an answer arrives"


def test_failover_moves_to_the_next_nameserver(monkeypatch):
    resolver = EliteDNSResolver(nameservers=["1.1.1.1", "8.8.8.8", "9.9.9.9"])
    calls: list[str] = []
    _with_fake_transport(monkeypatch, {"8.8.8.8": ["5.6.7.8"]}, calls)

    assert asyncio.run(resolver.resolve("example.test")) == ["5.6.7.8"]
    assert calls == ["1.1.1.1", "8.8.8.8"], "must try in order and stop at the first answer"


def test_all_nameservers_failing_returns_nothing(monkeypatch):
    resolver = EliteDNSResolver(nameservers=["1.1.1.1", "8.8.8.8"])
    calls: list[str] = []
    _with_fake_transport(monkeypatch, {}, calls)

    assert asyncio.run(resolver.resolve("example.test")) == []
    assert calls == ["1.1.1.1", "8.8.8.8"]


def test_a_repeat_lookup_is_served_from_the_cache(monkeypatch):
    resolver = EliteDNSResolver(nameservers=["1.1.1.1"])
    calls: list[str] = []
    _with_fake_transport(monkeypatch, {"1.1.1.1": ["1.2.3.4"]}, calls)

    async def scenario() -> list[list[str]]:
        first = await resolver.resolve("example.test")
        second = await resolver.resolve("example.test")
        return [first, second]

    first, second = asyncio.run(scenario())
    assert first == second == ["1.2.3.4"]
    assert calls == ["1.1.1.1"], "the second lookup must not hit the transport again"


def test_the_cache_is_keyed_by_query_type(monkeypatch):
    resolver = EliteDNSResolver(nameservers=["1.1.1.1"])
    calls: list[str] = []
    _with_fake_transport(monkeypatch, {"1.1.1.1": ["1.2.3.4"]}, calls)

    async def scenario() -> None:
        await resolver.resolve("example.test", qtype=1)
        await resolver.resolve("example.test", qtype=28)

    asyncio.run(scenario())
    assert calls == ["1.1.1.1", "1.1.1.1"], "A and AAAA are different questions"


def test_an_expired_cache_entry_is_re_resolved(monkeypatch, monkeypatched_time=None):
    resolver = EliteDNSResolver(nameservers=["1.1.1.1"])
    calls: list[str] = []
    _with_fake_transport(monkeypatch, {"1.1.1.1": ["1.2.3.4"]}, calls)

    clock = {"now": 1000.0}
    monkeypatch.setattr("modules.discovery.dns_resolver.time.time", lambda: clock["now"])

    async def scenario() -> tuple[list[str], list[str]]:
        first = await resolver.resolve("example.test")
        clock["now"] += 121          # past the 120 second window
        second = await resolver.resolve("example.test")
        return first, second

    first, second = asyncio.run(scenario())
    assert first == second == ["1.2.3.4"]
    assert calls == ["1.1.1.1", "1.1.1.1"], "an expired entry must be refetched"


def test_default_nameservers_are_public_resolvers():
    assert EliteDNSResolver().nameservers == ["8.8.8.8", "1.1.1.1", "8.8.4.4"]
