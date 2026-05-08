"""Phase 2 — decap-node behavioral tests.

Verifies that:
  1. Arming the overlay registers the configured UDP dst port on the IPv6
     udp dispatch table; disarming unregisters it.
  2. A synthetic IPv6+UDP packet matching the registered port, injected via
     VPP's packet-generator, is dispatched to overlay-decap, the outer
     headers are stripped, and the inner packet is forwarded to ip6-input.
"""

import re
import struct
import subprocess
import time

import pytest
from conftest import vppctl, vppctl_unchecked


DST_PORT = 6635
POD_PREFIX = "fd00:cafe::"
PREFIX_LEN = 48
LOCAL_ADDR = "fd00:cafe::1"

# pg0's hw address — pinned so the injected frame's dmac matches and
# ethernet-input does not punt the packet with "l3 mac mismatch".
PG0_MAC = "02:fe:00:00:00:01"
PG0_MAC_BYTES = bytes.fromhex(PG0_MAC.replace(":", ""))


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _arm(iface_name: str, dst_port: int = DST_PORT) -> None:
    out = vppctl_unchecked(
        "overlay", "enable", iface_name, "dst-port", str(dst_port),
    )
    assert "failed" not in out.lower(), f"enable produced: {out!r}"
    out = vppctl_unchecked(
        "overlay", "matcher", "add",
        "src-prefix", f"{POD_PREFIX}/{PREFIX_LEN}",
        "nic", iface_name,
    )
    assert "failed" not in out.lower(), f"matcher add produced: {out!r}"


def _disarm(iface_name: str) -> None:
    out = vppctl_unchecked("overlay", "disable", iface_name, "force")
    assert "failed" not in out.lower(), f"disable produced: {out!r}"


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s)


def _show_udp_port_registered(dst_port: int) -> bool:
    """Return True if dst_port is registered for IPv6 in the udp dispatch
    table.

    `vppctl show udp ports` prints (post ANSI strip):
        port  proto      node      desc
        6635   ip6   overlay-decap  (nil)
    """
    out = _strip_ansi(vppctl("show", "udp", "ports"))
    needle = str(dst_port)
    for line in out.splitlines():
        cols = line.split()
        if len(cols) >= 2 and cols[0] == needle and cols[1] == "ip6":
            return True
    return False


def _ipv6_checksum(src: bytes, dst: bytes, length: int, proto: int,
                   payload: bytes) -> int:
    """Standard IPv6 pseudo-header checksum."""
    pseudo = src + dst + struct.pack("!I", length) + b"\x00\x00\x00" + bytes([proto])
    data = pseudo + payload
    if len(data) & 1:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _build_packet(outer_src: str, outer_dst: str, outer_dport: int,
                  inner_src: str, inner_dst: str) -> bytes:
    """Build a complete Ethernet+IPv6+UDP+IPv6 frame for pg injection.

    Outer = IPv6+UDP. Inner = a minimal IPv6 packet (no L4 — we are only
    asserting that decap fires and forwards to ip6-input; ip6-input will
    parse the inner header and decide what to do next).
    """
    import socket

    # Inner: bare IPv6 header pointing at protocol 59 (NoNxt) so ip6-input
    # accepts it without further L4 parsing.
    inner_payload = b""  # 0-length L4
    inner_ip6 = struct.pack(
        "!IHBB",
        (6 << 28),                 # version=6, tc=0, fl=0
        len(inner_payload),         # payload_length
        59,                        # next_header = NoNxt (RFC 8200)
        64,                        # hop_limit
    ) + socket.inet_pton(socket.AF_INET6, inner_src) \
      + socket.inet_pton(socket.AF_INET6, inner_dst) \
      + inner_payload

    # Outer UDP carrying the inner packet.
    outer_sport = 0xC123
    udp_payload = inner_ip6
    udp_len = 8 + len(udp_payload)
    udp_no_cksum = struct.pack("!HHHH", outer_sport, outer_dport, udp_len, 0)
    outer_src_b = socket.inet_pton(socket.AF_INET6, outer_src)
    outer_dst_b = socket.inet_pton(socket.AF_INET6, outer_dst)
    cksum = _ipv6_checksum(outer_src_b, outer_dst_b, udp_len, 17,
                            udp_no_cksum + udp_payload)
    udp = struct.pack("!HHHH", outer_sport, outer_dport, udp_len, cksum) \
        + udp_payload

    # Outer IPv6.
    outer_ip6 = struct.pack(
        "!IHBB",
        (6 << 28),
        udp_len,
        17,    # next_header = UDP
        128,   # hop_limit (matches our overlay encap convention)
    ) + outer_src_b + outer_dst_b + udp

    # Ethernet: dmac = pg0's pinned hw addr, smac arbitrary, ethertype = IPv6.
    eth = PG0_MAC_BYTES + b"\x00" * 6 + b"\x86\xdd"

    return eth + outer_ip6


def _decap_counter() -> int:
    """Return the current overlay-decap DECAPSULATED counter."""
    out = vppctl("show", "errors")
    for line in out.splitlines():
        if "overlay-decap" in line and "decapsulated" in line.lower():
            # format: "<count> overlay-decap   packets decapsulated"
            parts = line.split()
            try:
                return int(parts[0])
            except (ValueError, IndexError):
                return 0
    return 0


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------


def test_arm_registers_udp_port(loopback):
    """Arming registers DST_PORT in the udp6 dispatch table."""
    assert not _show_udp_port_registered(DST_PORT), \
        "port already registered before arm"
    _arm(loopback)
    assert _show_udp_port_registered(DST_PORT), \
        "port not registered after arm"


def test_disarm_unregisters_udp_port(loopback):
    """Disarming removes DST_PORT from the udp6 dispatch table."""
    _arm(loopback)
    assert _show_udp_port_registered(DST_PORT)
    _disarm(loopback)
    assert not _show_udp_port_registered(DST_PORT), \
        "port still registered after disarm"


def test_decap_node_registered():
    """`show node overlay-decap` lists the node — confirms VLIB_REGISTER_NODE
    landed and the .so loaded with it."""
    out = vppctl("show", "node", "overlay-decap")
    assert "overlay-decap" in out.lower(), \
        f"overlay-decap node missing from `show node`: {out!r}"


def test_synthetic_packet_decapsulates(loopback):
    """Inject an IPv6+UDP packet via pg matching the registered port and
    confirm the overlay-decap counter increments."""
    _arm(loopback)

    # Bring the loopback up and give it the outer-dst address — this is
    # what makes ip6-lookup route to ip6-local instead of dropping.
    vppctl_unchecked("set", "interface", "ip", "address",
                     loopback, f"{LOCAL_ADDR}/128")
    vppctl_unchecked("set", "interface", "state", loopback, "up")

    # Set up a packet-generator interface to receive our synthetic frame.
    pg_iface = "pg0"
    vppctl_unchecked("create", "packet-generator", "interface", pg_iface)
    # Pin pg0's MAC so injected frames' dmac matches.
    vppctl_unchecked("set", "interface", "mac", "address", pg_iface, PG0_MAC)
    vppctl_unchecked("set", "interface", "ip", "address",
                     pg_iface, "fd00:beef::1/64")
    vppctl_unchecked("set", "interface", "state", pg_iface, "up")
    vppctl_unchecked("trace", "add", "pg-input", "10")

    pkt = _build_packet(
        outer_src="fd00:beef::2",
        outer_dst=LOCAL_ADDR,
        outer_dport=DST_PORT,
        inner_src="fd00:cafe:0:1::100",
        inner_dst="fd00:cafe:0:2::200",
    )
    hex_data = pkt.hex()
    size = len(pkt)

    before = _decap_counter()

    # `size` is N-N (range form); `enable-stream` is the activation verb.
    cli_script = (
        "packet-generator new { "
        f"name decap1 limit 1 size {size}-{size} node ethernet-input "
        f"interface {pg_iface} "
        f"data {{ hex 0x{hex_data} }} "
        "}"
    )
    vppctl_unchecked(cli_script)
    vppctl_unchecked("packet-generator", "enable-stream", "decap1")

    # Give VPP a moment to drain the frame.
    for _ in range(20):
        time.sleep(0.05)
        if _decap_counter() > before:
            break

    after = _decap_counter()
    assert after > before, (
        f"overlay-decap DECAPSULATED counter did not increment "
        f"(before={before} after={after}). Trace:\n"
        f"{vppctl_unchecked('show', 'trace')}"
    )
