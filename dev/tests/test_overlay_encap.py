"""Encap-node behavioral tests.

Topology in container (pure software, no DPDK):

    pg0 (ingress)              pg1 (egress, overlay-encap armed)
    fd00:beef::1/64            fd00:dead::1/64
         |                              |
         +-- ip6-fib: fd00:cafe::/48 via fd00:dead::2 on pg1 --+

Static neighbor for fd00:dead::2 lets ip6-rewrite stamp L2 without ND.

Tests inject a frame at pg0 carrying an inner IPv6 packet whose dst is
fd00:cafe::200 — routed to pg1 — and whose src varies (in or out of the
configured src_prefix). Expectations:

  inner src ∈ src_prefix  →  overlay-encap fires, outer IPv6+UDP
                              wrapper added, ENCAPSULATED++
  inner src ∉ src_prefix  →  feature passes through unchanged,
                              PASSED_THROUGH++
"""

import re
import socket
import struct
import time

import pytest
from conftest import vppctl, vppctl_unchecked


DST_PORT = 6635
POD_PREFIX = "fd00:cafe::"
PREFIX_LEN = 48
LOCAL_ADDR = "fd00:cafe::1"

PG0_ADDR = "fd00:beef::1"
PG1_ADDR = "fd00:dead::1"
NEXT_HOP = "fd00:dead::2"
NEXT_HOP_MAC = "02:fe:00:00:00:02"


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s)


# ---------------------------------------------------------------------------
# topology + injection helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def encap_topology():
    """Build pg0/pg1 + arm overlay on pg1 + add static route. Tear down at end."""
    vppctl_unchecked("create", "packet-generator", "interface", "pg0")
    vppctl_unchecked("create", "packet-generator", "interface", "pg1")
    vppctl_unchecked("set", "interface", "ip", "address", "pg0", f"{PG0_ADDR}/64")
    vppctl_unchecked("set", "interface", "ip", "address", "pg1", f"{PG1_ADDR}/64")
    vppctl_unchecked("set", "interface", "state", "pg0", "up")
    vppctl_unchecked("set", "interface", "state", "pg1", "up")

    # Static neighbor on pg1 for the next-hop, so ip6-rewrite has an L2.
    vppctl_unchecked("ip", "neighbor", "pg1", NEXT_HOP, NEXT_HOP_MAC, "static")

    # Route the pod prefix to pg1 via the static neighbor.
    vppctl_unchecked("ip", "route", "add",
                     f"{POD_PREFIX}/{PREFIX_LEN}",
                     "via", NEXT_HOP, "pg1")

    # Arm overlay on pg1 (also need a "loopback" — overlay_arm requires a
    # real sw_if_index; pg1 itself works).
    out = vppctl_unchecked(
        "overlay", "arm", "pg1",
        "src", LOCAL_ADDR,
        "src-prefix", f"{POD_PREFIX}/{PREFIX_LEN}",
        "dst-port", str(DST_PORT),
    )
    assert out.strip() == "", f"arm produced unexpected output: {out!r}"

    # Tracing on for the pg-input ingress.
    vppctl_unchecked("trace", "add", "pg-input", "20")

    yield

    vppctl_unchecked("clear", "trace")
    vppctl_unchecked("clear", "errors")
    vppctl_unchecked("overlay", "disarm", "pg1")
    vppctl_unchecked("ip", "route", "del",
                     f"{POD_PREFIX}/{PREFIX_LEN}",
                     "via", NEXT_HOP, "pg1")


def _build_inner_frame(inner_src: str, inner_dst: str) -> bytes:
    """Ethernet frame carrying a bare inner IPv6 (next-header = 59 / NoNxt)
    so ip6-input accepts it without further L4 parsing."""
    src = socket.inet_pton(socket.AF_INET6, inner_src)
    dst = socket.inet_pton(socket.AF_INET6, inner_dst)
    inner_ip6 = struct.pack("!IHBB", (6 << 28), 0, 59, 64) + src + dst
    eth = b"\x00" * 12 + b"\x86\xdd"
    return eth + inner_ip6


def _inject(frame: bytes, name: str = "encap_pkt") -> None:
    hex_data = frame.hex()
    size = len(frame)
    cmd = (
        "packet-generator new { "
        f"name {name} limit 1 size {size}-{size} node ethernet-input "
        f"interface pg0 "
        f"data {{ hex 0x{hex_data} }} "
        "}"
    )
    vppctl_unchecked(cmd)
    vppctl_unchecked("packet-generator", "enable-stream", name)


def _counter(name_substring: str) -> int:
    """Return the value of the named overlay-encap error counter."""
    out = vppctl("show", "errors")
    for line in out.splitlines():
        low = line.lower()
        if "overlay-encap" in low and name_substring.lower() in low:
            parts = line.split()
            try:
                return int(parts[0])
            except (ValueError, IndexError):
                return 0
    return 0


def _trace() -> str:
    return _strip_ansi(vppctl_unchecked("show", "trace"))


def _wait_for_counter(substring: str, target: int, timeout: float = 1.0) -> int:
    """Poll the error counter until it reaches `target` or timeout."""
    deadline = time.time() + timeout
    val = _counter(substring)
    while val < target and time.time() < deadline:
        time.sleep(0.05)
        val = _counter(substring)
    return val


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------


def test_encap_node_registered(encap_topology):
    out = vppctl("show", "node", "overlay-encap")
    assert "overlay-encap" in out.lower(), out


def test_encap_in_pod_prefix_increments_counter(encap_topology):
    """Inner src in src_prefix → encap fires → counter increments."""
    before = _counter("packets encapsulated")
    frame = _build_inner_frame("fd00:cafe::100", "fd00:cafe::200")
    _inject(frame, "encap1")

    after = _wait_for_counter("packets encapsulated", before + 1)
    assert after > before, (
        f"ENCAPSULATED counter didn't increment "
        f"(before={before} after={after}). Trace:\n{_trace()}"
    )


def test_encap_outer_dst_equals_inner_dst(encap_topology):
    """Trace must show outer-dst == inner-dst (the design's central trick)."""
    inner_dst = "fd00:cafe::abcd"
    frame = _build_inner_frame("fd00:cafe::100", inner_dst)
    _inject(frame, "encap2")
    _wait_for_counter("packets encapsulated", 1)

    trace = _trace()
    # Find the overlay-encap trace line.
    found = False
    for line in trace.splitlines():
        if "overlay-encap:" in line and "->" in line and "udp" in line:
            # format: "overlay-encap: tunnel N outer SRC -> DST udp SP -> DP"
            assert inner_dst in line, (
                f"outer dst doesn't match inner dst {inner_dst}. Line: {line}"
            )
            found = True
            break
    assert found, f"no overlay-encap trace line found:\n{trace}"


def test_encap_outer_udp_dport_matches_tunnel(encap_topology):
    """Outer UDP dst port equals the configured tunnel dst_port."""
    frame = _build_inner_frame("fd00:cafe::100", "fd00:cafe::200")
    _inject(frame, "encap3")
    _wait_for_counter("packets encapsulated", 1)

    trace = _trace()
    # Match "udp <sport> -> <dport>"
    m = None
    for line in trace.splitlines():
        if "overlay-encap:" in line:
            m = re.search(r"udp\s+(\d+)\s*->\s*(\d+)", line)
            if m:
                break
    assert m, f"no encap udp ports in trace:\n{trace}"
    sport, dport = int(m.group(1)), int(m.group(2))
    assert dport == DST_PORT, f"outer UDP dport={dport}, expected {DST_PORT}"
    # Sport must be in the ephemeral range (0xC000-0xFFFF) — entropy bits.
    assert 0xC000 <= sport <= 0xFFFF, f"outer UDP sport={sport} not ephemeral"


def test_pass_through_for_non_matching_src(encap_topology):
    """Inner src outside src_prefix → pass-through, no encap."""
    encap_before = _counter("packets encapsulated")
    pass_before = _counter("non-matching-src")

    frame = _build_inner_frame("fd00:beef::99", "fd00:cafe::200")
    _inject(frame, "passthru1")

    pass_after = _wait_for_counter("non-matching-src", pass_before + 1)
    encap_after = _counter("packets encapsulated")

    assert pass_after > pass_before, (
        f"PASSED_THROUGH counter didn't increment "
        f"(before={pass_before} after={pass_after}). Trace:\n{_trace()}"
    )
    assert encap_after == encap_before, (
        f"encap should NOT have fired for non-pod src "
        f"(before={encap_before} after={encap_after})"
    )
