"""Phase 3 — overlay-bypass node behavioral tests.

Topology (pure software, no DPDK):

    pg0 (uplink, NetVSC1 simulant)        pg1 (pod tap simulant)
    underlay /128 + SID /96                pod gw /128
         |                                       |
         +-- SR localsid End.DX6 → pg1, next-hop pod -+

The bypass node sits as a feature on the `ip6-unicast` arc with
`runs_before = ip6-lookup`. When an IPv6+UDP frame ingresses an armed NIC
with outer-dst == any local addr (e.g. the SID) and outer UDP dst-port ==
the configured tunnel port, the outer 48 bytes are stripped and the inner
packet is dispatched to ip6-lookup so SR localsid can match the SID. This
is regression coverage for the bug where SR localsid stole the
UDP-wrapped packet before the bypass had a chance to run.
"""

import re
import socket
import struct
import time

import pytest
from conftest import vppctl, vppctl_unchecked
from overlay_helpers import counter, inject, strip_ansi, trace


DST_PORT = 6635
UNDERLAY_ADDR = "fd00:dead:beef:2::4"
SID_PREFIX = "fd00:dead:beef:2:1::"
SID_PREFIX_LEN = 96
SID_ADDR = "fd00:dead:beef:2:1::1"
LOCAL_PFX = "fd00:dead:beef:2:0:1::"
LOCAL_PFX_LEN = 96
POD_GW_ADDR = "fd00:dead:beef:2:0:1::ff"
POD_NEXTHOP = "fd00:dead:beef:2:0:1::1"
POD_NEXTHOP_MAC = "02:fe:00:00:00:01"
OUTER_UNDERLAY_NET = "fd00:dead:beef:1::"
OUTER_UNDERLAY_NET_LEN = 64
OUTER_SRC = "fd00:dead:beef:1::4"
INNERMOST_SRC = "fd00:dead:beef:1:0:1::1"
INNERMOST_DST = "fd00:beef::1"


# ---------------------------------------------------------------------------
# topology fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def bypass_topology():
    """Build pg0/pg1 + arm overlay on pg0 + install SR localsid for the SID."""
    vppctl_unchecked("create", "packet-generator", "interface", "pg0")
    vppctl_unchecked("create", "packet-generator", "interface", "pg1")
    vppctl_unchecked("set", "interface", "state", "pg0", "up")
    vppctl_unchecked("set", "interface", "state", "pg1", "up")

    # pg0 = uplink: underlay /128 + SID /96.
    vppctl_unchecked("set", "interface", "ip", "address",
                     "pg0", f"{UNDERLAY_ADDR}/128")
    vppctl_unchecked("set", "interface", "ip", "address",
                     "pg0", f"{SID_PREFIX}99/{SID_PREFIX_LEN}")

    # pg1 = pod tap: pod gw /128 + static neighbor + route.
    vppctl_unchecked("set", "interface", "ip", "address",
                     "pg1", f"{POD_GW_ADDR}/128")
    vppctl_unchecked("ip", "neighbor", "pg1",
                     POD_NEXTHOP, POD_NEXTHOP_MAC, "static")
    vppctl_unchecked("ip", "route", "add",
                     f"{POD_NEXTHOP}/128", "via", "pg1")
    # RPF: outer src must route somewhere.
    vppctl_unchecked("ip", "route", "add",
                     f"{OUTER_UNDERLAY_NET}/{OUTER_UNDERLAY_NET_LEN}",
                     "via", "pg1")

    out = vppctl_unchecked("overlay", "enable", "pg0", "dst-port", str(DST_PORT))
    assert "failed" not in out.lower(), f"enable produced: {out!r}"
    out = vppctl_unchecked(
        "overlay", "matcher", "add",
        "src-prefix", f"{LOCAL_PFX}/{LOCAL_PFX_LEN}",
        "nic", "pg0",
    )
    assert "failed" not in out.lower(), f"matcher add produced: {out!r}"

    # SR localsid: End.DX6 to pg1 next-hop pod.
    vppctl_unchecked("sr", "localsid", "address", SID_ADDR,
                     "behavior", "end.dx6", "pg1", POD_NEXTHOP)

    vppctl_unchecked("clear", "errors")
    vppctl_unchecked("clear", "trace")
    vppctl_unchecked("trace", "add", "pg-input", "20")

    yield

    vppctl_unchecked("clear", "trace")
    vppctl_unchecked("sr", "localsid", "del", "address", SID_ADDR)
    vppctl_unchecked("overlay", "disable", "pg0", "force")
    vppctl_unchecked("ip", "route", "del",
                     f"{OUTER_UNDERLAY_NET}/{OUTER_UNDERLAY_NET_LEN}",
                     "via", "pg1")
    vppctl_unchecked("ip", "route", "del",
                     f"{POD_NEXTHOP}/128", "via", "pg1")


# ---------------------------------------------------------------------------
# packet builders
# ---------------------------------------------------------------------------


def _pg0_mac() -> str:
    """Read pg0's hardware address — outer eth dst must match for
    ethernet-input to accept the frame as locally addressed."""
    out = strip_ansi(vppctl("show", "hardware-interfaces", "pg0"))
    m = re.search(r"Ethernet address\s+([0-9a-f:]{17})", out)
    assert m, f"could not parse pg0 MAC from:\n{out}"
    return m.group(1)


def _ip6(s: str) -> bytes:
    return socket.inet_pton(socket.AF_INET6, s)


def _build_srh_encap_frame(outer_src: str, outer_dst: str,
                           outer_dport: int) -> bytes:
    """Outer eth + outer IPv6 + UDP + inner IPv6 + SRH(1 seg) + innermost IPv6.

    The "inner IPv6" carries an SRH whose only segment == SID == outer_dst,
    next-hdr = 41 (encap IPv6) so SR localsid End.DX6 cross-connects the
    innermost IPv6 onto pg1.
    """
    innermost = struct.pack("!IHBB", (6 << 28), 0, 59, 64) \
        + _ip6(INNERMOST_SRC) + _ip6(INNERMOST_DST)

    srh = struct.pack("!BBBBBBBB", 41, 2, 4, 0, 0, 0, 0, 0) \
        + _ip6(SID_ADDR) + innermost

    inner_ip6 = struct.pack("!IHBB", (6 << 28), len(srh), 43, 64) \
        + _ip6(INNERMOST_SRC) + _ip6(SID_ADDR) + srh

    udp = struct.pack("!HHHH", 0xC001, outer_dport, 8 + len(inner_ip6), 0) \
        + inner_ip6

    outer = struct.pack("!IHBB", (6 << 28), len(udp), 17, 128) \
        + _ip6(outer_src) + _ip6(outer_dst) + udp

    eth = bytes.fromhex(_pg0_mac().replace(":", "")) + b"\x00" * 6 + b"\x86\xdd"
    return eth + outer


def _build_plain_ip6_frame(dst: str) -> bytes:
    """Bare IPv6 frame with next-hdr=59, no UDP — the bypass node should
    NOT claim it."""
    payload = struct.pack("!IHBB", (6 << 28), 0, 59, 64) \
        + _ip6(OUTER_SRC) + _ip6(dst)
    eth = bytes.fromhex(_pg0_mac().replace(":", "")) + b"\x00" * 6 + b"\x86\xdd"
    return eth + payload


# ---------------------------------------------------------------------------
# counters / trace helpers
# ---------------------------------------------------------------------------


def _bypass_decap_counter() -> int:
    return counter("overlay-bypass", "decapsulated")


def _sr_localsid_no_inner_counter() -> int:
    return counter("sr-localsid-d", "no inner ip header")


def _sr_localsid_good_packets() -> int:
    out = strip_ansi(vppctl("show", "sr", "localsid"))
    # Look for the section for our SID.
    section = None
    for chunk in out.split("--------------------"):
        if SID_ADDR in chunk:
            section = chunk
            break
    if section is None:
        return 0
    m = re.search(r"Good traffic:\s*\[(\d+)\s+packets", section)
    return int(m.group(1)) if m else 0


def _wait_for(fn, target: int, timeout: float = 1.5) -> int:
    deadline = time.time() + timeout
    val = fn()
    while val < target and time.time() < deadline:
        time.sleep(0.05)
        val = fn()
    return val


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------


def test_bypass_node_registered():
    """`show node overlay-bypass` succeeds — confirms feature registration."""
    out = vppctl("show", "node", "overlay-bypass")
    assert "overlay-bypass" in out.lower(), out


def test_bypass_decapsulates_when_outer_dst_is_sid(bypass_topology):
    """Inject a UDP/6635 frame whose outer-dst is the SID. Bypass strips
    the outer headers, ip6-lookup routes the inner pkt to SR localsid,
    SR End.DX6 cross-connects to pg1."""
    bypass_before = _bypass_decap_counter()
    sr_good_before = _sr_localsid_good_packets()
    sr_err_before = _sr_localsid_no_inner_counter()

    frame = _build_srh_encap_frame(OUTER_SRC, SID_ADDR, DST_PORT)
    inject(frame, "bypass1")

    bypass_after = _wait_for(_bypass_decap_counter, bypass_before + 1)
    sr_good_after = _wait_for(_sr_localsid_good_packets, sr_good_before + 1)
    sr_err_after = _sr_localsid_no_inner_counter()

    trace_out = trace()
    assert bypass_after > bypass_before, (
        f"overlay-bypass decapsulated counter didn't increment "
        f"(before={bypass_before} after={bypass_after}). Trace:\n{trace_out}"
    )
    assert sr_good_after > sr_good_before, (
        f"SR localsid good-traffic didn't increment "
        f"(before={sr_good_before} after={sr_good_after}). Trace:\n{trace_out}"
    )
    assert sr_err_after == sr_err_before, (
        f"sr-localsid-d (No inner IP header) error fired "
        f"(before={sr_err_before} after={sr_err_after}) — "
        f"bypass didn't run before SR localsid. Trace:\n{trace_out}"
    )

    # Sanity-check the trace chain.
    assert "overlay-bypass" in trace_out, f"overlay-bypass not in trace:\n{trace_out}"
    assert "sr-localsid-d" in trace_out, f"sr-localsid-d not in trace:\n{trace_out}"


def test_bypass_passes_through_non_matching_dport(bypass_topology):
    """Outer UDP dst-port != tunnel port → bypass must NOT decapsulate."""
    bypass_before = _bypass_decap_counter()

    frame = _build_srh_encap_frame(OUTER_SRC, SID_ADDR, 9999)
    inject(frame, "bypass_wrongport")

    # Give VPP time to either fire the counter or not.
    time.sleep(0.5)
    bypass_after = _bypass_decap_counter()

    assert bypass_after == bypass_before, (
        f"overlay-bypass fired on non-matching dport "
        f"(before={bypass_before} after={bypass_after}). Trace:\n{trace()}"
    )


def test_bypass_passes_through_non_udp(bypass_topology):
    """Non-UDP IPv6 frame → bypass must NOT decapsulate."""
    bypass_before = _bypass_decap_counter()

    # IPv6 with next-hdr=59 (NoNxt), dst is the underlay /128 (not SID, to
    # avoid hitting any other path). ip6-input should accept locally and
    # the bypass node must fall through (not increment its decap counter).
    frame = _build_plain_ip6_frame(UNDERLAY_ADDR)
    inject(frame, "bypass_nonudp")

    time.sleep(0.5)
    bypass_after = _bypass_decap_counter()

    assert bypass_after == bypass_before, (
        f"overlay-bypass fired on non-UDP frame "
        f"(before={bypass_before} after={bypass_after}). Trace:\n{trace()}"
    )
