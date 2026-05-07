"""Multi-NIC encap tests — Slice A (shared tunnel) + Slice B (tenant separation).

Topology (shared by both fixtures):

    pg0 (ingress, unarmed)
      |
      +-- ip6-fib: route_a → pg1 via NEXT_HOP_A
      +-- ip6-fib: route_b → pg2 via NEXT_HOP_B

    pg1 (overlay-armed, egress for tenant A)
    pg2 (overlay-armed, egress for tenant B)

Slice A: pg1 and pg2 share identical (src, src_prefix, dst_port). Both NICs
end up under one tunnel; encap fires on either egress.

Slice B: pg1 has src_prefix A, pg2 has src_prefix B (different /64s) on the
same dst_port. Two distinct tunnels share a single UDP dst port; encap
filtering is per-NIC.
"""
import re
import socket
import struct
import time

import pytest
from conftest import vppctl, vppctl_unchecked


DST_PORT = 6635
LOCAL_ADDR = "fd00:cafe::1"

# Tenant A: pg1 egress
PREFIX_A = "2001:db8:e:e::"
PREFIX_A_LEN = 64
ROUTE_A_PREFIX = "2001:db8:e:e::"
ROUTE_A_LEN = 64
NEXT_HOP_A = "fd00:dead::2"
NEXT_HOP_A_MAC = "02:fe:00:00:00:02"

# Tenant B: pg2 egress
PREFIX_B = "2001:db8:50:50::"
PREFIX_B_LEN = 64
ROUTE_B_PREFIX = "2001:db8:50:50::"
ROUTE_B_LEN = 64
NEXT_HOP_B = "fd00:beef::2"
NEXT_HOP_B_MAC = "02:fe:00:00:00:03"

PG0_ADDR = "fd00:abcd::1"
PG1_ADDR = "fd00:dead::1"
PG2_ADDR = "fd00:beef::1"

# Pin pg0 MAC so injected frames' dmac matches.
PG0_MAC = "02:fe:00:00:00:01"
PG0_MAC_BYTES = bytes.fromhex(PG0_MAC.replace(":", ""))


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s)


def _build_inner_frame(inner_src: str, inner_dst: str) -> bytes:
    """Bare inner IPv6 (next-header = 59 / NoNxt) so ip6-input accepts
    it without further L4 parsing — same trick as test_overlay_encap."""
    src = socket.inet_pton(socket.AF_INET6, inner_src)
    dst = socket.inet_pton(socket.AF_INET6, inner_dst)
    inner_ip6 = struct.pack("!IHBB", (6 << 28), 0, 59, 64) + src + dst
    eth = PG0_MAC_BYTES + b"\x00" * 6 + b"\x86\xdd"
    return eth + inner_ip6


def _inject(frame: bytes, name: str) -> None:
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
    deadline = time.time() + timeout
    val = _counter(substring)
    while val < target and time.time() < deadline:
        time.sleep(0.05)
        val = _counter(substring)
    return val


def _bring_up_pg(name: str, addr: str, mac: str | None = None) -> None:
    vppctl_unchecked("create", "packet-generator", "interface", name)
    if mac is not None:
        vppctl_unchecked("set", "interface", "mac", "address", name, mac)
    vppctl_unchecked("set", "interface", "ip", "address", name, f"{addr}/64")
    vppctl_unchecked("set", "interface", "state", name, "up")


# ---------------------------------------------------------------------------
# Slice A — shared tunnel across two NICs (same src, src_prefix, dst_port)
# ---------------------------------------------------------------------------


@pytest.fixture
def shared_tunnel_topology():
    _bring_up_pg("pg0", PG0_ADDR, PG0_MAC)
    _bring_up_pg("pg1", PG1_ADDR)
    _bring_up_pg("pg2", PG2_ADDR)

    vppctl_unchecked("ip", "neighbor", "pg1", NEXT_HOP_A, NEXT_HOP_A_MAC, "static")
    vppctl_unchecked("ip", "neighbor", "pg2", NEXT_HOP_B, NEXT_HOP_B_MAC, "static")

    # Shared src_prefix /48 covers both /64 routes.
    shared_prefix = "2001:db8::"
    shared_len = 32
    # Route for "tenant A inner dst" via pg1.
    vppctl_unchecked("ip", "route", "add",
                     f"{ROUTE_A_PREFIX}/{ROUTE_A_LEN}",
                     "via", NEXT_HOP_A, "pg1")
    # Route for "tenant B inner dst" via pg2.
    vppctl_unchecked("ip", "route", "add",
                     f"{ROUTE_B_PREFIX}/{ROUTE_B_LEN}",
                     "via", NEXT_HOP_B, "pg2")

    # Arm both NICs with the SAME params — Slice A: shared tunnel.
    out = vppctl_unchecked(
        "overlay", "arm", "pg1",
        "src", LOCAL_ADDR,
        "src-prefix", f"{shared_prefix}/{shared_len}",
        "dst-port", str(DST_PORT),
    )
    assert out.strip() == "", f"arm pg1 unexpected output: {out!r}"
    out = vppctl_unchecked(
        "overlay", "arm", "pg2",
        "src", LOCAL_ADDR,
        "src-prefix", f"{shared_prefix}/{shared_len}",
        "dst-port", str(DST_PORT),
    )
    assert out.strip() == "", f"arm pg2 unexpected output: {out!r}"

    vppctl_unchecked("trace", "add", "pg-input", "20")

    yield

    vppctl_unchecked("clear", "trace")
    vppctl_unchecked("clear", "errors")
    vppctl_unchecked("overlay", "disarm", "pg1")
    vppctl_unchecked("overlay", "disarm", "pg2")
    vppctl_unchecked("ip", "route", "del",
                     f"{ROUTE_A_PREFIX}/{ROUTE_A_LEN}",
                     "via", NEXT_HOP_A, "pg1")
    vppctl_unchecked("ip", "route", "del",
                     f"{ROUTE_B_PREFIX}/{ROUTE_B_LEN}",
                     "via", NEXT_HOP_B, "pg2")


def test_slice_a_one_tunnel_two_nics(shared_tunnel_topology):
    """Two NICs armed with identical params collapse onto one tunnel."""
    show = vppctl("show", "overlay")
    assert show.count("overlay tunnel:") == 1, show
    assert "pg1" in show and "pg2" in show, show


def test_slice_a_encap_via_pg1(shared_tunnel_topology):
    before = _counter("packets encapsulated")
    frame = _build_inner_frame("2001:db8:e:e::100", "2001:db8:e:e::200")
    _inject(frame, "sliceA_pg1")
    after = _wait_for_counter("packets encapsulated", before + 1)
    assert after > before, (
        f"ENCAPSULATED via pg1 didn't increment "
        f"(before={before} after={after}). Trace:\n{_trace()}"
    )


def test_slice_a_encap_via_pg2(shared_tunnel_topology):
    before = _counter("packets encapsulated")
    frame = _build_inner_frame("2001:db8:50:50::100", "2001:db8:50:50::200")
    _inject(frame, "sliceA_pg2")
    after = _wait_for_counter("packets encapsulated", before + 1)
    assert after > before, (
        f"ENCAPSULATED via pg2 didn't increment "
        f"(before={before} after={after}). Trace:\n{_trace()}"
    )


# ---------------------------------------------------------------------------
# Slice B — tenant separation (different src_prefix per NIC, same dst_port)
# ---------------------------------------------------------------------------


@pytest.fixture
def tenant_topology():
    _bring_up_pg("pg0", PG0_ADDR, PG0_MAC)
    _bring_up_pg("pg1", PG1_ADDR)
    _bring_up_pg("pg2", PG2_ADDR)

    vppctl_unchecked("ip", "neighbor", "pg1", NEXT_HOP_A, NEXT_HOP_A_MAC, "static")
    vppctl_unchecked("ip", "neighbor", "pg2", NEXT_HOP_B, NEXT_HOP_B_MAC, "static")

    vppctl_unchecked("ip", "route", "add",
                     f"{ROUTE_A_PREFIX}/{ROUTE_A_LEN}",
                     "via", NEXT_HOP_A, "pg1")
    vppctl_unchecked("ip", "route", "add",
                     f"{ROUTE_B_PREFIX}/{ROUTE_B_LEN}",
                     "via", NEXT_HOP_B, "pg2")

    # pg1 — tenant A
    out = vppctl_unchecked(
        "overlay", "arm", "pg1",
        "src", LOCAL_ADDR,
        "src-prefix", f"{PREFIX_A}/{PREFIX_A_LEN}",
        "dst-port", str(DST_PORT),
    )
    assert out.strip() == "", f"arm pg1 unexpected output: {out!r}"
    # pg2 — tenant B (different src_prefix, same dst_port)
    out = vppctl_unchecked(
        "overlay", "arm", "pg2",
        "src", LOCAL_ADDR,
        "src-prefix", f"{PREFIX_B}/{PREFIX_B_LEN}",
        "dst-port", str(DST_PORT),
    )
    assert out.strip() == "", f"arm pg2 unexpected output: {out!r}"

    vppctl_unchecked("trace", "add", "pg-input", "20")

    yield

    vppctl_unchecked("clear", "trace")
    vppctl_unchecked("clear", "errors")
    vppctl_unchecked("overlay", "disarm", "pg1")
    vppctl_unchecked("overlay", "disarm", "pg2")
    vppctl_unchecked("ip", "route", "del",
                     f"{ROUTE_A_PREFIX}/{ROUTE_A_LEN}",
                     "via", NEXT_HOP_A, "pg1")
    vppctl_unchecked("ip", "route", "del",
                     f"{ROUTE_B_PREFIX}/{ROUTE_B_LEN}",
                     "via", NEXT_HOP_B, "pg2")


def test_slice_b_two_tunnels(tenant_topology):
    """Different src_prefix per NIC -> two tunnels share a single dst_port."""
    show = vppctl("show", "overlay")
    assert show.count("overlay tunnel:") == 2, show
    assert PREFIX_A in show and PREFIX_B in show, show


def test_slice_b_encap_tenant_a_via_pg1(tenant_topology):
    """Inner src in PREFIX_A routed to pg1 -> encap fires (src matches)."""
    before = _counter("packets encapsulated")
    frame = _build_inner_frame("2001:db8:e:e::1", "2001:db8:e:e::200")
    _inject(frame, "sliceB_pg1_match")
    after = _wait_for_counter("packets encapsulated", before + 1)
    assert after > before, (
        f"ENCAPSULATED via pg1 (tenant A) didn't increment "
        f"(before={before} after={after}). Trace:\n{_trace()}"
    )


def test_slice_b_encap_tenant_b_via_pg2(tenant_topology):
    """Inner src in PREFIX_B routed to pg2 -> encap fires."""
    before = _counter("packets encapsulated")
    frame = _build_inner_frame("2001:db8:50:50::1", "2001:db8:50:50::200")
    _inject(frame, "sliceB_pg2_match")
    after = _wait_for_counter("packets encapsulated", before + 1)
    assert after > before, (
        f"ENCAPSULATED via pg2 (tenant B) didn't increment "
        f"(before={before} after={after}). Trace:\n{_trace()}"
    )


def test_slice_b_wrong_prefix_passes_through_pg2(tenant_topology):
    """A frame with src in PREFIX_A but routed to pg2 (dst in PREFIX_B)
    must pass through unchanged — pg2's tunnel src_prefix is B, so the
    src ∈ A check fails and PASSED_THROUGH increments."""
    encap_before = _counter("packets encapsulated")
    pass_before = _counter("non-matching-src")

    # src is in tenant A; dst routed to pg2 (tenant B egress) — encap on
    # pg2 must not fire because pg2's tunnel filters on PREFIX_B.
    frame = _build_inner_frame("2001:db8:e:e::1", "2001:db8:50:50::200")
    _inject(frame, "sliceB_wrong_prefix")

    pass_after = _wait_for_counter("non-matching-src", pass_before + 1)
    encap_after = _counter("packets encapsulated")

    assert pass_after > pass_before, (
        f"PASSED_THROUGH didn't increment for cross-tenant traffic on pg2 "
        f"(before={pass_before} after={pass_after}). Trace:\n{_trace()}"
    )
    assert encap_after == encap_before, (
        f"encap should NOT have fired for src outside pg2's prefix "
        f"(before={encap_before} after={encap_after}). Trace:\n{_trace()}"
    )


def test_slice_b_non_srv6_ipv6_passes_through(tenant_topology):
    """A regular IPv6 frame (src outside both prefixes) on either NIC
    must pass through unchanged."""
    encap_before = _counter("packets encapsulated")
    pass_before = _counter("non-matching-src")

    # src in fd00:abcd::/64 — outside both PREFIX_A and PREFIX_B. Routed
    # to pg1 since dst is in PREFIX_A's route.
    frame = _build_inner_frame("fd00:abcd::99", "2001:db8:e:e::200")
    _inject(frame, "sliceB_non_overlay")

    pass_after = _wait_for_counter("non-matching-src", pass_before + 1)
    encap_after = _counter("packets encapsulated")

    assert pass_after > pass_before, (
        f"PASSED_THROUGH didn't increment for non-overlay traffic "
        f"(before={pass_before} after={pass_after}). Trace:\n{_trace()}"
    )
    assert encap_after == encap_before, (
        f"encap should NOT have fired for non-overlay src "
        f"(before={encap_before} after={encap_after}). Trace:\n{_trace()}"
    )


def test_slice_b_disarm_one_keeps_other(tenant_topology):
    """Disarming pg1 must not affect pg2's tunnel."""
    out = vppctl_unchecked("overlay", "disarm", "pg1")
    assert "failed" not in out, out
    show = vppctl("show", "overlay")
    assert show.count("overlay tunnel:") == 1, show
    assert "pg2" in show, show
    assert PREFIX_B in show, show
    # Re-arm so the fixture teardown's disarm pg1 doesn't error.
    out = vppctl_unchecked(
        "overlay", "arm", "pg1",
        "src", LOCAL_ADDR,
        "src-prefix", f"{PREFIX_A}/{PREFIX_A_LEN}",
        "dst-port", str(DST_PORT),
    )
    assert out.strip() == "", out
