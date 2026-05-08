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

import pytest
from conftest import vppctl, vppctl_unchecked
from overlay_helpers import (
    build_inner_frame, counter, inject, trace, wait_for_counter,
)


DST_PORT = 6635
POD_PREFIX = "fd00:cafe::"
PREFIX_LEN = 48
LOCAL_ADDR = "fd00:cafe::1"

PG0_ADDR = "fd00:beef::1"
PG1_ADDR = "fd00:dead::1"
NEXT_HOP = "fd00:dead::2"
NEXT_HOP_MAC = "02:fe:00:00:00:02"

# pg0's hw address — pinned so the injected frame's dmac matches and
# ethernet-input does not punt the packet with "l3 mac mismatch".
PG0_MAC = "02:fe:00:00:00:01"
PG0_MAC_BYTES = bytes.fromhex(PG0_MAC.replace(":", ""))


# ---------------------------------------------------------------------------
# topology + injection helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def encap_topology():
    """Build pg0/pg1 + arm overlay on pg1 + add static route. Tear down at end."""
    vppctl_unchecked("create", "packet-generator", "interface", "pg0")
    vppctl_unchecked("create", "packet-generator", "interface", "pg1")
    # Pin pg0's MAC so injected frames' dmac matches (otherwise
    # ethernet-input punts with "l3 mac mismatch").
    vppctl_unchecked("set", "interface", "mac", "address", "pg0", PG0_MAC)
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

    # Enable overlay on pg1 and add the matcher.
    out = vppctl_unchecked("overlay", "enable", "pg1", "dst-port", str(DST_PORT))
    assert "failed" not in out.lower(), f"enable produced: {out!r}"
    out = vppctl_unchecked(
        "overlay", "matcher", "add",
        "src-prefix", f"{POD_PREFIX}/{PREFIX_LEN}",
        "nic", "pg1",
    )
    assert "failed" not in out.lower(), f"matcher add produced: {out!r}"

    # Tracing on for the pg-input ingress.
    vppctl_unchecked("trace", "add", "pg-input", "20")

    yield

    vppctl_unchecked("clear", "trace")
    vppctl_unchecked("clear", "errors")
    vppctl_unchecked("overlay", "disable", "pg1", "force")
    vppctl_unchecked("ip", "route", "del",
                     f"{POD_PREFIX}/{PREFIX_LEN}",
                     "via", NEXT_HOP, "pg1")


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------


def test_encap_node_registered(encap_topology):
    out = vppctl("show", "node", "overlay-encap")
    assert "overlay-encap" in out.lower(), out


def test_encap_in_pod_prefix_increments_counter(encap_topology):
    """Inner src in src_prefix → encap fires → counter increments."""
    before = counter("overlay-encap", "packets encapsulated")
    frame = build_inner_frame("fd00:cafe::100", "fd00:cafe::200", PG0_MAC_BYTES)
    inject(frame, "encap1")

    after = wait_for_counter("overlay-encap", "packets encapsulated", before + 1)
    assert after > before, (
        f"ENCAPSULATED counter didn't increment "
        f"(before={before} after={after}). Trace:\n{trace()}"
    )


def test_encap_outer_dst_equals_inner_dst(encap_topology):
    """Trace must show outer-dst == inner-dst (the design's central trick)."""
    inner_dst = "fd00:cafe::abcd"
    frame = build_inner_frame("fd00:cafe::100", inner_dst, PG0_MAC_BYTES)
    inject(frame, "encap2")
    wait_for_counter("overlay-encap", "packets encapsulated", 1)

    trace_out = trace()
    # Find the overlay-encap trace line.
    found = False
    for line in trace_out.splitlines():
        if "overlay-encap:" in line and "->" in line and "udp" in line:
            # format: "overlay-encap: tunnel N outer SRC -> DST udp SP -> DP"
            assert inner_dst in line, (
                f"outer dst doesn't match inner dst {inner_dst}. Line: {line}"
            )
            found = True
            break
    assert found, f"no overlay-encap trace line found:\n{trace_out}"


def test_encap_outer_udp_dport_matches_tunnel(encap_topology):
    """Outer UDP dst port equals the configured tunnel dst_port."""
    frame = build_inner_frame("fd00:cafe::100", "fd00:cafe::200", PG0_MAC_BYTES)
    inject(frame, "encap3")
    wait_for_counter("overlay-encap", "packets encapsulated", 1)

    trace_out = trace()
    # Match "udp <sport> -> <dport>"
    m = None
    for line in trace_out.splitlines():
        if "overlay-encap:" in line:
            m = re.search(r"udp\s+(\d+)\s*->\s*(\d+)", line)
            if m:
                break
    assert m, f"no encap udp ports in trace:\n{trace_out}"
    sport, dport = int(m.group(1)), int(m.group(2))
    assert dport == DST_PORT, f"outer UDP dport={dport}, expected {DST_PORT}"
    # Sport must be in the ephemeral range (0xC000-0xFFFF) — entropy bits.
    assert 0xC000 <= sport <= 0xFFFF, f"outer UDP sport={sport} not ephemeral"


def test_pass_through_for_non_matching_src(encap_topology):
    """Inner src outside src_prefix → pass-through, no encap."""
    encap_before = counter("overlay-encap", "packets encapsulated")
    pass_before = counter("overlay-encap", "non-matching-src")

    frame = build_inner_frame("fd00:beef::99", "fd00:cafe::200", PG0_MAC_BYTES)
    inject(frame, "passthru1")

    pass_after = wait_for_counter("overlay-encap", "non-matching-src", pass_before + 1)
    encap_after = counter("overlay-encap", "packets encapsulated")

    assert pass_after > pass_before, (
        f"PASSED_THROUGH counter didn't increment "
        f"(before={pass_before} after={pass_after}). Trace:\n{trace()}"
    )
    assert encap_after == encap_before, (
        f"encap should NOT have fired for non-pod src "
        f"(before={encap_before} after={encap_after})"
    )


@pytest.fixture
def encap_topology_partial_byte_prefix():
    """Variant of encap_topology that arms with a non-byte-aligned
    src-prefix length (/52) so we exercise the partial-byte mask path
    in ip6_address_is_equal_masked()."""
    partial_prefix = "fd00:cafe:0::"
    partial_len = 52  # 13 nibbles of fd00:cafe:0:0... must match
    # Route covers /48 (a superset) so inner_dst is still routable on pg1.
    route_prefix = "fd00:cafe::"
    route_len = 48

    vppctl_unchecked("create", "packet-generator", "interface", "pg0")
    vppctl_unchecked("create", "packet-generator", "interface", "pg1")
    vppctl_unchecked("set", "interface", "mac", "address", "pg0", PG0_MAC)
    vppctl_unchecked("set", "interface", "ip", "address", "pg0", f"{PG0_ADDR}/64")
    vppctl_unchecked("set", "interface", "ip", "address", "pg1", f"{PG1_ADDR}/64")
    vppctl_unchecked("set", "interface", "state", "pg0", "up")
    vppctl_unchecked("set", "interface", "state", "pg1", "up")

    vppctl_unchecked("ip", "neighbor", "pg1", NEXT_HOP, NEXT_HOP_MAC, "static")
    vppctl_unchecked("ip", "route", "add",
                     f"{route_prefix}/{route_len}",
                     "via", NEXT_HOP, "pg1")

    out = vppctl_unchecked("overlay", "enable", "pg1", "dst-port", str(DST_PORT))
    assert "failed" not in out.lower(), f"enable produced: {out!r}"
    out = vppctl_unchecked(
        "overlay", "matcher", "add",
        "src-prefix", f"{partial_prefix}/{partial_len}",
        "nic", "pg1",
    )
    assert "failed" not in out.lower(), f"matcher add produced: {out!r}"

    vppctl_unchecked("trace", "add", "pg-input", "20")

    yield

    vppctl_unchecked("clear", "trace")
    vppctl_unchecked("clear", "errors")
    vppctl_unchecked("overlay", "disable", "pg1", "force")
    vppctl_unchecked("ip", "route", "del",
                     f"{route_prefix}/{route_len}",
                     "via", NEXT_HOP, "pg1")


def test_pass_through_partial_byte_prefix(encap_topology_partial_byte_prefix):
    """src-prefix /52 inside fd00:cafe::/48: an inner src that lies
    inside /48 but outside /52 must be classified as non-matching.

    fd00:cafe:0:1000::1 has bits 49-52 == 0b0001 (top nibble of the 4th
    hextet), while the /52 prefix demands those bits be 0b0000. The
    pre-byte-aligned mask path in ip6_address_is_equal_masked() must
    reject this src."""
    encap_before = counter("overlay-encap", "packets encapsulated")
    pass_before = counter("overlay-encap", "non-matching-src")

    # Inside /48 (fd00:cafe::/48), outside /52 (fd00:cafe:0::/52).
    frame = build_inner_frame("fd00:cafe:0:1000::1", "fd00:cafe::200", PG0_MAC_BYTES)
    inject(frame, "partial_byte_passthru")

    pass_after = wait_for_counter("overlay-encap", "non-matching-src", pass_before + 1)
    encap_after = counter("overlay-encap", "packets encapsulated")

    assert pass_after > pass_before, (
        f"PASSED_THROUGH counter didn't increment for partial-byte "
        f"non-match (before={pass_before} after={pass_after}). "
        f"Trace:\n{trace()}"
    )
    assert encap_after == encap_before, (
        f"encap fired for src outside /52 partial-byte prefix "
        f"(before={encap_before} after={encap_after}). Trace:\n{trace()}"
    )
