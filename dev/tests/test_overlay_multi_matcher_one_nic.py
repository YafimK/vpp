"""N=2 and N=3 matchers on a single NIC.

Each distinct prefix on the same NIC steers matching inner srcs to encap;
non-matching srcs pass through.
"""

import pytest
from conftest import vppctl_unchecked
from overlay_helpers import (
    DST_PORT, enable, disable, matcher_add, show_overlay_nic, cleanup_nic,
    build_inner_frame, counter, inject, wait_for_counter,
)


# Two routes — each prefix needs to be reachable so ip6-rewrite can set
# VLIB_TX = pg1 before overlay-encap runs.
PFX_A = "2001:db8:a::"
PFX_A_LEN = 48
PFX_B = "2001:db8:b::"
PFX_B_LEN = 48
PFX_C = "2001:db8:c::"
PFX_C_LEN = 48

PG0_ADDR = "fd00:abcd::1"
PG1_ADDR = "fd00:dead::1"
NEXT_HOP = "fd00:dead::2"
NEXT_HOP_MAC = "02:fe:00:00:00:02"
PG0_MAC = "02:fe:00:00:00:01"
PG0_MAC_BYTES = bytes.fromhex(PG0_MAC.replace(":", ""))


@pytest.fixture
def multi_matcher_topology():
    vppctl_unchecked("create", "packet-generator", "interface", "pg0")
    vppctl_unchecked("create", "packet-generator", "interface", "pg1")
    vppctl_unchecked("set", "interface", "mac", "address", "pg0", PG0_MAC)
    vppctl_unchecked("set", "interface", "ip", "address", "pg0", f"{PG0_ADDR}/64")
    vppctl_unchecked("set", "interface", "ip", "address", "pg1", f"{PG1_ADDR}/64")
    vppctl_unchecked("set", "interface", "state", "pg0", "up")
    vppctl_unchecked("set", "interface", "state", "pg1", "up")
    vppctl_unchecked("ip", "neighbor", "pg1", NEXT_HOP, NEXT_HOP_MAC, "static")

    for p, l in ((PFX_A, PFX_A_LEN), (PFX_B, PFX_B_LEN), (PFX_C, PFX_C_LEN)):
        vppctl_unchecked("ip", "route", "add", f"{p}/{l}", "via", NEXT_HOP, "pg1")

    cleanup_nic("pg1")
    out = enable("pg1")
    assert "failed" not in out.lower() and "error" not in out.lower(), out

    vppctl_unchecked("trace", "add", "pg-input", "20")

    yield

    vppctl_unchecked("clear", "trace")
    vppctl_unchecked("clear", "errors")
    cleanup_nic("pg1")
    for p, l in ((PFX_A, PFX_A_LEN), (PFX_B, PFX_B_LEN), (PFX_C, PFX_C_LEN)):
        vppctl_unchecked("ip", "route", "del", f"{p}/{l}", "via", NEXT_HOP, "pg1")


def test_two_matchers_each_encap(multi_matcher_topology):
    out = matcher_add(PFX_A, PFX_A_LEN, "pg1")
    assert "failed" not in out.lower(), out
    out = matcher_add(PFX_B, PFX_B_LEN, "pg1")
    assert "failed" not in out.lower(), out

    before = counter("overlay-encap", "packets encapsulated")
    inject(build_inner_frame("2001:db8:a::1", "2001:db8:a::200", PG0_MAC_BYTES), "n2_a")
    after_a = wait_for_counter("overlay-encap", "packets encapsulated", before + 1)
    assert after_a > before, f"encap A didn't fire (before={before} after={after_a})"

    inject(build_inner_frame("2001:db8:b::1", "2001:db8:b::200", PG0_MAC_BYTES), "n2_b")
    after_b = wait_for_counter("overlay-encap", "packets encapsulated", after_a + 1)
    assert after_b > after_a, f"encap B didn't fire (after_a={after_a} after_b={after_b})"


def test_three_matchers_each_encap(multi_matcher_topology):
    for p, l in ((PFX_A, PFX_A_LEN), (PFX_B, PFX_B_LEN), (PFX_C, PFX_C_LEN)):
        out = matcher_add(p, l, "pg1")
        assert "failed" not in out.lower(), out

    base = counter("overlay-encap", "packets encapsulated")
    for idx, (p_src, p_dst) in enumerate((
        ("2001:db8:a::1", "2001:db8:a::200"),
        ("2001:db8:b::1", "2001:db8:b::200"),
        ("2001:db8:c::1", "2001:db8:c::200"),
    )):
        inject(build_inner_frame(p_src, p_dst, PG0_MAC_BYTES), f"n3_{idx}")
        target = base + idx + 1
        got = wait_for_counter("overlay-encap", "packets encapsulated", target)
        assert got >= target, f"encap {idx} didn't fire (got={got} target={target})"


def test_three_matchers_non_matching_passes_through(multi_matcher_topology):
    for p, l in ((PFX_A, PFX_A_LEN), (PFX_B, PFX_B_LEN), (PFX_C, PFX_C_LEN)):
        out = matcher_add(p, l, "pg1")
        assert "failed" not in out.lower(), out

    encap_before = counter("overlay-encap", "packets encapsulated")
    pass_before = counter("overlay-encap", "non-matching-src")

    # Inner src outside all 3 prefixes; routed to pg1 via PFX_A's route.
    inject(build_inner_frame("fd00:beef::99", "2001:db8:a::200", PG0_MAC_BYTES), "n3_pass")
    pass_after = wait_for_counter("overlay-encap", "non-matching-src", pass_before + 1)
    encap_after = counter("overlay-encap", "packets encapsulated")

    assert pass_after > pass_before, (
        f"PASSED_THROUGH didn't increment "
        f"(before={pass_before} after={pass_after})"
    )
    assert encap_after == encap_before, (
        f"encap fired for non-matching src "
        f"(before={encap_before} after={encap_after})"
    )
