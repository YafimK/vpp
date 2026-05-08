"""Multi-NIC encap data-plane tests (Slice C-2 CLI).

Topology:

    pg0 (ingress, no overlay)
      |
      +-- ip6-fib: route_a -> pg1 via NEXT_HOP_A
      +-- ip6-fib: route_b -> pg2 via NEXT_HOP_B

    pg1 (overlay-enabled, egress for tenant A)
    pg2 (overlay-enabled, egress for tenant B)

Shared-prefix scenario: both pg1 and pg2 carry the same matcher prefix.
Per-NIC matcher scenario: pg1 and pg2 each carry a distinct matcher.
"""
import pytest
from conftest import vppctl, vppctl_unchecked
from overlay_helpers import (
    build_inner_frame, counter, inject, trace, wait_for_counter,
)


DST_PORT = 6635

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

PG0_MAC = "02:fe:00:00:00:01"
PG0_MAC_BYTES = bytes.fromhex(PG0_MAC.replace(":", ""))


def _bring_up_pg(name: str, addr: str, mac: str | None = None) -> None:
    vppctl_unchecked("create", "packet-generator", "interface", name)
    if mac is not None:
        vppctl_unchecked("set", "interface", "mac", "address", name, mac)
    vppctl_unchecked("set", "interface", "ip", "address", name, f"{addr}/64")
    vppctl_unchecked("set", "interface", "state", name, "up")


# ---------------------------------------------------------------------------
# Shared matcher across two NICs (one overlay matcher add, two NICs)
# ---------------------------------------------------------------------------


@pytest.fixture
def shared_matcher_topology():
    _bring_up_pg("pg0", PG0_ADDR, PG0_MAC)
    _bring_up_pg("pg1", PG1_ADDR)
    _bring_up_pg("pg2", PG2_ADDR)

    vppctl_unchecked("ip", "neighbor", "pg1", NEXT_HOP_A, NEXT_HOP_A_MAC, "static")
    vppctl_unchecked("ip", "neighbor", "pg2", NEXT_HOP_B, NEXT_HOP_B_MAC, "static")

    shared_prefix = "2001:db8::"
    shared_len = 32
    vppctl_unchecked("ip", "route", "add",
                     f"{ROUTE_A_PREFIX}/{ROUTE_A_LEN}",
                     "via", NEXT_HOP_A, "pg1")
    vppctl_unchecked("ip", "route", "add",
                     f"{ROUTE_B_PREFIX}/{ROUTE_B_LEN}",
                     "via", NEXT_HOP_B, "pg2")

    for nic in ("pg1", "pg2"):
        out = vppctl_unchecked("overlay", "enable", nic, "dst-port", str(DST_PORT))
        assert "failed" not in out.lower(), out
    out = vppctl_unchecked(
        "overlay", "matcher", "add",
        "src-prefix", f"{shared_prefix}/{shared_len}",
        "nic", "pg1", "nic", "pg2",
    )
    assert "failed" not in out.lower(), out

    vppctl_unchecked("trace", "add", "pg-input", "20")

    yield

    vppctl_unchecked("clear", "trace")
    vppctl_unchecked("clear", "errors")
    vppctl_unchecked("overlay", "disable", "pg1", "force")
    vppctl_unchecked("overlay", "disable", "pg2", "force")
    vppctl_unchecked("ip", "route", "del",
                     f"{ROUTE_A_PREFIX}/{ROUTE_A_LEN}",
                     "via", NEXT_HOP_A, "pg1")
    vppctl_unchecked("ip", "route", "del",
                     f"{ROUTE_B_PREFIX}/{ROUTE_B_LEN}",
                     "via", NEXT_HOP_B, "pg2")


def test_shared_matcher_visible_on_both_nics(shared_matcher_topology):
    show = vppctl("show", "overlay")
    assert "pg1" in show and "pg2" in show, show


def test_shared_matcher_encap_via_pg1(shared_matcher_topology):
    before = counter("overlay-encap", "packets encapsulated")
    frame = build_inner_frame("2001:db8:e:e::100", "2001:db8:e:e::200", PG0_MAC_BYTES)
    inject(frame, "shared_pg1")
    after = wait_for_counter("overlay-encap", "packets encapsulated", before + 1)
    assert after > before, (
        f"ENCAPSULATED via pg1 didn't increment "
        f"(before={before} after={after}). Trace:\n{trace()}"
    )


def test_shared_matcher_encap_via_pg2(shared_matcher_topology):
    before = counter("overlay-encap", "packets encapsulated")
    frame = build_inner_frame("2001:db8:50:50::100", "2001:db8:50:50::200", PG0_MAC_BYTES)
    inject(frame, "shared_pg2")
    after = wait_for_counter("overlay-encap", "packets encapsulated", before + 1)
    assert after > before, (
        f"ENCAPSULATED via pg2 didn't increment "
        f"(before={before} after={after}). Trace:\n{trace()}"
    )


# ---------------------------------------------------------------------------
# Per-NIC matchers (tenant separation): pg1 has matcher A, pg2 has matcher B
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

    for nic in ("pg1", "pg2"):
        out = vppctl_unchecked("overlay", "enable", nic, "dst-port", str(DST_PORT))
        assert "failed" not in out.lower(), out
    out = vppctl_unchecked(
        "overlay", "matcher", "add",
        "src-prefix", f"{PREFIX_A}/{PREFIX_A_LEN}",
        "nic", "pg1",
    )
    assert "failed" not in out.lower(), out
    out = vppctl_unchecked(
        "overlay", "matcher", "add",
        "src-prefix", f"{PREFIX_B}/{PREFIX_B_LEN}",
        "nic", "pg2",
    )
    assert "failed" not in out.lower(), out

    vppctl_unchecked("trace", "add", "pg-input", "20")

    yield

    vppctl_unchecked("clear", "trace")
    vppctl_unchecked("clear", "errors")
    vppctl_unchecked("overlay", "disable", "pg1", "force")
    vppctl_unchecked("overlay", "disable", "pg2", "force")
    vppctl_unchecked("ip", "route", "del",
                     f"{ROUTE_A_PREFIX}/{ROUTE_A_LEN}",
                     "via", NEXT_HOP_A, "pg1")
    vppctl_unchecked("ip", "route", "del",
                     f"{ROUTE_B_PREFIX}/{ROUTE_B_LEN}",
                     "via", NEXT_HOP_B, "pg2")


def test_tenant_show_lists_both_prefixes(tenant_topology):
    show = vppctl("show", "overlay")
    assert PREFIX_A in show and PREFIX_B in show, show


def test_tenant_encap_a_via_pg1(tenant_topology):
    before = counter("overlay-encap", "packets encapsulated")
    frame = build_inner_frame("2001:db8:e:e::1", "2001:db8:e:e::200", PG0_MAC_BYTES)
    inject(frame, "tenant_pg1_match")
    after = wait_for_counter("overlay-encap", "packets encapsulated", before + 1)
    assert after > before, (
        f"ENCAPSULATED via pg1 (tenant A) didn't increment "
        f"(before={before} after={after}). Trace:\n{trace()}"
    )


def test_tenant_encap_b_via_pg2(tenant_topology):
    before = counter("overlay-encap", "packets encapsulated")
    frame = build_inner_frame("2001:db8:50:50::1", "2001:db8:50:50::200", PG0_MAC_BYTES)
    inject(frame, "tenant_pg2_match")
    after = wait_for_counter("overlay-encap", "packets encapsulated", before + 1)
    assert after > before, (
        f"ENCAPSULATED via pg2 (tenant B) didn't increment "
        f"(before={before} after={after}). Trace:\n{trace()}"
    )


def test_tenant_wrong_prefix_passes_through_pg2(tenant_topology):
    """src in PREFIX_A routed to pg2 must NOT encap (pg2 only matches B)."""
    encap_before = counter("overlay-encap", "packets encapsulated")
    pass_before = counter("overlay-encap", "non-matching-src")

    frame = build_inner_frame("2001:db8:e:e::1", "2001:db8:50:50::200", PG0_MAC_BYTES)
    inject(frame, "tenant_wrong_prefix")

    pass_after = wait_for_counter("overlay-encap", "non-matching-src", pass_before + 1)
    encap_after = counter("overlay-encap", "packets encapsulated")

    assert pass_after > pass_before, (
        f"PASSED_THROUGH didn't increment for cross-tenant traffic on pg2 "
        f"(before={pass_before} after={pass_after}). Trace:\n{trace()}"
    )
    assert encap_after == encap_before, (
        f"encap should NOT have fired for src outside pg2's matchers "
        f"(before={encap_before} after={encap_after}). Trace:\n{trace()}"
    )


def test_tenant_non_overlay_passes_through(tenant_topology):
    encap_before = counter("overlay-encap", "packets encapsulated")
    pass_before = counter("overlay-encap", "non-matching-src")

    frame = build_inner_frame("fd00:abcd::99", "2001:db8:e:e::200", PG0_MAC_BYTES)
    inject(frame, "tenant_non_overlay")

    pass_after = wait_for_counter("overlay-encap", "non-matching-src", pass_before + 1)
    encap_after = counter("overlay-encap", "packets encapsulated")

    assert pass_after > pass_before, (
        f"PASSED_THROUGH didn't increment for non-overlay traffic "
        f"(before={pass_before} after={pass_after}). Trace:\n{trace()}"
    )
    assert encap_after == encap_before, (
        f"encap should NOT have fired for non-overlay src "
        f"(before={encap_before} after={encap_after}). Trace:\n{trace()}"
    )


def test_tenant_disable_one_keeps_other(tenant_topology):
    out = vppctl_unchecked("overlay", "disable", "pg1", "force")
    assert "failed" not in out.lower(), out
    show = vppctl("show", "overlay")
    assert "pg2" in show, show
    assert PREFIX_B in show, show
    # Re-enable so the fixture teardown's disable pg1 is a no-op success.
    out = vppctl_unchecked("overlay", "enable", "pg1", "dst-port", str(DST_PORT))
    assert "failed" not in out.lower(), out
