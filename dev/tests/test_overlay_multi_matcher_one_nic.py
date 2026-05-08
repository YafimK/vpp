"""Slice C-2: N=2 and N=3 matchers on a single NIC.

Each distinct prefix on the same NIC steers matching inner srcs to encap;
non-matching srcs pass through. Reuses the encap pg0/pg1 topology shape
from test_overlay_encap.py.
"""
import re
import socket
import struct
import time

import pytest
from conftest import vppctl, vppctl_unchecked
from overlay_helpers import (
    DST_PORT, enable, disable, matcher_add, show_overlay_nic, cleanup_nic,
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


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(s):
    return _ANSI_RE.sub("", s)


def _build_inner_frame(inner_src, inner_dst):
    src = socket.inet_pton(socket.AF_INET6, inner_src)
    dst = socket.inet_pton(socket.AF_INET6, inner_dst)
    inner_ip6 = struct.pack("!IHBB", (6 << 28), 0, 59, 64) + src + dst
    eth = PG0_MAC_BYTES + b"\x00" * 6 + b"\x86\xdd"
    return eth + inner_ip6


def _inject(frame, name):
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


def _counter(substring):
    out = vppctl("show", "errors")
    for line in out.splitlines():
        low = line.lower()
        if "overlay-encap" in low and substring.lower() in low:
            try:
                return int(line.split()[0])
            except (ValueError, IndexError):
                return 0
    return 0


def _wait_for_counter(substring, target, timeout=1.0):
    deadline = time.time() + timeout
    val = _counter(substring)
    while val < target and time.time() < deadline:
        time.sleep(0.05)
        val = _counter(substring)
    return val


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

    before = _counter("packets encapsulated")
    _inject(_build_inner_frame("2001:db8:a::1", "2001:db8:a::200"), "n2_a")
    after_a = _wait_for_counter("packets encapsulated", before + 1)
    assert after_a > before, f"encap A didn't fire (before={before} after={after_a})"

    _inject(_build_inner_frame("2001:db8:b::1", "2001:db8:b::200"), "n2_b")
    after_b = _wait_for_counter("packets encapsulated", after_a + 1)
    assert after_b > after_a, f"encap B didn't fire (after_a={after_a} after_b={after_b})"


def test_three_matchers_each_encap(multi_matcher_topology):
    for p, l in ((PFX_A, PFX_A_LEN), (PFX_B, PFX_B_LEN), (PFX_C, PFX_C_LEN)):
        out = matcher_add(p, l, "pg1")
        assert "failed" not in out.lower(), out

    base = _counter("packets encapsulated")
    for idx, (p_src, p_dst) in enumerate((
        ("2001:db8:a::1", "2001:db8:a::200"),
        ("2001:db8:b::1", "2001:db8:b::200"),
        ("2001:db8:c::1", "2001:db8:c::200"),
    )):
        _inject(_build_inner_frame(p_src, p_dst), f"n3_{idx}")
        target = base + idx + 1
        got = _wait_for_counter("packets encapsulated", target)
        assert got >= target, f"encap {idx} didn't fire (got={got} target={target})"


def test_three_matchers_non_matching_passes_through(multi_matcher_topology):
    for p, l in ((PFX_A, PFX_A_LEN), (PFX_B, PFX_B_LEN), (PFX_C, PFX_C_LEN)):
        out = matcher_add(p, l, "pg1")
        assert "failed" not in out.lower(), out

    encap_before = _counter("packets encapsulated")
    pass_before = _counter("non-matching-src")

    # Inner src outside all 3 prefixes; routed to pg1 via PFX_A's route.
    _inject(_build_inner_frame("fd00:beef::99", "2001:db8:a::200"), "n3_pass")
    pass_after = _wait_for_counter("non-matching-src", pass_before + 1)
    encap_after = _counter("packets encapsulated")

    assert pass_after > pass_before, (
        f"PASSED_THROUGH didn't increment "
        f"(before={pass_before} after={pass_after})"
    )
    assert encap_after == encap_before, (
        f"encap fired for non-matching src "
        f"(before={encap_before} after={encap_after})"
    )
