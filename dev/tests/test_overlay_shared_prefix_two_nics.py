"""Slice C-2: one matcher prefix scoped to two NICs in a single CLI call.

`overlay matcher add src-prefix X nic NIC_A nic NIC_B` adds the same
matcher to both NICs' inline arrays. Encap fires on each NIC independently.
"""
import re
import socket
import struct
import time

import pytest
from conftest import vppctl, vppctl_unchecked
from overlay_helpers import (
    DST_PORT, enable, matcher_add, show_overlay_nic, cleanup_nic,
)


SHARED_PFX = "2001:db8:abcd::"
SHARED_PFX_LEN = 48

# Two non-overlapping /64s inside the /48 — each routed to a different NIC.
ROUTE_A = "2001:db8:abcd:1::"
ROUTE_A_LEN = 64
ROUTE_B = "2001:db8:abcd:2::"
ROUTE_B_LEN = 64

PG0_ADDR = "fd00:abcd::1"
PG1_ADDR = "fd00:dead::1"
PG2_ADDR = "fd00:beef::1"
NEXT_HOP_A = "fd00:dead::2"
NEXT_HOP_A_MAC = "02:fe:00:00:00:02"
NEXT_HOP_B = "fd00:beef::2"
NEXT_HOP_B_MAC = "02:fe:00:00:00:03"
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
def shared_prefix_topology():
    vppctl_unchecked("create", "packet-generator", "interface", "pg0")
    vppctl_unchecked("create", "packet-generator", "interface", "pg1")
    vppctl_unchecked("create", "packet-generator", "interface", "pg2")
    vppctl_unchecked("set", "interface", "mac", "address", "pg0", PG0_MAC)
    vppctl_unchecked("set", "interface", "ip", "address", "pg0", f"{PG0_ADDR}/64")
    vppctl_unchecked("set", "interface", "ip", "address", "pg1", f"{PG1_ADDR}/64")
    vppctl_unchecked("set", "interface", "ip", "address", "pg2", f"{PG2_ADDR}/64")
    vppctl_unchecked("set", "interface", "state", "pg0", "up")
    vppctl_unchecked("set", "interface", "state", "pg1", "up")
    vppctl_unchecked("set", "interface", "state", "pg2", "up")

    vppctl_unchecked("ip", "neighbor", "pg1", NEXT_HOP_A, NEXT_HOP_A_MAC, "static")
    vppctl_unchecked("ip", "neighbor", "pg2", NEXT_HOP_B, NEXT_HOP_B_MAC, "static")
    vppctl_unchecked("ip", "route", "add",
                     f"{ROUTE_A}/{ROUTE_A_LEN}", "via", NEXT_HOP_A, "pg1")
    vppctl_unchecked("ip", "route", "add",
                     f"{ROUTE_B}/{ROUTE_B_LEN}", "via", NEXT_HOP_B, "pg2")

    cleanup_nic("pg1")
    cleanup_nic("pg2")
    out = enable("pg1")
    assert "failed" not in out.lower(), out
    out = enable("pg2")
    assert "failed" not in out.lower(), out

    vppctl_unchecked("trace", "add", "pg-input", "20")

    yield

    vppctl_unchecked("clear", "trace")
    vppctl_unchecked("clear", "errors")
    cleanup_nic("pg1")
    cleanup_nic("pg2")
    vppctl_unchecked("ip", "route", "del",
                     f"{ROUTE_A}/{ROUTE_A_LEN}", "via", NEXT_HOP_A, "pg1")
    vppctl_unchecked("ip", "route", "del",
                     f"{ROUTE_B}/{ROUTE_B_LEN}", "via", NEXT_HOP_B, "pg2")


def test_shared_prefix_visible_on_both_nics(shared_prefix_topology):
    out = matcher_add(SHARED_PFX, SHARED_PFX_LEN, "pg1", "pg2")
    assert "failed" not in out.lower() and "error" not in out.lower(), out

    show_a = show_overlay_nic("pg1")
    show_b = show_overlay_nic("pg2")
    assert SHARED_PFX in show_a, show_a
    assert SHARED_PFX in show_b, show_b


def test_shared_prefix_encap_on_each_nic(shared_prefix_topology):
    out = matcher_add(SHARED_PFX, SHARED_PFX_LEN, "pg1", "pg2")
    assert "failed" not in out.lower(), out

    before = _counter("packets encapsulated")

    # Routed to pg1 (ROUTE_A); inner src in shared /48.
    _inject(_build_inner_frame("2001:db8:abcd:1::1",
                               "2001:db8:abcd:1::200"), "shared_pg1")
    after_pg1 = _wait_for_counter("packets encapsulated", before + 1)
    assert after_pg1 > before, (
        f"encap on pg1 didn't fire (before={before} after={after_pg1})"
    )

    # Routed to pg2 (ROUTE_B); inner src in same shared /48.
    _inject(_build_inner_frame("2001:db8:abcd:2::1",
                               "2001:db8:abcd:2::200"), "shared_pg2")
    after_pg2 = _wait_for_counter("packets encapsulated", after_pg1 + 1)
    assert after_pg2 > after_pg1, (
        f"encap on pg2 didn't fire (after_pg1={after_pg1} after_pg2={after_pg2})"
    )
