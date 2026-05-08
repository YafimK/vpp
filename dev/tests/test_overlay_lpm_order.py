"""Slice C-2: longest-prefix-match ordering of matchers.

Control plane sorts matchers by prefix_len descending, so an inner src
that falls inside both /32 and /48 prefixes hits the /48 matcher first.

Also covers duplicate-add rejection: re-adding the exact same
(prefix, len) returns an error.
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


PFX_OUTER = "2001:db8::"
PFX_OUTER_LEN = 32
PFX_INNER = "2001:db8:cafe::"
PFX_INNER_LEN = 48

# Cover both /32 and /48 with one /32 route on pg1 so the inner dst is
# reachable regardless of which matcher's hot-path is taken.
ROUTE_PFX = "2001:db8::"
ROUTE_PFX_LEN = 32

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


def _trace():
    return _strip_ansi(vppctl_unchecked("show", "trace"))


@pytest.fixture
def lpm_topology():
    vppctl_unchecked("create", "packet-generator", "interface", "pg0")
    vppctl_unchecked("create", "packet-generator", "interface", "pg1")
    vppctl_unchecked("set", "interface", "mac", "address", "pg0", PG0_MAC)
    vppctl_unchecked("set", "interface", "ip", "address", "pg0", f"{PG0_ADDR}/64")
    vppctl_unchecked("set", "interface", "ip", "address", "pg1", f"{PG1_ADDR}/64")
    vppctl_unchecked("set", "interface", "state", "pg0", "up")
    vppctl_unchecked("set", "interface", "state", "pg1", "up")
    vppctl_unchecked("ip", "neighbor", "pg1", NEXT_HOP, NEXT_HOP_MAC, "static")
    vppctl_unchecked("ip", "route", "add",
                     f"{ROUTE_PFX}/{ROUTE_PFX_LEN}", "via", NEXT_HOP, "pg1")

    cleanup_nic("pg1")
    out = enable("pg1")
    assert "failed" not in out.lower(), out

    vppctl_unchecked("trace", "add", "pg-input", "20")
    vppctl_unchecked("trace", "add", "overlay-encap", "20")

    yield

    vppctl_unchecked("clear", "trace")
    vppctl_unchecked("clear", "errors")
    cleanup_nic("pg1")
    vppctl_unchecked("ip", "route", "del",
                     f"{ROUTE_PFX}/{ROUTE_PFX_LEN}", "via", NEXT_HOP, "pg1")


def test_lpm_inner_prefix_wins(lpm_topology):
    # Add /32 first, then /48 — control plane must sort desc by len.
    out = matcher_add(PFX_OUTER, PFX_OUTER_LEN, "pg1")
    assert "failed" not in out.lower(), out
    out = matcher_add(PFX_INNER, PFX_INNER_LEN, "pg1")
    assert "failed" not in out.lower(), out

    # Inner src in /48 — should match the /48 matcher (LPM).
    before = _counter("packets encapsulated")
    _inject(_build_inner_frame("2001:db8:cafe::1",
                               "2001:db8:cafe::200"), "lpm_inner")
    after = _wait_for_counter("packets encapsulated", before + 1)
    assert after > before, f"encap didn't fire for /48 match (before={before} after={after})"


def test_lpm_outer_prefix_falls_back(lpm_topology):
    out = matcher_add(PFX_OUTER, PFX_OUTER_LEN, "pg1")
    assert "failed" not in out.lower(), out
    out = matcher_add(PFX_INNER, PFX_INNER_LEN, "pg1")
    assert "failed" not in out.lower(), out

    # Inner src in /32 but outside /48 — should match the /32 matcher.
    before = _counter("packets encapsulated")
    _inject(_build_inner_frame("2001:db8:beef::1",
                               "2001:db8:beef::200"), "lpm_outer")
    after = _wait_for_counter("packets encapsulated", before + 1)
    assert after > before, f"encap didn't fire for /32 fallback (before={before} after={after})"


def test_lpm_show_orders_matchers_desc(lpm_topology):
    # Add in shorter-first order to verify the show output reflects sort.
    out = matcher_add(PFX_OUTER, PFX_OUTER_LEN, "pg1")
    assert "failed" not in out.lower(), out
    out = matcher_add(PFX_INNER, PFX_INNER_LEN, "pg1")
    assert "failed" not in out.lower(), out

    show = show_overlay_nic("pg1")
    # Both prefixes present.
    assert PFX_OUTER in show, show
    assert PFX_INNER in show, show
    # /48 listed before /32 (sorted desc by prefix_len).
    inner_pos = show.find(PFX_INNER)
    outer_pos = show.find(PFX_OUTER)
    assert inner_pos < outer_pos, (
        f"/48 should appear before /32 in show output (sort desc):\n{show}"
    )


def test_duplicate_matcher_add_rejected(lpm_topology):
    out = matcher_add(PFX_INNER, PFX_INNER_LEN, "pg1")
    assert "failed" not in out.lower(), out
    out = matcher_add(PFX_INNER, PFX_INNER_LEN, "pg1")
    low = out.lower()
    assert ("already" in low or "exists" in low or "duplicate" in low
            or "failed" in low or "error" in low), out

    # Still exactly one matcher with that prefix.
    show = show_overlay_nic("pg1")
    assert show.count(PFX_INNER) == 1, show
