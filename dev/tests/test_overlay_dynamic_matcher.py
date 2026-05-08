"""Feature arcs stay attached across matcher add/del.

enable() must install both `overlay-encap` (ip6-output) and
`overlay-bypass` (ip6-unicast). Adding/deleting matchers must NOT detach
the feature arcs — only matcher state changes.
"""
import re
import socket
import struct
import time

import pytest
from conftest import vppctl, vppctl_unchecked
from overlay_helpers import (
    DST_PORT, enable, matcher_add, matcher_del, show_features, cleanup_nic,
)


PFX = "2001:db8:d::"
PFX_LEN = 48

PG0_ADDR = "fd00:abcd::1"
PG1_ADDR = "fd00:dead::1"
NEXT_HOP = "fd00:dead::2"
NEXT_HOP_MAC = "02:fe:00:00:00:02"
PG0_MAC = "02:fe:00:00:00:01"
PG0_MAC_BYTES = bytes.fromhex(PG0_MAC.replace(":", ""))


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


def _assert_features_attached(nic):
    out = show_features(nic)
    assert "overlay-encap" in out, (
        f"overlay-encap not on {nic} feature list:\n{out}"
    )
    assert "overlay-bypass" in out, (
        f"overlay-bypass not on {nic} feature list:\n{out}"
    )


@pytest.fixture
def dyn_topology():
    vppctl_unchecked("create", "packet-generator", "interface", "pg0")
    vppctl_unchecked("create", "packet-generator", "interface", "pg1")
    vppctl_unchecked("set", "interface", "mac", "address", "pg0", PG0_MAC)
    vppctl_unchecked("set", "interface", "ip", "address", "pg0", f"{PG0_ADDR}/64")
    vppctl_unchecked("set", "interface", "ip", "address", "pg1", f"{PG1_ADDR}/64")
    vppctl_unchecked("set", "interface", "state", "pg0", "up")
    vppctl_unchecked("set", "interface", "state", "pg1", "up")
    vppctl_unchecked("ip", "neighbor", "pg1", NEXT_HOP, NEXT_HOP_MAC, "static")
    vppctl_unchecked("ip", "route", "add",
                     f"{PFX}/{PFX_LEN}", "via", NEXT_HOP, "pg1")

    cleanup_nic("pg1")
    out = enable("pg1")
    assert "failed" not in out.lower(), out

    vppctl_unchecked("trace", "add", "pg-input", "20")

    yield

    vppctl_unchecked("clear", "trace")
    vppctl_unchecked("clear", "errors")
    cleanup_nic("pg1")
    vppctl_unchecked("ip", "route", "del",
                     f"{PFX}/{PFX_LEN}", "via", NEXT_HOP, "pg1")


def test_features_attached_after_enable_no_matchers(dyn_topology):
    _assert_features_attached("pg1")

    encap_before = _counter("packets encapsulated")
    pass_before = _counter("non-matching-src")
    _inject(_build_inner_frame("2001:db8:d::1", "2001:db8:d::200"), "dyn_pre")
    pass_after = _wait_for_counter("non-matching-src", pass_before + 1)
    encap_after = _counter("packets encapsulated")
    assert pass_after > pass_before, (
        f"PASSED_THROUGH didn't increment for no-matchers traffic "
        f"(before={pass_before} after={pass_after})"
    )
    assert encap_after == encap_before, (
        f"encap fired with no matchers configured "
        f"(before={encap_before} after={encap_after})"
    )

    # Re-assert after traffic.
    _assert_features_attached("pg1")


def test_features_persist_across_matcher_add_del(dyn_topology):
    _assert_features_attached("pg1")

    out = matcher_add(PFX, PFX_LEN, "pg1")
    assert "failed" not in out.lower(), out
    _assert_features_attached("pg1")

    encap_before = _counter("packets encapsulated")
    _inject(_build_inner_frame("2001:db8:d::1", "2001:db8:d::200"), "dyn_match")
    encap_after = _wait_for_counter("packets encapsulated", encap_before + 1)
    assert encap_after > encap_before, (
        f"encap didn't fire after matcher add "
        f"(before={encap_before} after={encap_after})"
    )

    out = matcher_del(PFX, PFX_LEN, "pg1")
    assert "failed" not in out.lower(), out
    _assert_features_attached("pg1")

    pass_before = _counter("non-matching-src")
    _inject(_build_inner_frame("2001:db8:d::1", "2001:db8:d::200"), "dyn_post")
    pass_after = _wait_for_counter("non-matching-src", pass_before + 1)
    assert pass_after > pass_before, (
        f"PASSED_THROUGH didn't increment after matcher del "
        f"(before={pass_before} after={pass_after})"
    )
