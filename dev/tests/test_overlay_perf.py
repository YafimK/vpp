"""Overlay perf smoke microbench — local docker harness only.

This is a SMOKE microbench, NOT a precision benchmark. It is intended to
catch gross C-level regressions (think 2x slower) before code lands at
the Azure validation gate. The numbers it produces are NOT comparable
across machines: docker on Apple Silicon runs an x86_64 VPP under qemu
emulation, so absolute cyc/pkt values are inflated relative to the
reference Azure baseline (encap ~77, bypass ~25 cyc/pkt on Skylake).
What stays stable is the *order of magnitude* on the same host.

Method:
  - Arm overlay-encap on pg1 (encap egress) with a route from pg0.
  - Arm overlay-bypass on pg0 with an SR localsid behind it (decap path).
  - For each direction, in its own fixture:
      * `clear runtime`
      * inject N frames via packet-generator (single stream, limit=N)
      * poll error counters until N frames have been processed
      * parse the matching row of `show runtime`; the "Clocks" column is
        already cyc/pkt in VPP's output.
  - Assert cyc/pkt < a loose ceiling. Ceilings are configurable via
        OVERLAY_PERF_ENCAP_MAX  (default: 160)
        OVERLAY_PERF_BYPASS_MAX (default:  60)
        OVERLAY_PERF_N          (default: 100000 frames per direction)

Limitations:
  - Won't catch sub-50% regressions reliably under qemu — TSC variance
    inside emulated x86_64 is significant. The ceilings are loose for
    the same reason.
  - Skipped by default in fast iterations: run with `pytest -m perf`,
    skip with `pytest -m 'not perf'`.
"""

import os
import re
import socket
import struct

import pytest
from conftest import vppctl, vppctl_unchecked
from overlay_helpers import counter, strip_ansi, wait_for_counter


# ---------------------------------------------------------------------------
# Tunables (env-overridable)
# ---------------------------------------------------------------------------

N_FRAMES = int(os.environ.get("OVERLAY_PERF_N", "100000"))
ENCAP_MAX = float(os.environ.get("OVERLAY_PERF_ENCAP_MAX", "160"))
BYPASS_MAX = float(os.environ.get("OVERLAY_PERF_BYPASS_MAX", "60"))

# Generous wait so qemu-emulated VPP can drain the burst.
DRAIN_TIMEOUT_S = float(os.environ.get("OVERLAY_PERF_DRAIN_TIMEOUT", "60"))


pytestmark = pytest.mark.perf


# ---------------------------------------------------------------------------
# show runtime parsing
# ---------------------------------------------------------------------------


def _runtime_clocks_per_vec(node: str) -> tuple[int, int, float]:
    """Return (calls, vectors, clocks_per_vec) for `node` from
    `show runtime`. The Clocks column in VPP's `show runtime` is already
    cyc/pkt (clocks per vector element)."""
    out = strip_ansi(vppctl("show", "runtime"))
    for line in out.splitlines():
        # Node name may be padded; match on word-boundary at line start.
        if not line.startswith(node):
            continue
        # "Name State Calls Vectors Suspends Clocks Vectors/Call"
        # Some VPP versions have the optional "State" column ("active" or
        # blank). Tolerate both by indexing from the right.
        parts = line.split()
        if len(parts) < 6:
            continue
        try:
            # Right-anchored: vec_per_call, clocks, suspends, vectors, calls
            vec_per_call = float(parts[-1])
            clocks = float(parts[-2])
            # parts[-3] is suspends — unused
            vectors = int(parts[-4])
            calls = int(parts[-5])
        except (ValueError, IndexError):
            continue
        # Sanity: vec_per_call should be plausible.
        _ = vec_per_call
        return calls, vectors, clocks
    pytest.fail(
        f"node '{node}' not found in `show runtime`:\n{out}"
    )


def _ip6(s: str) -> bytes:
    return socket.inet_pton(socket.AF_INET6, s)


# ===========================================================================
# Encap microbench
# ===========================================================================

ENCAP_DST_PORT = 6635
ENCAP_LOCAL = "fd00:cafe::1"
ENCAP_POD_PREFIX = "fd00:cafe::"
ENCAP_POD_LEN = 48
ENCAP_PG0_ADDR = "fd00:beef::1"
ENCAP_PG1_ADDR = "fd00:dead::1"
ENCAP_NEXTHOP = "fd00:dead::2"
ENCAP_NEXTHOP_MAC = "02:fe:00:00:00:02"
ENCAP_PG0_MAC = "02:fe:00:00:00:01"


@pytest.fixture
def encap_perf_topology():
    vppctl_unchecked("create", "packet-generator", "interface", "pg0")
    vppctl_unchecked("create", "packet-generator", "interface", "pg1")
    vppctl_unchecked("set", "interface", "mac", "address", "pg0", ENCAP_PG0_MAC)
    vppctl_unchecked("set", "interface", "ip", "address",
                     "pg0", f"{ENCAP_PG0_ADDR}/64")
    vppctl_unchecked("set", "interface", "ip", "address",
                     "pg1", f"{ENCAP_PG1_ADDR}/64")
    vppctl_unchecked("set", "interface", "state", "pg0", "up")
    vppctl_unchecked("set", "interface", "state", "pg1", "up")
    vppctl_unchecked("ip", "neighbor", "pg1",
                     ENCAP_NEXTHOP, ENCAP_NEXTHOP_MAC, "static")
    vppctl_unchecked("ip", "route", "add",
                     f"{ENCAP_POD_PREFIX}/{ENCAP_POD_LEN}",
                     "via", ENCAP_NEXTHOP, "pg1")
    out = vppctl_unchecked("overlay", "enable", "pg1",
                           "dst-port", str(ENCAP_DST_PORT))
    assert "failed" not in out.lower(), f"enable produced: {out!r}"
    out = vppctl_unchecked(
        "overlay", "matcher", "add",
        "src-prefix", f"{ENCAP_POD_PREFIX}/{ENCAP_POD_LEN}",
        "nic", "pg1",
    )
    assert "failed" not in out.lower(), f"matcher add produced: {out!r}"

    vppctl_unchecked("clear", "errors")
    vppctl_unchecked("clear", "runtime")
    yield

    vppctl_unchecked("overlay", "disable", "pg1", "force")
    vppctl_unchecked("ip", "route", "del",
                     f"{ENCAP_POD_PREFIX}/{ENCAP_POD_LEN}",
                     "via", ENCAP_NEXTHOP, "pg1")


def _build_encap_inner_frame() -> bytes:
    inner_src = _ip6("fd00:cafe::100")
    inner_dst = _ip6("fd00:cafe::200")
    inner_ip6 = struct.pack("!IHBB", (6 << 28), 0, 59, 64) + inner_src + inner_dst
    eth = bytes.fromhex(ENCAP_PG0_MAC.replace(":", "")) + b"\x00" * 6 + b"\x86\xdd"
    return eth + inner_ip6


def _encap_done() -> int:
    return counter("overlay-encap", "packets encapsulated")


def test_perf_encap_cyc_per_pkt(encap_perf_topology):
    """Push N frames through overlay-encap; assert cyc/pkt under ceiling."""
    frame = _build_encap_inner_frame()
    hex_data = frame.hex()
    size = len(frame)
    cmd = (
        "packet-generator new { "
        f"name perf_encap limit {N_FRAMES} size {size}-{size} "
        f"node ethernet-input interface pg0 "
        f"data {{ hex 0x{hex_data} }} "
        "}"
    )
    before = _encap_done()
    vppctl_unchecked(cmd)
    vppctl_unchecked("packet-generator", "enable-stream", "perf_encap")

    after = wait_for_counter("overlay-encap", "packets encapsulated", before + N_FRAMES, timeout=DRAIN_TIMEOUT_S)
    delivered = after - before
    assert delivered >= N_FRAMES, (
        f"encap drain incomplete: got {delivered}/{N_FRAMES} in "
        f"{DRAIN_TIMEOUT_S}s"
    )

    calls, vectors, cyc_pkt = _runtime_clocks_per_vec("overlay-encap")
    print(
        f"\n[perf] overlay-encap: N={N_FRAMES} calls={calls} "
        f"vectors={vectors} cyc/pkt={cyc_pkt:.1f} ceiling={ENCAP_MAX}"
    )
    assert vectors >= N_FRAMES * 0.9, (
        f"overlay-encap saw only {vectors} vectors, expected ~{N_FRAMES} "
        f"— burst did not reach the node"
    )
    assert cyc_pkt < ENCAP_MAX, (
        f"overlay-encap regression: {cyc_pkt:.1f} cyc/pkt >= "
        f"ceiling {ENCAP_MAX} (override with OVERLAY_PERF_ENCAP_MAX)"
    )


# ===========================================================================
# Bypass microbench
# ===========================================================================

BYPASS_DST_PORT = 6635
BYPASS_UNDERLAY = "fd00:dead:beef:2::4"
BYPASS_SID_PREFIX = "fd00:dead:beef:2:1::"
BYPASS_SID_PREFIX_LEN = 96
BYPASS_SID_ADDR = "fd00:dead:beef:2:1::1"
BYPASS_LOCAL_PFX = "fd00:dead:beef:2:0:1::"
BYPASS_LOCAL_PFX_LEN = 96
BYPASS_POD_GW = "fd00:dead:beef:2:0:1::ff"
BYPASS_POD_NEXTHOP = "fd00:dead:beef:2:0:1::1"
BYPASS_POD_NEXTHOP_MAC = "02:fe:00:00:00:01"
BYPASS_OUTER_NET = "fd00:dead:beef:1::"
BYPASS_OUTER_NET_LEN = 64
BYPASS_OUTER_SRC = "fd00:dead:beef:1::4"
BYPASS_INNERMOST_SRC = "fd00:dead:beef:1:0:1::1"
BYPASS_INNERMOST_DST = "fd00:beef::1"


@pytest.fixture
def bypass_perf_topology():
    vppctl_unchecked("create", "packet-generator", "interface", "pg0")
    vppctl_unchecked("create", "packet-generator", "interface", "pg1")
    vppctl_unchecked("set", "interface", "state", "pg0", "up")
    vppctl_unchecked("set", "interface", "state", "pg1", "up")
    vppctl_unchecked("set", "interface", "ip", "address",
                     "pg0", f"{BYPASS_UNDERLAY}/128")
    vppctl_unchecked("set", "interface", "ip", "address",
                     "pg0", f"{BYPASS_SID_PREFIX}99/{BYPASS_SID_PREFIX_LEN}")
    vppctl_unchecked("set", "interface", "ip", "address",
                     "pg1", f"{BYPASS_POD_GW}/128")
    vppctl_unchecked("ip", "neighbor", "pg1",
                     BYPASS_POD_NEXTHOP, BYPASS_POD_NEXTHOP_MAC, "static")
    vppctl_unchecked("ip", "route", "add",
                     f"{BYPASS_POD_NEXTHOP}/128", "via", "pg1")
    vppctl_unchecked("ip", "route", "add",
                     f"{BYPASS_OUTER_NET}/{BYPASS_OUTER_NET_LEN}",
                     "via", "pg1")

    out = vppctl_unchecked("overlay", "enable", "pg0",
                           "dst-port", str(BYPASS_DST_PORT))
    assert "failed" not in out.lower(), f"enable produced: {out!r}"
    out = vppctl_unchecked(
        "overlay", "matcher", "add",
        "src-prefix", f"{BYPASS_LOCAL_PFX}/{BYPASS_LOCAL_PFX_LEN}",
        "nic", "pg0",
    )
    assert "failed" not in out.lower(), f"matcher add produced: {out!r}"

    vppctl_unchecked("sr", "localsid", "address", BYPASS_SID_ADDR,
                     "behavior", "end.dx6", "pg1", BYPASS_POD_NEXTHOP)

    vppctl_unchecked("clear", "errors")
    vppctl_unchecked("clear", "runtime")
    yield

    vppctl_unchecked("sr", "localsid", "del", "address", BYPASS_SID_ADDR)
    vppctl_unchecked("overlay", "disable", "pg0", "force")
    vppctl_unchecked("ip", "route", "del",
                     f"{BYPASS_OUTER_NET}/{BYPASS_OUTER_NET_LEN}",
                     "via", "pg1")
    vppctl_unchecked("ip", "route", "del",
                     f"{BYPASS_POD_NEXTHOP}/128", "via", "pg1")


def _pg0_mac() -> str:
    out = strip_ansi(vppctl("show", "hardware-interfaces", "pg0"))
    m = re.search(r"Ethernet address\s+([0-9a-f:]{17})", out)
    assert m, f"could not parse pg0 MAC from:\n{out}"
    return m.group(1)


def _build_bypass_frame() -> bytes:
    """SRH-encap'd frame whose outer dst is the SID and outer UDP dport
    matches the configured tunnel port — same shape as
    test_overlay_bypass._build_srh_encap_frame."""
    innermost = struct.pack("!IHBB", (6 << 28), 0, 59, 64) \
        + _ip6(BYPASS_INNERMOST_SRC) + _ip6(BYPASS_INNERMOST_DST)
    srh = struct.pack("!BBBBBBBB", 41, 2, 4, 0, 0, 0, 0, 0) \
        + _ip6(BYPASS_SID_ADDR) + innermost
    inner_ip6 = struct.pack("!IHBB", (6 << 28), len(srh), 43, 64) \
        + _ip6(BYPASS_INNERMOST_SRC) + _ip6(BYPASS_SID_ADDR) + srh
    udp = struct.pack("!HHHH", 0xC001, BYPASS_DST_PORT, 8 + len(inner_ip6), 0) \
        + inner_ip6
    outer = struct.pack("!IHBB", (6 << 28), len(udp), 17, 128) \
        + _ip6(BYPASS_OUTER_SRC) + _ip6(BYPASS_SID_ADDR) + udp
    eth = bytes.fromhex(_pg0_mac().replace(":", "")) + b"\x00" * 6 + b"\x86\xdd"
    return eth + outer


def _bypass_done() -> int:
    return counter("overlay-bypass", "decapsulated")


def test_perf_bypass_cyc_per_pkt(bypass_perf_topology):
    """Push N frames through overlay-bypass; assert cyc/pkt under ceiling."""
    frame = _build_bypass_frame()
    hex_data = frame.hex()
    size = len(frame)
    cmd = (
        "packet-generator new { "
        f"name perf_bypass limit {N_FRAMES} size {size}-{size} "
        f"node ethernet-input interface pg0 "
        f"data {{ hex 0x{hex_data} }} "
        "}"
    )
    before = _bypass_done()
    vppctl_unchecked(cmd)
    vppctl_unchecked("packet-generator", "enable-stream", "perf_bypass")

    after = wait_for_counter("overlay-bypass", "decapsulated", before + N_FRAMES, timeout=DRAIN_TIMEOUT_S)
    delivered = after - before
    assert delivered >= N_FRAMES, (
        f"bypass drain incomplete: got {delivered}/{N_FRAMES} in "
        f"{DRAIN_TIMEOUT_S}s"
    )

    calls, vectors, cyc_pkt = _runtime_clocks_per_vec("overlay-bypass")
    print(
        f"\n[perf] overlay-bypass: N={N_FRAMES} calls={calls} "
        f"vectors={vectors} cyc/pkt={cyc_pkt:.1f} ceiling={BYPASS_MAX}"
    )
    assert vectors >= N_FRAMES * 0.9, (
        f"overlay-bypass saw only {vectors} vectors, expected ~{N_FRAMES} "
        f"— burst did not reach the node"
    )
    assert cyc_pkt < BYPASS_MAX, (
        f"overlay-bypass regression: {cyc_pkt:.1f} cyc/pkt >= "
        f"ceiling {BYPASS_MAX} (override with OVERLAY_PERF_BYPASS_MAX)"
    )
