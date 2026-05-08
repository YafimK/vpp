"""Shared helpers wrapping the overlay CLI for tests.

Covers `overlay enable`, `overlay disable`, `overlay matcher add|del`,
`show overlay nic|matcher|version`, plus packet-injection / counter /
trace primitives shared across encap, bypass, decap, and matcher tests.
"""
import re
import socket
import struct
import time

from conftest import vppctl, vppctl_unchecked


DST_PORT = 6635
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def enable(nic, dst_port=DST_PORT):
    """Enable overlay on `nic` with `dst-port`. Returns CLI output."""
    return vppctl_unchecked(
        "overlay", "enable", nic, "dst-port", str(dst_port),
    )


def disable(nic, force=False):
    """Disable overlay on `nic`. Returns CLI output."""
    args = ["overlay", "disable", nic]
    if force:
        args.append("force")
    return vppctl_unchecked(*args)


def matcher_add(prefix, prefix_len, *nics):
    """`overlay matcher add src-prefix <p>/<l> nic <iface> [nic <iface>]...`."""
    args = ["overlay", "matcher", "add",
            "src-prefix", f"{prefix}/{prefix_len}"]
    for n in nics:
        args.extend(["nic", n])
    return vppctl_unchecked(*args)


def matcher_del(prefix, prefix_len, *nics):
    args = ["overlay", "matcher", "del",
            "src-prefix", f"{prefix}/{prefix_len}"]
    for n in nics:
        args.extend(["nic", n])
    return vppctl_unchecked(*args)


def show_overlay():
    return vppctl("show", "overlay")


def show_overlay_nic(nic):
    return vppctl_unchecked("show", "overlay", "nic", nic)


def show_overlay_matcher():
    return vppctl_unchecked("show", "overlay", "matcher")


def show_features(nic):
    return vppctl_unchecked("show", "interface", "features", nic)


def cleanup_nic(nic):
    """Best-effort: disable (force) so a NIC starts each test clean.

    Safe to call on a NIC that isn't enabled — vppctl_unchecked swallows
    errors.
    """
    vppctl_unchecked("overlay", "disable", nic, "force")


def strip_ansi(s):
    """Remove ANSI colour escapes so substring asserts on CLI output work."""
    return _ANSI_RE.sub("", s)


def build_inner_frame(inner_src, inner_dst, dmac_bytes):
    """Ethernet frame carrying a bare inner IPv6 (next-header 59 / NoNxt) so
    ip6-input accepts it without further L4 parsing. dmac is the pinned hw
    address of the pg interface the frame will be injected on."""
    src = socket.inet_pton(socket.AF_INET6, inner_src)
    dst = socket.inet_pton(socket.AF_INET6, inner_dst)
    inner_ip6 = struct.pack("!IHBB", (6 << 28), 0, 59, 64) + src + dst
    eth = dmac_bytes + b"\x00" * 6 + b"\x86\xdd"
    return eth + inner_ip6


def inject(frame, name="pkt", iface="pg0"):
    """Inject a single frame into VPP via the packet-generator on `iface`."""
    hex_data = frame.hex()
    size = len(frame)
    cmd = (
        "packet-generator new { "
        f"name {name} limit 1 size {size}-{size} node ethernet-input "
        f"interface {iface} "
        f"data {{ hex 0x{hex_data} }} "
        "}"
    )
    vppctl_unchecked(cmd)
    vppctl_unchecked("packet-generator", "enable-stream", name)


def counter(node_substring, name_substring):
    """Read a node error counter — e.g. counter("overlay-encap", "encap").

    Both substrings are matched case-insensitively against each `show errors`
    line; both must be present. Returns 0 if no line matches."""
    out = vppctl("show", "errors")
    nsub = node_substring.lower()
    msub = name_substring.lower()
    for line in out.splitlines():
        low = line.lower()
        if nsub in low and msub in low:
            try:
                return int(line.split()[0])
            except (ValueError, IndexError):
                return 0
    return 0


def wait_for_counter(node_substring, name_substring, target, timeout=1.0):
    """Poll counter() until it reaches `target` or `timeout` seconds elapse."""
    deadline = time.time() + timeout
    val = counter(node_substring, name_substring)
    while val < target and time.time() < deadline:
        time.sleep(0.05)
        val = counter(node_substring, name_substring)
    return val


def trace():
    """Return `show trace` output with ANSI colour escapes stripped."""
    return strip_ansi(vppctl_unchecked("show", "trace"))
