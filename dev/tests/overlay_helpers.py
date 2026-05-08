"""Shared helpers wrapping the overlay CLI for tests.

Covers `overlay enable`, `overlay disable`, `overlay matcher add|del`, and
`show overlay nic|matcher|version`.
"""
from conftest import vppctl, vppctl_unchecked


DST_PORT = 6635


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
