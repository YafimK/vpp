"""Slice C-2: matcher_add atomicity — failed adds must leave zero state.

If `matcher add` references an unenabled NIC or a malformed prefix, it
must error AND leave the matcher pool unchanged. No partial inserts.
"""
import re

from conftest import vppctl, vppctl_unchecked, reset_overlay_state
from overlay_helpers import (
    DST_PORT, enable, matcher_add, show_overlay_matcher, show_overlay_nic,
    cleanup_nic,
)


PFX = "fd00:cafe::"
PFX_LEN = 48
BAD_PFX = "fd00:beef::"


def _matcher_count(nic):
    show = show_overlay_nic(nic)
    n = 0
    for token in (PFX, BAD_PFX):
        if token in show:
            n += 1
    return n


def test_add_to_unenabled_nic_errors_no_state(loopback, two_loopbacks):
    """`loopback` (enabled) and `two_loopbacks[0]` (unenabled) — adding
    a matcher referencing the unenabled NIC must error and leave both
    NICs' matcher state untouched."""
    reset_overlay_state()
    cleanup_nic(loopback)
    a, b = two_loopbacks
    cleanup_nic(a)
    cleanup_nic(b)

    out = enable(loopback)
    assert "failed" not in out.lower(), out
    # `a` and `b` are intentionally NOT enabled.

    out = matcher_add(PFX, PFX_LEN, loopback, a)
    low = out.lower()
    assert ("failed" in low or "error" in low or "not enabled" in low
            or "not armed" in low or "unknown" in low), (
        f"add referencing unenabled NIC should error; got: {out!r}"
    )

    # Atomicity: the enabled NIC must NOT have a partial matcher.
    show = show_overlay_nic(loopback)
    assert PFX not in show, (
        f"matcher partially added on enabled NIC despite error:\n{show}"
    )
    n_total = _matcher_count(loopback)
    assert n_total == 0, (
        f"expected 0 matchers on {loopback}, got {n_total}\n"
        f"show: {show}"
    )

    cleanup_nic(loopback)


def test_add_malformed_prefix_len_zero_errors(loopback):
    reset_overlay_state()
    cleanup_nic(loopback)
    enable(loopback)

    out = matcher_add(PFX, 0, loopback)
    low = out.lower()
    assert ("failed" in low or "error" in low or "invalid" in low), (
        f"len=0 should error; got: {out!r}"
    )
    show = show_overlay_nic(loopback)
    assert PFX not in show, show

    cleanup_nic(loopback)


def test_add_malformed_prefix_len_too_large_errors(loopback):
    reset_overlay_state()
    cleanup_nic(loopback)
    enable(loopback)

    out = matcher_add(PFX, 129, loopback)
    low = out.lower()
    assert ("failed" in low or "error" in low or "invalid" in low), (
        f"len=129 should error; got: {out!r}"
    )
    show = show_overlay_nic(loopback)
    assert PFX not in show, show

    cleanup_nic(loopback)
