"""Slice C-2: hard cap of 3 matchers per NIC.

A 4th `matcher add` returns an error matching `too many matchers|matcher
cap exceeded`. Cap is on count, not lifetime: deleting one and adding
another succeeds.
"""
import re

from conftest import vppctl, vppctl_unchecked, reset_overlay_state
from overlay_helpers import (
    DST_PORT, enable, matcher_add, matcher_del, show_overlay_nic, cleanup_nic,
)


PREFIXES = [
    ("2001:db8:1::", 48),
    ("2001:db8:2::", 48),
    ("2001:db8:3::", 48),
]
EXTRA = ("2001:db8:4::", 48)

CAP_RE = re.compile(r"too many matchers|matcher cap exceeded", re.IGNORECASE)


def _count_matchers_for_nic(nic):
    show = show_overlay_nic(nic)
    n = 0
    for pfx, _ in PREFIXES + [EXTRA]:
        if pfx in show:
            n += 1
    return n


def test_cap_three_succeed(loopback):
    reset_overlay_state()
    cleanup_nic(loopback)
    out = enable(loopback)
    assert "failed" not in out.lower(), out

    for p, l in PREFIXES:
        out = matcher_add(p, l, loopback)
        assert "failed" not in out.lower() and "error" not in out.lower(), (
            f"add {p}/{l} unexpectedly errored: {out}"
        )

    show = show_overlay_nic(loopback)
    for p, _ in PREFIXES:
        assert p in show, f"{p} missing from show output:\n{show}"

    cleanup_nic(loopback)


def test_fourth_matcher_rejected(loopback):
    reset_overlay_state()
    cleanup_nic(loopback)
    enable(loopback)
    for p, l in PREFIXES:
        matcher_add(p, l, loopback)

    out = matcher_add(EXTRA[0], EXTRA[1], loopback)
    assert CAP_RE.search(out), (
        f"4th matcher add should error with cap message; got: {out!r}"
    )

    # Still exactly 3 matchers; the 4th must NOT have been partially added.
    n = _count_matchers_for_nic(loopback)
    assert n == 3, (
        f"expected 3 matchers after rejected 4th add, got {n}\n"
        f"show: {show_overlay_nic(loopback)}"
    )

    cleanup_nic(loopback)


def test_cap_is_count_not_lifetime(loopback):
    reset_overlay_state()
    cleanup_nic(loopback)
    enable(loopback)
    for p, l in PREFIXES:
        matcher_add(p, l, loopback)

    # Delete one matcher.
    p_del, l_del = PREFIXES[0]
    out = matcher_del(p_del, l_del, loopback)
    assert "failed" not in out.lower() and "error" not in out.lower(), out

    # 4th add now succeeds — cap is on current count.
    out = matcher_add(EXTRA[0], EXTRA[1], loopback)
    assert "failed" not in out.lower() and "error" not in out.lower(), (
        f"add after delete should succeed; got: {out!r}"
    )
    show = show_overlay_nic(loopback)
    assert EXTRA[0] in show, show
    assert p_del not in show, show

    cleanup_nic(loopback)
