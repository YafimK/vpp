"""Disable semantics with respect to existing matchers.

- `disable` without `force` errors if matchers exist.
- `disable force` clears matchers and disables the NIC.
- Matchers do NOT survive a disable→enable cycle.
"""
from conftest import vppctl, vppctl_unchecked, reset_overlay_state
from overlay_helpers import (
    DST_PORT, enable, disable, matcher_add, show_overlay_nic, cleanup_nic,
)


PFX = "fd00:cafe::"
PFX_LEN = 48


def _is_not_enabled(show_out):
    low = show_out.lower()
    return ("not enabled" in low or "not armed" in low
            or "no overlay" in low or "unknown" in low)


def test_disable_without_force_errors_if_matchers(loopback):
    reset_overlay_state()
    cleanup_nic(loopback)
    out = enable(loopback)
    assert "failed" not in out.lower(), out
    out = matcher_add(PFX, PFX_LEN, loopback)
    assert "failed" not in out.lower(), out

    out = disable(loopback, force=False)
    low = out.lower()
    assert ("matcher" in low or "force" in low
            or "failed" in low or "error" in low), out
    show = show_overlay_nic(loopback)
    assert PFX in show, show

    cleanup_nic(loopback)


def test_disable_force_succeeds_and_clears(loopback):
    reset_overlay_state()
    cleanup_nic(loopback)
    enable(loopback)
    matcher_add(PFX, PFX_LEN, loopback)

    out = disable(loopback, force=True)
    assert "failed" not in out.lower() and "error" not in out.lower(), out

    show = show_overlay_nic(loopback)
    assert _is_not_enabled(show), show


def test_matcher_does_not_survive_disable_enable_cycle(loopback):
    reset_overlay_state()
    cleanup_nic(loopback)
    enable(loopback)
    matcher_add(PFX, PFX_LEN, loopback)

    out = disable(loopback, force=True)
    assert "failed" not in out.lower(), out

    out = enable(loopback)
    assert "failed" not in out.lower(), out

    show = show_overlay_nic(loopback)
    # NIC enabled, but no matchers retained.
    assert PFX not in show, (
        f"matcher prefix {PFX} survived disable→enable cycle:\n{show}"
    )
    assert ("0 matchers" in show or "matchers: 0" in show
            or "n_matchers: 0" in show), show

    cleanup_nic(loopback)
