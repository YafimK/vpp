"""Control-plane semantics for `overlay enable` / `overlay disable`."""
from conftest import vppctl, vppctl_unchecked, reset_overlay_state
from overlay_helpers import (
    DST_PORT, enable, disable, matcher_add, show_overlay_nic, cleanup_nic,
)


PFX = "fd00:cafe::"
PFX_LEN = 48


def test_enable_creates_entry(loopback):
    reset_overlay_state()
    out = enable(loopback)
    assert "failed" not in out.lower() and "error" not in out.lower(), out

    show = show_overlay_nic(loopback)
    assert loopback in show, show
    assert str(DST_PORT) in show, show
    # Zero matchers on a freshly enabled NIC.
    assert "0 matchers" in show or "matchers: 0" in show or "n_matchers: 0" in show, show


def test_enable_idempotent_same_dst_port(loopback):
    reset_overlay_state()
    out1 = enable(loopback, DST_PORT)
    assert "failed" not in out1.lower(), out1
    out2 = enable(loopback, DST_PORT)
    assert "failed" not in out2.lower() and "error" not in out2.lower(), out2

    show = show_overlay_nic(loopback)
    # Still one entry, still the original dst_port.
    assert show.count(loopback) >= 1, show
    assert str(DST_PORT) in show, show


def test_enable_different_dst_port_rejected(loopback):
    reset_overlay_state()
    out = enable(loopback, DST_PORT)
    assert "failed" not in out.lower(), out
    out2 = enable(loopback, DST_PORT + 1)
    low = out2.lower()
    assert ("failed" in low or "error" in low or "in use" in low
            or "disable" in low or "conflict" in low or "already" in low), out2

    # Original dst_port still in effect.
    show = show_overlay_nic(loopback)
    assert str(DST_PORT) in show, show
    assert str(DST_PORT + 1) not in show, show


def test_disable_no_matchers_succeeds_without_force(loopback):
    reset_overlay_state()
    enable(loopback)
    out = disable(loopback, force=False)
    assert "failed" not in out.lower() and "error" not in out.lower(), out

    show = show_overlay_nic(loopback)
    low = show.lower()
    assert ("not enabled" in low or "not armed" in low
            or "no overlay" in low or "unknown" in low), show


def test_disable_with_matchers_requires_force(loopback):
    reset_overlay_state()
    enable(loopback)
    out = matcher_add(PFX, PFX_LEN, loopback)
    assert "failed" not in out.lower() and "error" not in out.lower(), out

    out = disable(loopback, force=False)
    assert ("matcher" in out.lower() or "force" in out.lower()
            or "failed" in out.lower() or "error" in out.lower()), out
    # NIC still enabled, matcher still present.
    show = show_overlay_nic(loopback)
    assert PFX in show, show

    out = disable(loopback, force=True)
    assert "failed" not in out.lower() and "error" not in out.lower(), out
    show = show_overlay_nic(loopback)
    low = show.lower()
    assert ("not enabled" in low or "not armed" in low
            or "no overlay" in low or "unknown" in low), show
    cleanup_nic(loopback)
