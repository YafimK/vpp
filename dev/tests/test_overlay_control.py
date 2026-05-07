"""Phase 1 control-plane tests for the overlay plugin.

Drives the plugin through `vppctl` (CLI). Validates arm/disarm semantics,
parameter validation, idempotence, and multi-NIC handling.
"""
from conftest import vppctl, vppctl_unchecked


SRC = "fd00:cafe::1"
PFX = "fd00:cafe::"
PFX_LEN = 48
DST_PORT = 6635


def _arm(nic, src=SRC, prefix=PFX, prefix_len=PFX_LEN, port=DST_PORT):
    return vppctl_unchecked(
        "overlay", "arm", nic,
        "src", src,
        "src-prefix", f"{prefix}/{prefix_len}",
        "dst-port", str(port),
    )


def _disarm(nic):
    return vppctl_unchecked("overlay", "disarm", nic)


def test_show_empty():
    out = vppctl("show", "overlay")
    assert "no overlay configured" in out, out


def test_arm_creates_tunnel(loopback):
    out = _arm(loopback)
    assert out.strip() == "", f"arm produced unexpected output: {out!r}"
    show = vppctl("show", "overlay")
    assert "overlay tunnel" in show, show
    assert loopback in show, show
    assert str(DST_PORT) in show, show


def test_arm_idempotent(loopback):
    out1 = _arm(loopback)
    assert "failed" not in out1, out1
    out2 = _arm(loopback)
    assert "failed" not in out2, out2
    show = vppctl("show", "overlay")
    # exactly one tunnel + this NIC armed once
    assert show.count(loopback) == 1, show


def test_arm_different_src_prefix_creates_second_tunnel(two_loopbacks):
    """Slice B: two NICs may carry different src_prefix on the same dst_port.
    Each prefix produces its own overlay_tunnel_t — show should list two
    tunnel blocks and both NICs."""
    a, b = two_loopbacks
    out = _arm(a, prefix="fd00:cafe::", prefix_len=48)
    assert "failed" not in out, out
    out = _arm(b, prefix="fd00:beef::", prefix_len=48)
    assert "failed" not in out, out
    show = vppctl("show", "overlay")
    # Two tunnel blocks expected.
    assert show.count("overlay tunnel:") == 2, show
    assert a in show and b in show, show
    assert "fd00:cafe::" in show and "fd00:beef::" in show, show


def test_arm_port_conflict_rejected(two_loopbacks):
    """Two tunnels on the same VPP must share one dst_port. Arming a second
    NIC on a different port returns the dst-port conflict error."""
    a, b = two_loopbacks
    out = _arm(a, port=DST_PORT)
    assert "failed" not in out, out
    out = _arm(b, prefix="fd00:beef::", port=DST_PORT + 1)
    assert "dst-port" in out.lower() or "conflict" in out.lower(), out


def test_arm_rearm_same_nic_different_params_rejected(loopback):
    """Re-arming a NIC with different params (without disarming first)
    must be rejected. Caller must disarm explicitly."""
    out = _arm(loopback, prefix="fd00:cafe::", prefix_len=48)
    assert "failed" not in out, out
    out = _arm(loopback, prefix="fd00:beef::", prefix_len=48)
    assert "failed" in out.lower() or "invalid" in out.lower(), out


def test_arm_invalid_iface():
    out = vppctl_unchecked(
        "overlay", "arm", "no-such-iface-9999",
        "src", SRC,
        "src-prefix", f"{PFX}/{PFX_LEN}",
        "dst-port", str(DST_PORT),
    )
    # CLI parser fails to match unformat_vnet_sw_interface
    assert ("unknown input" in out.lower() or "interface required" in out.lower()
            or "invalid interface" in out.lower()), out


def test_disarm_unarmed_nic(loopback):
    out = _disarm(loopback)
    assert "not armed" in out.lower(), out


def test_disarm_last_nic_destroys_tunnel(loopback):
    _arm(loopback)
    out = _disarm(loopback)
    assert "failed" not in out, out
    show = vppctl("show", "overlay")
    assert "no overlay configured" in show, show


def test_multiple_nics(two_loopbacks):
    a, b = two_loopbacks
    out = _arm(a)
    assert "failed" not in out, out
    out = _arm(b)
    assert "failed" not in out, out
    show = vppctl("show", "overlay")
    assert a in show and b in show, show
    # disarm one
    _disarm(a)
    show = vppctl("show", "overlay")
    assert "overlay tunnel" in show, show
    assert b in show, show
    assert a not in show, show
    # disarm last -> tunnel gone
    _disarm(b)
    show = vppctl("show", "overlay")
    assert "no overlay configured" in show, show


def test_show_overlay_version():
    """`show overlay version` returns build identity (sha may be 'unknown' in
    the test container which has no .git access — but the structure must be there)."""
    import re
    out = vppctl("show", "overlay", "version")
    assert "overlay plugin version" in out, out
    m = re.search(r"build sha:\s+(\S+)", out)
    assert m, f"missing build sha line: {out!r}"
    sha = m.group(1)
    assert sha == "unknown" or re.fullmatch(r"[a-f0-9]{40}", sha), \
        f"bad sha format: {sha!r}"
    assert "build date:" in out
    assert "branch:" in out
