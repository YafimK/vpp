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
        "pod-sid-prefix", f"{prefix}/{prefix_len}",
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


def test_arm_param_mismatch(two_loopbacks):
    a, b = two_loopbacks
    out = _arm(a, prefix="fd00:cafe::", prefix_len=48)
    assert "failed" not in out, out
    out = _arm(b, prefix="fd00:beef::", prefix_len=48)
    assert "tunnel parameters" in out.lower() or "mismatch" in out.lower(), out


def test_arm_reserved_port_4791(loopback):
    out = _arm(loopback, port=4791)
    assert "reserved" in out.lower(), out


def test_arm_reserved_port_65330(loopback):
    out = _arm(loopback, port=65330)
    assert "reserved" in out.lower(), out


def test_arm_invalid_iface():
    out = vppctl_unchecked(
        "overlay", "arm", "no-such-iface-9999",
        "src", SRC,
        "pod-sid-prefix", f"{PFX}/{PFX_LEN}",
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
