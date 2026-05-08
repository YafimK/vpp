"""Pytest fixtures for overlay control-plane tests.

Assumes VPP is already running with the overlay plugin loaded and
- CLI socket at $VPP_CLI_SOCK (default /tmp/vpp.sock)
- Binary API socket at $VPP_API_SOCK (default /run/vpp/api.sock)

The run-tests.sh harness starts VPP before invoking pytest.
"""
import os
import subprocess

import pytest


VPP_CLI_SOCK = os.environ.get("VPP_CLI_SOCK", "/tmp/vpp.sock")


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "perf: smoke microbench for overlay nodes (cyc/pkt). "
        "Skip in fast iterations with `-m 'not perf'`.",
    )


def vppctl(*args, check=True):
    cmd = ["vppctl", "-s", VPP_CLI_SOCK, *args]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if check and res.returncode != 0:
        raise AssertionError(
            f"vppctl {' '.join(args)} failed: rc={res.returncode}\n"
            f"stdout={res.stdout!r}\nstderr={res.stderr!r}"
        )
    # vppctl returns 0 even on CLI errors and prints message to stdout.
    return res.stdout


def vppctl_unchecked(*args):
    """Run vppctl and return combined stdout+stderr without raising on
    non-zero exit. Useful for asserting on CLI error messages."""
    cmd = ["vppctl", "-s", VPP_CLI_SOCK, *args]
    res = subprocess.run(cmd, capture_output=True, text=True)
    return res.stdout + res.stderr


def reset_overlay_state():
    """Best-effort: disable any enabled NICs so each test starts fresh.

    Walks `show overlay`. Each enabled NIC is reported on a line of the
    form `enabled NIC: <name> sw_if_index <X> dst-port <P> n_matchers <M>`
    (see format_overlay_state in overlay.c). We extract <name> and call
    `overlay disable <name> force` so that the NIC is disabled regardless
    of any matchers it still owns.
    """
    out = vppctl("show", "overlay", check=False)
    if not out or "no overlay configured" in out:
        return
    nics = []
    for line in out.splitlines():
        stripped = line.strip()
        if not stripped.startswith("enabled NIC:"):
            continue
        parts = stripped.split()
        # Expect: ["enabled", "NIC:", "<name>", "sw_if_index", ...]
        if len(parts) >= 3:
            nics.append(parts[2])
    for n in nics:
        vppctl("overlay", "disable", n, "force", check=False)


def _list_loopbacks():
    out = vppctl("show", "interface")
    names = []
    for line in out.splitlines():
        parts = line.split()
        if parts and parts[0].startswith("loop"):
            names.append(parts[0])
    return names


@pytest.fixture(autouse=True)
def _clean_state():
    # One-pass cleanup at setup. The loopback fixtures own their own
    # teardown for the loopbacks they create; the next test's setup will
    # disarm any leftovers via reset_overlay_state(). No teardown work
    # needed here.
    reset_overlay_state()
    for n in _list_loopbacks():
        vppctl("delete", "loopback", "interface", "intfc", n, check=False)
    yield


@pytest.fixture
def loopback():
    pre = set(_list_loopbacks())
    vppctl("create", "loopback", "interface")
    post = set(_list_loopbacks())
    new = list(post - pre)
    assert len(new) == 1, f"expected 1 new loopback, got {new}"
    yield new[0]


@pytest.fixture
def two_loopbacks():
    pre = set(_list_loopbacks())
    vppctl("create", "loopback", "interface")
    vppctl("create", "loopback", "interface")
    post = set(_list_loopbacks())
    new = sorted(post - pre)
    assert len(new) == 2, f"expected 2 new loopbacks, got {new}"
    yield new
