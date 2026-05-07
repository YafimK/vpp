# Multi-Interface Support — Architecture Plan

**Status:** design only — not yet implemented.
**Owner:** Yafim @ Check Point.
**Target branch:** cut from `feature/srv6-udp-overlay` after Step 2 lands.
**Prerequisite reading:** this plan supersedes the v1 draft; the v1 `tunnel_index_by_port` and decap-demux designs are withdrawn.

---

## 1. Corrected Framing

Multi-interface support is primarily a **feature-arm topology change, not a tunnel-pool change.**

The plugin's encap is stateless: per-packet, the encap node copies `inner_dst → outer_dst` and computes an entropy-based UDP src port from the inner headers. The only per-NIC state consumed at runtime is `(src, src_prefix, src_prefix_mask, dst_port)` — stored in `overlay_tunnel_t`. There is **one UDP dst port per VPP instance**. A second NIC receiving traffic on that port hits the same decap node and strips the outer headers the same way; it does not need a separate port or a separate demux lookup.

Consequence: "add a second NIC to the same tunnel" is already implemented. `overlay_arm()` at `overlay.c:95–123` adds the NIC to `t->armed_nic_sw_if_indices` and extends `tunnel_index_by_nic` whenever the params match the active tunnel. The only gate blocking a second NIC with *different* params is `OVERLAY_RC_TUNNEL_PARAM_MISMATCH` at `overlay.c:78–79`.

The work therefore splits into two independent slices:

| Slice | Condition | Code change |
|---|---|---|
| A — shared tunnel | N NICs, same `(src, src_prefix, dst_port)` | none — verify with a pytest |
| B — per-NIC tunnel | N NICs, different `src_prefix` (tenant separation) | control-plane refactor + bypass node |

---

## 2. Slice A — Shared Tunnel Across Multiple NICs

**Code change: none.**

`overlay_arm()` already accumulates NICs onto a single `overlay_tunnel_t` when params match (`overlay.c:74–83`, `95–123`). `test_multiple_nics` in `test_overlay_control.py:85–102` exercises this path today and passes.

The decap node reads `active_tunnel_index` once per frame (`decap.c:64–68`) and attributes all decapped traffic to that tunnel's loopback — correct, because all encapped traffic on any armed NIC uses the same `dst_port` and the same loopback.

The bypass node reads `active_tunnel_index` once per frame (`node.c:365–372`) to populate `overlay_rx_sw_if_index` and `expected_dport_n` as frame-level scalars — also correct; both NICs share the same port.

**New test needed:** add `test_overlay_multi_nic_shared.py` or extend `test_overlay_control.py`:

1. Arm two NICs with identical params — assert no error, `show overlay` lists both NICs under one tunnel entry.
2. Send encap traffic on each NIC — assert packets are encapsulated and counters on the shared tunnel increment.
3. Disarm one NIC — other stays live, tunnel survives.
4. Disarm last NIC — tunnel and loopback destroyed.

No Go binding changes needed.

---

## 3. Slice B — Per-NIC Tunnel State (Tenant Separation)

This slice is needed when two NICs on the same VPP instance must filter on **different `src_prefix` values** — for example, two pod CIDRs from different Azure VNets. The port stays the same; the `src_prefix` differs.

### 3.1 What changes in the control plane

**`overlay.h`**

Remove `active_tunnel_index` from `overlay_main_t` (`overlay.h:45`). Add a replacement for the decap and `show` paths:

```c
u32 decap_overlay_sw_if_index;  /* loopback sw_if_index for decap attribution;
                                   set when dst_port is first registered via
                                   udp_register_dst_port; ~0 when no tunnel armed */
```

`tunnel_index_by_nic` (`overlay.h:44`) is unchanged — it already handles the per-NIC encap and bypass lookup.

**`overlay.c` — `overlay_arm()`**

Remove the `active_tunnel_index != ~0` param-mismatch check (`overlay.c:74–83`). Replace with:

- If this NIC is already armed (`tunnel_index != ~0`): idempotent return if params unchanged; disarm-then-rearm if params differ (disarm the old tunnel entry for this NIC, allocate a new one).
- If no tunnel exists yet for this port: create tunnel + loopback + `udp_register_dst_port` as today, and set `om->decap_overlay_sw_if_index = t->sw_if_index`.
- If a tunnel already exists for this port (same port, different src_prefix, new NIC): allocate a new `overlay_tunnel_t` entry with its own loopback. The port is already registered — do not call `udp_register_dst_port` again. `decap_overlay_sw_if_index` stays pointing to the first tunnel's loopback (shared decap attribution — see §3.3).

Remove `OVERLAY_RC_TUNNEL_PARAM_MISMATCH` from `overlay_rc_to_api` (`overlay.c:176–177`) and from `overlay.h:60`.

**`overlay.c` — `overlay_v1_dump` / `format_overlay_state`**

Replace the `active_tunnel_index` gate (`overlay.c:249–253`, `265–268`) with `pool_foreach` iteration. Each tunnel emits one `overlay_v1_details` message. Wire format is unchanged.

**Disarm path (`overlay.c:130–162`)**

When the last NIC on a tunnel is disarmed and the tunnel is destroyed (`pool_put`): only call `udp_unregister_dst_port` if no other tunnel is still registered for that port (check `pool_elts(om->tunnels) == 0` or maintain a port refcount). Reset `decap_overlay_sw_if_index` to `~0` when the last tunnel is gone.

### 3.2 What changes in bypass (`node.c:365–425`)

Replace the per-frame scalar setup block (`node.c:365–372`) with a per-packet `tunnel_index_by_nic` lookup:

```c
u32 rx_sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
u32 tunnel_index = ~0;
if (rx_sw_if_index < vec_len (om->tunnel_index_by_nic))
    tunnel_index = om->tunnel_index_by_nic[rx_sw_if_index];
if (PREDICT_FALSE (tunnel_index == ~0))
    { vnet_feature_next_u16 (&next[0], b0); n_no_tunnel++; goto trace0; }
overlay_tunnel_t *t = pool_elt_at_index (om->tunnels, tunnel_index);
if (udp->dst_port != clib_host_to_net_u16 (t->dst_port))
    { vnet_feature_next_u16 (&next[0], b0); goto trace0; }
vnet_buffer (b0)->sw_if_index[VLIB_RX] = t->sw_if_index;
```

`t->dst_port` can be pre-computed as `dst_port_n` (network byte order) at arm time to eliminate the per-packet byte-swap; add `u16 dst_port_n` to `overlay_tunnel_t`. Cost: one vec bounds check + one u32 load per packet, ~2 cycles, negligible against the ~43 cyc/pkt bypass budget measured in Phase 1.

The ip6-unicast feature fires per-NIC. A packet on an unarmed NIC never reaches `overlay-bypass`, so the `tunnel_index == ~0` branch is only a PREDICT_FALSE guard for the disarm race.

### 3.3 What does NOT change in decap (`decap.c`)

The decap node receives packets dispatched by the UDP dst port table. Since there is one port per VPP instance, the decap node strips the outer headers and attributes all decapped traffic to `om->decap_overlay_sw_if_index` — the loopback of whichever tunnel first registered the port. The inner packet's forwarding (SRv6 localsid lookup) is determined by the inner destination address, not by which NIC the outer packet arrived on. Decap does not need to know which tunnel's `src_prefix` to apply — that filtering only matters for encap.

The only change to `decap.c` is mechanical: replace the `active_tunnel_index` dereference (`decap.c:64–68`) with a read of `om->decap_overlay_sw_if_index`. One line changes; the logic and performance are identical.

---

## 4. API Contract

**`overlay_arm_v1` wire format:** unchanged. The behavioral change (second NIC with different params no longer errors) is a documented semantic change. No CRC bump required unless `OVERLAY_RC_TUNNEL_PARAM_MISMATCH` is exposed in the API enum in a way that affects the CRC.

**`overlay_v1_dump`:** now emits N details messages instead of 0 or 1. The `RPCService.OverlayV1Dump` stream in `overlay_rpc.ba.go` already returns a stream — no structural change needed.

**Error codes:** remove `OVERLAY_RC_TUNNEL_PARAM_MISMATCH`. Update `overlay_rc_to_api` and `overlay.h`. Regenerate Go bindings if the CRC changes:

```
vppapigen JSON --input overlay.api --output overlay.api.json
binapi-generator --input overlay.api.json --output-dir dev/go-overlay/
```

**CLI:** `overlay arm`, `overlay disarm` syntax unchanged. `show overlay` prints N tunnel blocks when N > 1.

---

## 5. Test Plan

### Existing tests — impact

| Test | Impact |
|---|---|
| `test_arm_param_mismatch` (`test_overlay_control.py:52–57`) | Currently asserts error — must invert for Slice B: assert arm succeeds and creates a second tunnel |
| `test_multiple_nics` (`test_overlay_control.py:85–102`) | Slice A common case — still valid, no change |
| All single-NIC datapath tests (`test_overlay_bypass.py`, `_decap.py`, `_encap.py`) | Unaffected |

### New tests for Slice A

In `test_overlay_control.py` or a new `test_overlay_multi_nic_shared.py`:

1. Arm two NICs with same params — one tunnel, both NICs listed.
2. Encap traffic on both NICs — shared tunnel counter increments.
3. Disarm one — tunnel survives with one NIC.

### New tests for Slice B

In `test_overlay_multi_nic_tenant.py`:

1. Arm `pg0` with `src-prefix A`, arm `pg1` with `src-prefix B`, same port — assert two tunnels in dump, no error.
2. Re-arm same NIC with different `src_prefix` — assert no error, dump reflects update.
3. Encap traffic on `pg0` with src in A — encapsulated. Traffic with src in B — passed through (src-prefix mismatch for pg0's tunnel).
4. Disarm `pg0` — `pg1` still works; one tunnel in dump.
5. Inject decap packet to the shared port — arrives on loopback attributed to `decap_overlay_sw_if_index`; counter on that interface increments.

### Go integration tests

In `dev/go-overlay/`: add a test that calls `OverlayArmV1` for two different `IfaceSwIfIndex` values with the same port but different `src_prefix`, then iterates `OverlayV1Dump` and asserts two `OverlayV1Details` messages are returned.

---

## 6. Migration / Rollout

Two commits, shipped as one PR (commit 1 breaks bypass/decap for single-NIC until commit 2 lands).

**Commit 1 — Control plane**
Files: `overlay.h`, `overlay.c`
- Remove `active_tunnel_index`; add `decap_overlay_sw_if_index`.
- Rewrite `overlay_arm()`: drop param-mismatch check, allow multiple tunnels, handle port-already-registered case.
- Update `overlay_v1_dump` and `format_overlay_state` to use `pool_foreach`.
- Remove `OVERLAY_RC_TUNNEL_PARAM_MISMATCH`.

**Commit 2 — Datapath**
Files: `overlay.h` (add `dst_port_n` to `overlay_tunnel_t`), `node.c`, `decap.c`
- Bypass node: replace per-frame scalar block with per-packet `tunnel_index_by_nic` lookup.
- Decap node: replace `active_tunnel_index` dereference with `decap_overlay_sw_if_index` read.

Risk areas (unchanged from v1):
- **Disarm race:** existing per-NIC ordering (disarm feature before clearing `tunnel_index_by_nic`) is sufficient for each tunnel independently.
- **Pool fragmentation:** `pool_foreach` skips free entries correctly; `pool_elt_at_index` is safe as long as `tunnel_index_by_nic` is cleared on disarm.
- **UDP port collision:** `udp_register_dst_port` is global. Skip the second call if the port is already registered (track with `decap_overlay_sw_if_index != ~0`). Return an error if caller tries to arm two tunnels with *different* ports on the same VPP instance — that is not a supported configuration.

---

## 7. Open Questions

**Can two tunnels have different `dst_port` values on the same VPP instance?**
No. There is one UDP port per VPP instance. The design enforces this: `udp_register_dst_port` is called once on the first arm; subsequent arms with a different port are rejected. This closes the v1 open question about per-tunnel ports.

**Do cv5-spike VMs have a second NIC?**
Azure VM SKUs used in the spike (see `setup-vmA.sh`) may only expose one accelerated NIC. If so, Slice B Azure validation is blocked until a second NIC is provisioned. Slice A can be validated today with the existing single-NIC setup by arming the NIC, disarming, and re-arming — no second physical NIC needed for that path.

**Decap loopback attribution for tenant separation — does it matter?**
With two tunnels and one loopback used for decap attribution, decapped traffic from both tenants arrives on the same overlay interface. If VRF separation per tenant is required (different FIB table per loopback), decap must attribute packets to the tunnel-specific loopback. This requires reading `outer_src` in decap and matching it to a tunnel's `src_prefix` — a more expensive per-packet lookup. Defer this until VRF separation is an explicit requirement; it is not needed for the cv5/azure POC.

**API version bump for removing `TUNNEL_PARAM_MISMATCH`?**
Callers that expected this error (e.g., orchestration code that treats it as "NIC already claimed") will silently get success instead. Decide whether to bump to `overlay_arm_v2` or document the behavioral change in the existing `v1` comment. Low risk for the cv5/azure POC since the only caller is the Go test harness and `setup-vmA.sh`.
