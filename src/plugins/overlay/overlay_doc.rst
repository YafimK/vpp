.. SPDX-License-Identifier: Apache-2.0
.. Copyright (c) 2026 Check Point Software Technologies, Ltd.

SRv6-over-UDP overlay tunnel
============================

Overview
--------

The ``overlay`` plugin transports SRv6 traffic between PoPs across an Azure
VNet underlay. Azure SDN drops native SRv6 packets (IPv6 Routing Header type
4), so the plugin wraps each outgoing SRv6 packet in an outer IPv6 + UDP
header that Azure treats as plain UDP, and strips that header on the receiving
node before re-injecting the inner packet into the normal IPv6 / SR pipeline.

Use this plugin when running an SRv6 dataplane on Azure VMs (typically
AKS worker nodes peered via Global VNet Peering) where native SRv6 cannot
traverse the SDN. It is stateless by construction: there is no per-peer
configuration, no route distribution, and no mesh controller — a new node
joining the cluster is reachable to every other node without any
configuration change.

This document describes Phase 1 of the plugin, which provides the control
plane (binary API, CLI, dump). The encap and decap dataplane nodes are
delivered in subsequent phases.

Architecture
------------

The plugin follows an *encap-on-egress / decap-on-ingress* model and is
modelled on ``src/plugins/ipip/``:

* **Encap** runs as an ``ip6-output`` feature, armed per dataplane NIC. It
  matches packets whose IPv6 source address falls within a configured pod
  SID prefix (typically a /48). Matching packets are wrapped; everything
  else passes through unchanged.

* **Decap** is a graph node registered against a configured UDP destination
  port in the IPv6 UDP dispatch table (``udp_register_dst_port`` with
  ``is_ip4 = 0``). It strips the outer IPv6+UDP header and re-injects the
  inner packet into ``ip6-input``, where SR processing fires normally.

Wire format:

.. code-block:: text

   Outer IPv6 [src=inner_src, dst=inner_dst, hop_limit=128]
   UDP        [src=entropy(inner 5-tuple), dst=tunnel->dst_port]
   Inner IPv6 [src=A, dst=SID_B] + SRH + payload

The outer IPv6 source and destination are **copied directly** from the inner
header. This works because the inner destination is already a routable Azure
VNet IPv6 address (the SID belongs to the destination node's VNet prefix), so
the existing adjacency resolved by ``ip6-lookup`` is correct for the encapped
packet — no second FIB lookup, no mapping table, no per-peer state. The outer
hop-limit is set to 128 to absorb the one-hop decrement applied by Azure vWAN
hubs (VNet peering does not decrement).

The encap node saves ``vnet_buffer(b)->ip.adj_index[VLIB_TX]`` before
prepending the outer header and restores it after, then forwards directly to
``ip6-rewrite``. This both avoids the redundant FIB lookup and prevents the
re-encap loop that would occur if the encapped packet re-traversed
``ip6-output``.

Configuration
-------------

The plugin exposes three CLI commands. The first ``overlay arm`` call lazily
creates the tunnel object and the ``overlay0`` loopback interface; subsequent
calls arm additional dataplane NICs against the same tunnel (the tunnel
parameters must match). When the last NIC is disarmed the tunnel is
destroyed automatically.

.. code-block:: console

   overlay arm <iface> src <local-ipv6> pod-sid-prefix <prefix>/<len> dst-port <port>
   overlay disarm <iface>
   show overlay

Worked example — arm encap on ``HundredGigabitEthernet0/0/0`` for pod SIDs
in ``fd00:cafe::/48``, using UDP destination port 6635:

.. code-block:: console

   vpp# overlay arm HundredGigabitEthernet0/0/0 src fd00:abcd::1 \
          pod-sid-prefix fd00:cafe::/48 dst-port 6635
   vpp# show overlay
   overlay tunnel:
     src:              fd00:abcd::1
     pod-sid-prefix:   fd00:cafe::/48
     dst-port:         6635
     overlay-sw-if:    loop0 (sw_if_index 3)
     armed NICs (1):
       HundredGigabitEthernet0/0/0 (sw_if_index 1)

Per-tunnel byte/packet counters are exported via the standard interface
infrastructure (``show interface overlay0``) and the stats segment under
``/net/overlay-tunnel``.

API
---

The binary API is defined in ``overlay.api``:

* ``overlay_arm_v1`` — arm or disarm the encap feature on a single
  dataplane NIC. The first call with ``enable=true`` lazily creates the
  tunnel from the supplied parameters; subsequent arming calls must pass
  matching parameters. The last disarm destroys the tunnel. Reserved
  Azure UDP ports 4791 and 65330 are rejected.
* ``overlay_v1_dump`` / ``overlay_v1_details`` — return the current tunnel
  configuration and the list of armed NIC ``sw_if_index`` values.

All messages carry a ``_v1`` suffix; the API is versioned from the start.

Operational notes
-----------------

* **Reserved UDP ports.** Azure reserves UDP 4791 (RoCEv2) and 65330
  (Azure WireServer). Do not configure either as ``dst_port`` — the plugin
  rejects them.
* **MTU.** The outer wrapper adds 48 bytes (40 IPv6 + 8 UDP). On a
  1500-byte VNet MTU the effective inner MTU is **1452 bytes**. Inside that
  budget the inner IPv6 header (40), SRH (8 + 16·N for N SIDs), and L4
  header further reduce the L4 payload size.
* **TCP MSS clamping.** Azure blocks outbound ICMP by default, so PMTU
  discovery does not work. Clamp the TCP MSS option in SYN/SYN-ACK to the
  largest value that fits within 1452 bytes given the SR list depth. For a
  single-segment SR list the correct clamp is **MSS = 1368**. Multi-segment
  lists require a lower clamp (≈ MSS = 1352 for N=2, MSS = 1336 for N=3).
  Use the ``tcp-mss-clamping`` plugin on the overlay interface; the encap
  feature is registered with ``runs_after = tcp-mss-clamping`` so the clamp
  applies before encapsulation.
* **UDP checksum.** IPv6 requires a non-zero UDP checksum (RFC 2460); the
  encap node uses NIC TX offload via ``VNET_BUFFER_F_OFFLOAD_UDP_CKSUM`` and
  sets ``l3_hdr_offset`` / ``l4_hdr_offset`` for the NIC.
* **ECMP entropy.** Outer IPv6 src/dst are constant for a given node pair,
  so ECMP across Azure backbone paths comes entirely from the outer UDP
  source port, computed as a flow hash of the inner 5-tuple
  (``ip6_compute_flow_hash``).
* **Single overlay hop.** Encap happens at the source PoP and decap at the
  destination PoP. Intermediate Azure routers see plain IPv6+UDP — they do
  not participate in SR. Multi-segment SR lists are processed end-to-end
  inside the inner packet, not by the underlay.

Known limitations
-----------------

* **vWAN topology not supported.** Azure vWAN hubs do not carry native IPv6
  in transit, so this design (IPv6 outer) only works over Global VNet
  Peering. A vWAN deployment requires an IPv4 outer variant, which is out
  of scope for this plugin.
* **Single-segment SR list assumed for MSS clamping.** The recommended MSS
  of 1368 covers a one-SID list. Deployments using deeper SR lists must
  lower the clamp accordingly.
* **No PMTU discovery.** Azure blocks outbound ICMP — MSS clamping is the
  only mechanism keeping flows under the path MTU.
* **One tunnel per node.** The design intentionally supports a single
  overlay tunnel instance; multiple dataplane NICs are armed against that
  one tunnel via repeated ``overlay arm`` calls.

References
----------

The full design specification — including POC validation results, encap
node pseudocode, performance expectations, and resolved design decisions —
lives in the ``cv5-azure-sfc-arch`` repository at
``docs/srv6_udp_overlay_vpp.md``.
