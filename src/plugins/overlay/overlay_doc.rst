.. SPDX-License-Identifier: Apache-2.0
.. Copyright (c) 2026 Check Point Software Technologies, Ltd.

SRv6-over-UDP overlay tunnel
============================

Overview
--------

The ``overlay`` plugin transports SRv6 traffic across an IPv6 underlay
that drops native packets carrying IPv6 Routing Header type 4 (a
constraint imposed by some public-cloud SDNs and other middleboxes). It
wraps each outgoing SRv6 packet in an outer IPv6+UDP header that the
underlay treats as plain UDP, and strips that header on the receiving
node before re-injecting the inner packet into the IPv6 / SR pipeline.

The plugin is stateless by construction: there is no per-peer
configuration, no route distribution, and no mesh controller. A new
peer becomes reachable as soon as its destination address is routable
on the underlay.

Architecture
------------

The plugin follows an *encap-on-egress / decap-on-ingress* model:

* **Encap** runs as an ``ip6-output`` feature, armed per dataplane NIC.
  It matches packets whose IPv6 source address falls within a
  configured local source prefix (``src_prefix``). Matching packets are
  wrapped; everything else continues down the feature chain unchanged
  via ``vnet_feature_next``.

* **Decap** is a graph node registered against a configured UDP
  destination port in the IPv6 UDP dispatch table
  (``udp_register_dst_port`` with ``is_ip4 = 0``). It strips the outer
  IPv6+UDP header and re-injects the inner packet into ``ip6-input``,
  where SR processing fires normally.

Wire format:

.. code-block:: text

   Outer IPv6 [src=inner_src, dst=inner_dst, hop_limit=128]
   UDP        [src=hash(inner 5-tuple), dst=tunnel->dst_port]
   Inner IPv6 [src=A, dst=B] + SRH + payload

The outer IPv6 source and destination are **copied verbatim from the
inner header**. This works because the inner destination must be
routable on the underlay (the deployer is responsible for ensuring
this); the existing adjacency resolved by ``ip6-lookup`` is therefore
correct for the encapped packet, and the L2 rewrite stamped by
``ip6-rewrite`` is reused without a second FIB lookup.

The encap node anchors on the ``ip6-output`` arc with
``runs_after = tcp-mss-clamping`` and ``runs_before = interface-output``
so its position in the chain is invariant under the addition of other
features.

Configuration
-------------

The plugin exposes three CLI commands. The first ``overlay arm`` call
lazily creates the tunnel object and the ``overlay0`` loopback
interface; subsequent calls arm additional dataplane NICs against the
same tunnel (the tunnel parameters must match). When the last NIC is
disarmed the tunnel is destroyed automatically.

.. code-block:: console

   overlay arm <iface> src <local-ipv6> src-prefix <prefix>/<len> dst-port <port>
   overlay disarm <iface>
   show overlay

Worked example — arm encap on ``HundredGigabitEthernet0/0/0`` for
sources in ``fd00:cafe::/48``, using UDP destination port 6635:

.. code-block:: console

   vpp# overlay arm HundredGigabitEthernet0/0/0 src fd00:abcd::1 \
          src-prefix fd00:cafe::/48 dst-port 6635
   vpp# show overlay
   overlay tunnel:
     src:              fd00:abcd::1
     src-prefix:       fd00:cafe::/48
     dst-port:         6635
     overlay-sw-if:    loop0 (sw_if_index 3)
     armed NICs (1):
       HundredGigabitEthernet0/0/0 (sw_if_index 1)

Per-tunnel byte/packet counters are exported via the standard
interface infrastructure (``show interface overlay0``) and the stats
segment under ``/net/overlay-tunnel``.

API
---

The binary API is defined in ``overlay.api``:

* ``overlay_arm_v1`` — arm or disarm the encap feature on a single
  dataplane NIC. The first call with ``enable=true`` lazily creates the
  tunnel from the supplied parameters; subsequent arming calls must
  pass matching parameters. The last disarm destroys the tunnel.
* ``overlay_v1_dump`` / ``overlay_v1_details`` — return the current
  tunnel configuration and the list of armed NIC ``sw_if_index``
  values.

All messages carry a ``_v1`` suffix; the API is versioned from the
start.

Operational notes
-----------------

* **MTU.** The outer wrapper adds 48 bytes (40 IPv6 + 8 UDP). On a
  1500-byte underlay MTU the effective inner MTU is **1452 bytes**.
  Inside that budget the inner IPv6 header (40), SRH (8 + 16·N for N
  SIDs), and L4 header further reduce the L4 payload size.
* **TCP MSS clamping.** Where PMTU discovery is not reliable (some
  cloud underlays drop outbound ICMP), clamp the TCP MSS option in
  SYN/SYN-ACK to the largest value that fits within 1452 bytes given
  the SR list depth. For a single-segment SR list the correct clamp is
  **MSS = 1368**; multi-segment lists require a lower clamp
  (≈ 1352 for N=2, 1336 for N=3). Use the ``tcp-mss-clamping`` plugin
  on the dataplane interface — the encap feature anchors with
  ``runs_after = tcp-mss-clamping`` so MSS is clamped on the inner
  packet before encap.
* **UDP checksum.** IPv6 requires a non-zero UDP checksum (RFC 2460);
  the encap node uses NIC TX offload via
  ``VNET_BUFFER_OFFLOAD_F_UDP_CKSUM`` and sets ``l3_hdr_offset`` /
  ``l4_hdr_offset`` for the NIC.
* **ECMP entropy.** Outer IPv6 src/dst are constant for a given node
  pair, so underlay ECMP comes entirely from the outer UDP source
  port. The encap node walks past the SRH (extension header type 43)
  with ``ip6_ext_header_walk`` to reach the inner L4 5-tuple, then
  hashes via ``clib_xxhash``. The result is placed in the ephemeral
  port range 0xC000–0xFFFF.
  Note: stock ``ip6_compute_flow_hash`` does not walk past the SRH,
  so calling it directly would collapse entropy to per-pod-pair only.
* **Reserved underlay UDP ports.** Some underlays reserve specific UDP
  ports (e.g. 4791 / RoCEv2). The plugin does **not** filter these —
  the deployer chooses ``dst_port`` to avoid collisions on the
  underlay in use.
* **Single overlay hop.** Encap happens at the source node and decap
  at the destination node. Intermediate underlay routers see plain
  IPv6+UDP and do not participate in SR. Multi-segment SR lists are
  processed end-to-end by the inner packet, not by the underlay.

Known limitations
-----------------

* **IPv4 outer not supported.** The encap path uses an IPv6 outer
  header; underlays that do not carry IPv6 in transit are out of
  scope.
* **No PMTU discovery handling.** MSS clamping is the only mechanism
  keeping inner flows under the path MTU; deployers must clamp
  explicitly.
* **One tunnel per node.** The design supports a single overlay
  tunnel instance; multiple dataplane NICs are armed against that one
  tunnel via repeated ``overlay arm`` calls.

Observability
-------------

* ``show node overlay-encap`` / ``show node overlay-decap`` — node
  state and multi-arch variant selection (``hsw`` / ``skx`` / ``icl``
  / ``default``).
* ``show errors`` — per-node counters
  (``ENCAPSULATED`` / ``PASSED_THROUGH`` / ``NO_TUNNEL`` for encap;
  ``DECAPSULATED`` / ``BAD_LENGTH`` / ``NO_TUNNEL`` for decap).
* ``trace add <node> <count>`` then ``show trace`` — per-packet trace
  records with the encap/decap outer-header values.
* ``pcap trace rx|tx on intfc <nic>`` — wire-byte capture of the
  encapsulated frames for offline inspection.

References
----------

* ``src/plugins/ipip/`` — closest reference for the tunnel-plugin
  structure.
* ``src/vnet/srv6/`` — SRv6 segment routing primitives this plugin
  composes with.
