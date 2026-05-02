/*
 * Copyright (c) 2026 Check Point Software Technologies, Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip6_inlines.h>
#include <vnet/udp/udp_packet.h>
#include <vppinfra/xxhash.h>

#include <overlay/overlay.h>

/* The ip6-output feature arc fires AFTER ip6-rewrite has stamped the L2
   header. At our node entry, vlib_buffer_get_current(b) points at the
   start of the L2 header; the inner IPv6 header sits at
   current + save_rewrite_length. We use vnet_feature_next_u16 to
   continue the arc rather than dispatching to a hardcoded next-node —
   short-circuiting to ip6-rewrite would re-trigger the arc and loop. */

typedef enum
{
  OVERLAY_ENCAP_NEXT_DROP,
  OVERLAY_ENCAP_N_NEXT,
} overlay_encap_next_t;

static char *overlay_encap_error_strings[] = {
#define _(sym, str) str,
  foreach_overlay_encap_error
#undef _
};

/* Compare the first `plen` bits of `addr` and `prefix`. The IPv6 words
   are stored network-order in `as_u64[2]`; the mask is built host-order
   then byte-swapped to match, so the bitwise compare stays in
   network-order space. */
static_always_inline u32
overlay_addr_in_prefix (const ip6_address_t *addr,
			const ip6_address_t *prefix, u8 plen)
{
  if (plen == 0)
    return 1;
  if (plen <= 64)
    {
      u64 mask = clib_host_to_net_u64 (((u64) ~0ULL) << (64 - plen));
      return (addr->as_u64[0] & mask) == (prefix->as_u64[0] & mask);
    }
  if (addr->as_u64[0] != prefix->as_u64[0])
    return 0;
  if (plen == 128)
    return addr->as_u64[1] == prefix->as_u64[1];
  u64 mask = clib_host_to_net_u64 (((u64) ~0ULL) << (128 - plen));
  return (addr->as_u64[1] & mask) == (prefix->as_u64[1] & mask);
}

/* Compute the outer UDP source port for an SRv6 inner packet.

   Stock ip6_compute_flow_hash() walks only the HBH (0) and Fragmentation
   (44) extension headers; the SRH (43) is not in its walk list, so for
   SRv6 it returns a hash dominated by the inner src/dst alone. We walk
   the SRH explicitly via ip6_ext_header_walk to reach the true inner
   L4 5-tuple, then mix everything through clib_xxhash and place the
   result in an ECMP-friendly ephemeral range. */
static_always_inline u16
overlay_outer_udp_sport (vlib_buffer_t *b, ip6_header_t *inner)
{
  ip6_ext_hdr_chain_t c;
  int last = ip6_ext_header_walk (b, inner, -1 /* find transport */, &c);
  u8 l4proto = (last >= 0) ? c.eh[last].protocol : inner->protocol;
  u32 sport = 0, dport = 0;

  if (last >= 0 &&
      (l4proto == IP_PROTOCOL_TCP || l4proto == IP_PROTOCOL_UDP))
    {
      udp_header_t *u =
	(udp_header_t *) ((u8 *) inner + c.eh[last].offset);
      sport = u->src_port;
      dport = u->dst_port;
    }

  u64 k1 = inner->src_address.as_u64[0] ^ inner->src_address.as_u64[1] ^
	   inner->dst_address.as_u64[0] ^ inner->dst_address.as_u64[1];
  u64 k2 = ((u64) l4proto << 32) | (((u32) sport) << 16) | (u32) dport;
  u64 h = clib_xxhash (k1 ^ k2);

  /* Ephemeral range 0xC000-0xFFFF, RFC 7510-style. */
  return 0xC000 | (u16) (h & 0x3FFF);
}

static u8 *
format_overlay_encap_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  overlay_encap_trace_t *t = va_arg (*args, overlay_encap_trace_t *);

  if (t->passed_through)
    return format (s, "overlay-encap: pass-through (src not in pod prefix)");

  return format (
    s, "overlay-encap: tunnel %u outer %U -> %U udp %u -> %u",
    t->tunnel_index, format_ip6_address, &t->outer_src, format_ip6_address,
    &t->outer_dst, t->outer_sport, t->outer_dport);
}

VLIB_NODE_FN (overlay_encap_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_left = frame->n_vectors;
  u32 *from = vlib_frame_vector_args (frame);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  overlay_main_t *om = &overlay_main;
  u32 n_encap = 0, n_pass = 0, n_no_tunnel = 0;
  const u32 hdr_overhead = sizeof (ip6_header_t) + sizeof (udp_header_t);

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left > 0)
    {
      vlib_buffer_t *b0 = b[0];
      u32 nic_sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
      u32 rw_len = vnet_buffer (b0)->ip.save_rewrite_length;
      u32 tunnel_index = ~0;
      overlay_tunnel_t *t = NULL;
      u8 passed_through = 0;

      /* current_data is at the L2 header (post ip6-rewrite). */
      u8 *l2_orig = vlib_buffer_get_current (b0);
      ip6_header_t *inner = (ip6_header_t *) (l2_orig + rw_len);

      if (nic_sw_if_index < vec_len (om->tunnel_index_by_nic))
	tunnel_index = om->tunnel_index_by_nic[nic_sw_if_index];

      if (PREDICT_FALSE (tunnel_index == ~0))
	{
	  next[0] = OVERLAY_ENCAP_NEXT_DROP;
	  b0->error = node->errors[OVERLAY_ENCAP_ERROR_NO_TUNNEL];
	  n_no_tunnel++;
	  goto trace0;
	}

      t = pool_elt_at_index (om->tunnels, tunnel_index);

      /* Source-prefix gate: only encap traffic from a pod SID in the
	 cluster's range. Everything else continues unchanged down the
	 feature chain. */
      if (!overlay_addr_in_prefix (&inner->src_address, &t->pod_sid_prefix,
				   t->pod_sid_prefix_len))
	{
	  vnet_feature_next_u16 (&next[0], b0);
	  b0->error = node->errors[OVERLAY_ENCAP_ERROR_PASSED_THROUGH];
	  n_pass++;
	  passed_through = 1;
	  goto trace0;
	}

      /* Encap path. The outer IPv6 dst equals the inner dst — that is
	 the design's central trick, since the SID is already a routable
	 Azure VNet address and the L2 rewrite ip6-rewrite already
	 stamped is correct for the outer packet too. */
      ip6_address_t inner_src = inner->src_address;
      ip6_address_t inner_dst = inner->dst_address;
      u16 sport = overlay_outer_udp_sport (b0, inner);

      /* Save the L2 rewrite into a local; we will reapply it at the
	 new buffer head once we have created room for outer ip6+udp.
	 Vector typically rw_len == 14 (Ethernet); guard the local. */
      ASSERT (rw_len <= 64);
      u8 l2_save[64];
      clib_memcpy_fast (l2_save, l2_orig, rw_len);

      /* Make hdr_overhead bytes of room before current_data. */
      vlib_buffer_advance (b0, -(i32) hdr_overhead);
      u8 *new_head = vlib_buffer_get_current (b0);

      /* New layout:
	 [new_head .. new_head+rw_len-1]            L2 (re-stamped)
	 [new_head+rw_len .. +rw_len+39]            outer IPv6
	 [new_head+rw_len+40 .. +rw_len+47]         outer UDP
	 [new_head+rw_len+48 .. ]                   inner IPv6 (untouched) */
      clib_memcpy_fast (new_head, l2_save, rw_len);

      ip6_header_t *outer = (ip6_header_t *) (new_head + rw_len);
      udp_header_t *udp = (udp_header_t *) (outer + 1);

      u16 inner_total =
	vlib_buffer_length_in_chain (vm, b0) - rw_len - sizeof (ip6_header_t);

      outer->ip_version_traffic_class_and_flow_label =
	clib_host_to_net_u32 (0x60000000);
      outer->payload_length = clib_host_to_net_u16 (inner_total);
      outer->protocol = IP_PROTOCOL_UDP;
      outer->hop_limit = 128; /* vWAN-safe headroom */
      outer->src_address = inner_src;
      outer->dst_address = inner_dst;

      udp->src_port = clib_host_to_net_u16 (sport);
      udp->dst_port = clib_host_to_net_u16 (t->dst_port);
      udp->length = clib_host_to_net_u16 (inner_total);
      udp->checksum = 0; /* TX offload fills it; IPv6 requires non-zero */

      /* L3 starts after L2; L4 starts after outer IPv6. */
      vnet_buffer (b0)->l3_hdr_offset = (u8 *) outer - b0->data;
      vnet_buffer (b0)->l4_hdr_offset = (u8 *) udp - b0->data;
      b0->flags |= VNET_BUFFER_F_IS_IP6 | VNET_BUFFER_F_OFFLOAD |
		   VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
		   VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
      vnet_buffer (b0)->oflags |= VNET_BUFFER_OFFLOAD_F_UDP_CKSUM;

      vlib_increment_combined_counter (
	&om->tunnel_counters, vm->thread_index, tunnel_index, 1,
	vlib_buffer_length_in_chain (vm, b0));

      /* Continue down the feature arc — typically straight to
	 interface-output since we anchor as the last feature. */
      vnet_feature_next_u16 (&next[0], b0);
      n_encap++;

    trace0:
      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  overlay_encap_trace_t *tr =
	    vlib_add_trace (vm, node, b0, sizeof (*tr));
	  tr->tunnel_index = tunnel_index;
	  tr->passed_through = passed_through;
	  if (!passed_through && t != NULL && next[0] != OVERLAY_ENCAP_NEXT_DROP)
	    {
	      ip6_header_t *outer_h =
		(ip6_header_t *) (vlib_buffer_get_current (b0) + rw_len);
	      udp_header_t *udp_h = (udp_header_t *) (outer_h + 1);
	      tr->outer_src = outer_h->src_address;
	      tr->outer_dst = outer_h->dst_address;
	      tr->outer_sport = clib_net_to_host_u16 (udp_h->src_port);
	      tr->outer_dport = clib_net_to_host_u16 (udp_h->dst_port);
	    }
	}

      b++;
      next++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  if (n_encap)
    vlib_node_increment_counter (vm, overlay_encap_node.index,
				 OVERLAY_ENCAP_ERROR_ENCAPSULATED, n_encap);
  if (n_pass)
    vlib_node_increment_counter (vm, overlay_encap_node.index,
				 OVERLAY_ENCAP_ERROR_PASSED_THROUGH, n_pass);
  if (n_no_tunnel)
    vlib_node_increment_counter (vm, overlay_encap_node.index,
				 OVERLAY_ENCAP_ERROR_NO_TUNNEL, n_no_tunnel);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (overlay_encap_node) = {
  .name = "overlay-encap",
  .vector_size = sizeof (u32),
  .format_trace = format_overlay_encap_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = OVERLAY_ENCAP_N_ERROR,
  .error_strings = overlay_encap_error_strings,
  .n_next_nodes = OVERLAY_ENCAP_N_NEXT,
  .next_nodes = {
    [OVERLAY_ENCAP_NEXT_DROP] = "error-drop",
  },
};

/* ip6-output feature arc: armed per-NIC by overlay_arm() via
   vnet_feature_enable_disable. Anchors:
     - runs_after  tcp-mss-clamping  so MSS clamp operates on the inner
       packet (we continue the arc via vnet_feature_next; anything
       upstream in the chain has already had a chance to fire).
     - runs_before interface-output  the arc terminus. Pinning both
       sides prevents future ip6-output features from drifting our
       position in the chain. */
VNET_FEATURE_INIT (overlay_encap_feature, static) = {
  .arc_name = "ip6-output",
  .node_name = "overlay-encap",
  .runs_after = VNET_FEATURES ("tcp-mss-clamping"),
  .runs_before = VNET_FEATURES ("interface-output"),
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
