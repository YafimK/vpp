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
   current + save_rewrite_length. We continue the arc with
   vnet_feature_next_u16 — short-circuiting to ip6-rewrite would re-trigger
   the arc and loop. */

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

/* Compute the outer UDP source port for an SRv6 inner packet. Stock
   ip6_compute_flow_hash() walks only HBH (0) and Fragmentation (44)
   extension headers; the SRH (43) is not in its list, so for SRv6 it
   returns a hash dominated by the inner src/dst alone. We walk the SRH
   explicitly via ip6_ext_header_walk to reach the true inner L4 5-tuple,
   then mix everything through clib_xxhash and place the result in an
   ECMP-friendly ephemeral range. */
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
    return format (s, "overlay-encap: pass-through (src not in any matcher)");

  return format (
    s, "overlay-encap: nic %u outer src %U -> outer dst %U udp %u -> %u",
    t->nic_index, format_ip6_address, &t->outer_src, format_ip6_address,
    &t->outer_dst, t->outer_sport, t->outer_dport);
}

/* Per-packet outcome — keeps counter + trace bookkeeping in sync. */
typedef enum
{
  OVERLAY_ENCAP_OUTCOME_ENCAP,
  OVERLAY_ENCAP_OUTCOME_PASS,
  OVERLAY_ENCAP_OUTCOME_NO_TUNNEL,
} overlay_encap_outcome_t;

/* Walk the NIC's matcher slots, longest-prefix first. Returns 1 if the
   inner_src lies in any matcher, 0 otherwise. The caller has already
   bounded n_matchers to OVERLAY_MAX_MATCHERS_PER_NIC. */
static_always_inline int
overlay_match_inner_src (overlay_armed_nic_t *anic,
			 const ip6_address_t *inner_src)
{
  /* N=1 fast path — inlined by the caller already, but keep here for the
     N>=2 fallback. */
  u8 n = anic->n_matchers;
  if (n == 0)
    return 0;
  {
    overlay_matcher_t *m = &anic->matchers0;
    if (ip6_address_is_equal_masked (inner_src, &m->src_prefix,
				     &m->src_prefix_mask))
      return 1;
  }
  for (u8 i = 1; i < n; i++)
    {
      overlay_matcher_t *m = &anic->matchers12[i - 1];
      if (ip6_address_is_equal_masked (inner_src, &m->src_prefix,
				       &m->src_prefix_mask))
	return 1;
    }
  return 0;
}

static_always_inline overlay_encap_outcome_t
overlay_encap_one (vlib_main_t *vm, vlib_node_runtime_t *node,
		   overlay_main_t *om, vlib_buffer_t *b, u16 *next,
		   u32 *cached_tx_sw_if, overlay_armed_nic_t **cached_anic,
		   u32 *out_nic_index)
{
  const u32 hdr_overhead = sizeof (ip6_header_t) + sizeof (udp_header_t);
  u32 tx_sw_if = vnet_buffer (b)->sw_if_index[VLIB_TX];
  u32 rw_len = vnet_buffer (b)->ip.save_rewrite_length;

  u8 *l2_orig = vlib_buffer_get_current (b);
  ip6_header_t *inner = (ip6_header_t *) (l2_orig + rw_len);

  /* Refresh hoisted scalars on NIC change. The common case (whole frame
     comes from the same egress NIC) is a single register compare. */
  if (PREDICT_FALSE (tx_sw_if != *cached_tx_sw_if))
    {
      u32 idx = ~0u;
      if (tx_sw_if < vec_len (om->armed_nic_index_by_sw_if))
	idx = om->armed_nic_index_by_sw_if[tx_sw_if];
      if (PREDICT_FALSE (idx == ~0u))
	{
	  /* NIC unarmed — leave the hoisted scalars alone (don't poison the
	     cache for subsequent same-NIC packets in this frame). */
	  *out_nic_index = ~0u;
	  *next = OVERLAY_ENCAP_NEXT_DROP;
	  b->error = node->errors[OVERLAY_ENCAP_ERROR_NO_TUNNEL];
	  return OVERLAY_ENCAP_OUTCOME_NO_TUNNEL;
	}
      *cached_anic = pool_elt_at_index (om->armed_nics, idx);
      *cached_tx_sw_if = tx_sw_if;
    }

  overlay_armed_nic_t *anic = *cached_anic;
  /* Trace surfaces the NIC's sw_if_index — this is what operators see in
     `vppctl show interface` and is stable across pool reuse. */
  *out_nic_index = anic->sw_if_index;

  /* N=1 inline fast path. matchers0 is in the same cache line as anic, so
     once `anic` is in L1 the matcher compare is free. Predicted true: the
     overwhelmingly common deployment shape is a single src_prefix per NIC. */
  ip6_address_t inner_src = inner->src_address;
  int matched;
  if (PREDICT_TRUE (anic->n_matchers == 1))
    {
      overlay_matcher_t *m = &anic->matchers0;
      matched = ip6_address_is_equal_masked (&inner_src, &m->src_prefix,
					     &m->src_prefix_mask);
    }
  else
    {
      matched = overlay_match_inner_src (anic, &inner_src);
    }

  if (!matched)
    {
      vnet_feature_next_u16 (next, b);
      b->error = node->errors[OVERLAY_ENCAP_ERROR_PASSED_THROUGH];
      return OVERLAY_ENCAP_OUTCOME_PASS;
    }

  /* Encap path. Outer dst == inner dst (the design's central trick). The
     L2 rewrite ip6-rewrite stamped is correct for the outer packet too —
     no second FIB lookup needed. Outer src == inner src (Slice C: there
     is no per-NIC outer_src config any more). */
  ip6_address_t inner_dst = inner->dst_address;
  u16 sport = overlay_outer_udp_sport (b, inner);
  u16 dst_port_n = anic->dst_port_n;

  ASSERT (rw_len <= 64);
  u8 l2_save[64];
  clib_memcpy_fast (l2_save, l2_orig, rw_len);

  vlib_buffer_advance (b, -(i32) hdr_overhead);
  u8 *new_head = vlib_buffer_get_current (b);
  clib_memcpy_fast (new_head, l2_save, rw_len);

  ip6_header_t *outer = (ip6_header_t *) (new_head + rw_len);
  udp_header_t *udp = (udp_header_t *) (outer + 1);
  u32 pkt_len = vlib_buffer_length_in_chain (vm, b);
  u16 inner_total = pkt_len - rw_len - sizeof (ip6_header_t);

  outer->ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 (0x60000000);
  outer->payload_length = clib_host_to_net_u16 (inner_total);
  outer->protocol = IP_PROTOCOL_UDP;
  outer->hop_limit = 128;
  outer->src_address = inner_src;
  outer->dst_address = inner_dst;

  udp->src_port = clib_host_to_net_u16 (sport);
  udp->dst_port = dst_port_n;
  udp->length = clib_host_to_net_u16 (inner_total);
  udp->checksum = 0;

  vnet_buffer (b)->l3_hdr_offset = (u8 *) outer - b->data;
  vnet_buffer (b)->l4_hdr_offset = (u8 *) udp - b->data;
  b->flags |= VNET_BUFFER_F_IS_IP6 | VNET_BUFFER_F_OFFLOAD |
	      VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
	      VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
  vnet_buffer (b)->oflags |= VNET_BUFFER_OFFLOAD_F_UDP_CKSUM;

  vlib_increment_combined_counter (&om->nic_counters, vm->thread_index,
				   anic - om->armed_nics, 1, pkt_len);

  vnet_feature_next_u16 (next, b);
  return OVERLAY_ENCAP_OUTCOME_ENCAP;
}

static_always_inline void
overlay_encap_trace_one (vlib_main_t *vm, vlib_node_runtime_t *node,
			 vlib_buffer_t *b, u32 nic_index,
			 overlay_encap_outcome_t outcome, u16 next)
{
  if (PREDICT_TRUE (!(b->flags & VLIB_BUFFER_IS_TRACED)))
    return;

  overlay_encap_trace_t *tr = vlib_add_trace (vm, node, b, sizeof (*tr));
  tr->nic_index = nic_index;
  tr->passed_through = (outcome == OVERLAY_ENCAP_OUTCOME_PASS);

  if (outcome == OVERLAY_ENCAP_OUTCOME_ENCAP &&
      next != OVERLAY_ENCAP_NEXT_DROP)
    {
      u32 rw_len = vnet_buffer (b)->ip.save_rewrite_length;
      ip6_header_t *outer_h =
	(ip6_header_t *) (vlib_buffer_get_current (b) + rw_len);
      udp_header_t *udp_h = (udp_header_t *) (outer_h + 1);
      tr->outer_src = outer_h->src_address;
      tr->outer_dst = outer_h->dst_address;
      tr->outer_sport = clib_net_to_host_u16 (udp_h->src_port);
      tr->outer_dport = clib_net_to_host_u16 (udp_h->dst_port);
    }
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

  /* Per-frame hoisted scalars. Refreshed inside overlay_encap_one when
     VLIB_TX changes — the common case (whole frame from one NIC) keeps
     them stable, so the inner loop avoids the vec/pool deref pair. This
     mirrors the bypass node's Slice B pattern. */
  u32 cached_tx_sw_if = ~0u;
  overlay_armed_nic_t *cached_anic = NULL;

  vlib_get_buffers (vm, from, bufs, n_left);

  /* Dual loop: process two packets while prefetching the next two. */
  while (n_left >= 4)
    {
      vlib_prefetch_buffer_header (b[2], LOAD);
      vlib_prefetch_buffer_header (b[3], LOAD);
      CLIB_PREFETCH (b[2]->data - CLIB_CACHE_LINE_BYTES,
		     2 * CLIB_CACHE_LINE_BYTES, LOAD);
      CLIB_PREFETCH (b[3]->data - CLIB_CACHE_LINE_BYTES,
		     2 * CLIB_CACHE_LINE_BYTES, LOAD);

      u32 ni0, ni1;
      overlay_encap_outcome_t o0 = overlay_encap_one (
	vm, node, om, b[0], &next[0], &cached_tx_sw_if, &cached_anic, &ni0);
      overlay_encap_outcome_t o1 = overlay_encap_one (
	vm, node, om, b[1], &next[1], &cached_tx_sw_if, &cached_anic, &ni1);

      n_encap += (o0 == OVERLAY_ENCAP_OUTCOME_ENCAP);
      n_encap += (o1 == OVERLAY_ENCAP_OUTCOME_ENCAP);
      n_pass += (o0 == OVERLAY_ENCAP_OUTCOME_PASS);
      n_pass += (o1 == OVERLAY_ENCAP_OUTCOME_PASS);
      n_no_tunnel += (o0 == OVERLAY_ENCAP_OUTCOME_NO_TUNNEL);
      n_no_tunnel += (o1 == OVERLAY_ENCAP_OUTCOME_NO_TUNNEL);

      overlay_encap_trace_one (vm, node, b[0], ni0, o0, next[0]);
      overlay_encap_trace_one (vm, node, b[1], ni1, o1, next[1]);

      b += 2;
      next += 2;
      n_left -= 2;
    }

  while (n_left > 0)
    {
      u32 ni0;
      overlay_encap_outcome_t o0 = overlay_encap_one (
	vm, node, om, b[0], &next[0], &cached_tx_sw_if, &cached_anic, &ni0);

      n_encap += (o0 == OVERLAY_ENCAP_OUTCOME_ENCAP);
      n_pass += (o0 == OVERLAY_ENCAP_OUTCOME_PASS);
      n_no_tunnel += (o0 == OVERLAY_ENCAP_OUTCOME_NO_TUNNEL);

      overlay_encap_trace_one (vm, node, b[0], ni0, o0, next[0]);

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

/* ip6-output feature arc. Anchored after tcp-mss-clamping (so MSS clamp
   operates on the inner packet) and before interface-output (the arc
   terminus). Pinning both sides prevents future ip6-output features from
   drifting our position in the chain. */
VNET_FEATURE_INIT (overlay_encap_feature, static) = {
  .arc_name = "ip6-output",
  .node_name = "overlay-encap",
  .runs_after = VNET_FEATURES ("tcp-mss-clamping"),
  .runs_before = VNET_FEATURES ("interface-output"),
};

/* ---------------------------------------------------------------------------
   overlay-bypass: ip6-unicast feature that intercepts encap'd packets BEFORE
   ip6-lookup. Without this, packets whose outer dst is an SRv6 SID would be
   stolen by SR localsid (an exclusive FIB DPO) and never reach our udp-local
   decap path. Mirrors the ip6-vxlan-bypass pattern in vxlan/decap.c.
   --------------------------------------------------------------------------- */

typedef enum
{
  OVERLAY_BYPASS_NEXT_LOOKUP,
  OVERLAY_BYPASS_NEXT_DROP,
  OVERLAY_BYPASS_N_NEXT,
} overlay_bypass_next_t;

static char *overlay_bypass_error_strings[] = {
#define _(sym, str) str,
  foreach_overlay_bypass_error
#undef _
};

static u8 *
format_overlay_bypass_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  overlay_bypass_trace_t *t = va_arg (*args, overlay_bypass_trace_t *);

  s = format (s, "overlay-bypass: %s outer %U -> %U udp %u -> %u",
	      t->decapsulated ? "decapsulated" : "passed-through",
	      format_ip6_address, &t->outer_src, format_ip6_address,
	      &t->outer_dst, t->outer_sport, t->outer_dport);
  return s;
}

VLIB_NODE_FN (overlay_bypass_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_left = frame->n_vectors;
  u32 *from = vlib_frame_vector_args (frame);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  overlay_main_t *om = &overlay_main;
  u32 n_decap = 0, n_bad_length = 0, n_no_tunnel = 0;

  vlib_get_buffers (vm, from, bufs, n_left);

  /* Slice B/C scalar hoist: cache the (rx_sw_if -> NIC) resolution + the
     per-NIC constants the inner loop touches (expected dst port in net
     order, the global decap loopback sw_if_index used for attribution).
     Common case: a frame is entirely from one input NIC, so every packet
     after the first reduces to a single rx_sw_if compare followed by
     register-resident compares. Heterogeneous frames re-resolve correctly. */
  u32 cached_rx_sw_if_index = ~0u;
  u16 cached_expected_dport_n = 0;
  u32 cached_overlay_rx_sw_if_index = ~0u;
  u32 anic_idx_by_sw_if_len = vec_len (om->armed_nic_index_by_sw_if);

  while (n_left > 0)
    {
      vlib_buffer_t *b0 = b[0];
      ip6_header_t *outer = vlib_buffer_get_current (b0);
      u8 decapsulated = 0;
      u16 outer_sport = 0, outer_dport = 0;
      ip6_address_t outer_src = outer->src_address;
      ip6_address_t outer_dst = outer->dst_address;

      /* Fast pass-through for non-UDP. */
      if (PREDICT_FALSE (outer->protocol != IP_PROTOCOL_UDP))
	{
	  vnet_feature_next_u16 (&next[0], b0);
	  goto trace0;
	}

      /* Length check: outer ip6 + udp + at least an inner ip6 header. */
      if (PREDICT_FALSE (vlib_buffer_length_in_chain (vm, b0) <
			 (sizeof (ip6_header_t) + sizeof (udp_header_t) +
			  sizeof (ip6_header_t))))
	{
	  next[0] = OVERLAY_BYPASS_NEXT_DROP;
	  b0->error = node->errors[OVERLAY_BYPASS_ERROR_BAD_LENGTH];
	  n_bad_length++;
	  goto trace0;
	}

      udp_header_t *udp = (udp_header_t *) (outer + 1);
      outer_sport = clib_net_to_host_u16 (udp->src_port);
      outer_dport = clib_net_to_host_u16 (udp->dst_port);

      u32 rx_sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      if (PREDICT_FALSE (rx_sw_if_index != cached_rx_sw_if_index))
	{
	  u32 anic_idx = ~0u;
	  if (rx_sw_if_index < anic_idx_by_sw_if_len)
	    anic_idx = om->armed_nic_index_by_sw_if[rx_sw_if_index];

	  if (PREDICT_FALSE (anic_idx == ~0u))
	    {
	      /* Don't poison the cache: leave the hoisted constants
		 pointing at the last good NIC so subsequent same-NIC
		 packets in this frame keep the fast path. */
	      vnet_feature_next_u16 (&next[0], b0);
	      n_no_tunnel++;
	      goto trace0;
	    }

	  overlay_armed_nic_t *anic =
	    pool_elt_at_index (om->armed_nics, anic_idx);
	  cached_rx_sw_if_index = rx_sw_if_index;
	  cached_expected_dport_n = anic->dst_port_n;
	  cached_overlay_rx_sw_if_index = anic->loopback_sw_if;
	}

      /* Wrong port — pass through (not for us, not an error). */
      if (udp->dst_port != cached_expected_dport_n)
	{
	  vnet_feature_next_u16 (&next[0], b0);
	  goto trace0;
	}

      /* Match — strip outer ip6 + udp, hand to ip6-lookup so the inner
	 dst (typically an SRv6 SID) hits SR localsid as intended. */
      vlib_buffer_advance (b0,
			   sizeof (ip6_header_t) + sizeof (udp_header_t));
      vnet_buffer (b0)->sw_if_index[VLIB_RX] = cached_overlay_rx_sw_if_index;
      vnet_buffer (b0)->l3_hdr_offset = b0->current_data;
      b0->flags &= ~(VNET_BUFFER_F_L4_CHECKSUM_COMPUTED |
		     VNET_BUFFER_F_L4_CHECKSUM_CORRECT |
		     VNET_BUFFER_F_OFFLOAD);
      b0->flags |= VNET_BUFFER_F_L3_HDR_OFFSET_VALID;
      next[0] = OVERLAY_BYPASS_NEXT_LOOKUP;
      decapsulated = 1;
      n_decap++;

    trace0:
      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  overlay_bypass_trace_t *tr =
	    vlib_add_trace (vm, node, b0, sizeof (*tr));
	  tr->outer_src = outer_src;
	  tr->outer_dst = outer_dst;
	  tr->outer_sport = outer_sport;
	  tr->outer_dport = outer_dport;
	  tr->decapsulated = decapsulated;
	}

      b++;
      next++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  if (n_decap)
    vlib_node_increment_counter (vm, overlay_bypass_node.index,
				 OVERLAY_BYPASS_ERROR_DECAPSULATED, n_decap);
  if (n_bad_length)
    vlib_node_increment_counter (vm, overlay_bypass_node.index,
				 OVERLAY_BYPASS_ERROR_BAD_LENGTH,
				 n_bad_length);
  if (n_no_tunnel)
    vlib_node_increment_counter (vm, overlay_bypass_node.index,
				 OVERLAY_BYPASS_ERROR_NO_TUNNEL, n_no_tunnel);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (overlay_bypass_node) = {
  .name = "overlay-bypass",
  .vector_size = sizeof (u32),
  .format_trace = format_overlay_bypass_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = OVERLAY_BYPASS_N_ERROR,
  .error_strings = overlay_bypass_error_strings,
  .n_next_nodes = OVERLAY_BYPASS_N_NEXT,
  .next_nodes = {
    [OVERLAY_BYPASS_NEXT_LOOKUP] = "ip6-lookup",
    [OVERLAY_BYPASS_NEXT_DROP]   = "error-drop",
  },
};

VNET_FEATURE_INIT (overlay_bypass_feature, static) = {
  .arc_name    = "ip6-unicast",
  .node_name   = "overlay-bypass",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
