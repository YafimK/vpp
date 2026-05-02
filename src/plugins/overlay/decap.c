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
#include <vnet/ip/ip.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_local.h>
#include <vnet/udp/udp_packet.h>

#include <overlay/overlay.h>

typedef enum
{
  OVERLAY_DECAP_NEXT_IP6_INPUT,
  OVERLAY_DECAP_NEXT_DROP,
  OVERLAY_DECAP_N_NEXT,
} overlay_decap_next_t;

static char *overlay_decap_error_strings[] = {
#define _(sym, str) str,
  foreach_overlay_decap_error
#undef _
};

static u8 *
format_overlay_decap_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  overlay_decap_trace_t *t = va_arg (*args, overlay_decap_trace_t *);

  s = format (s, "overlay-decap: outer %U -> %U udp %u -> %u",
	      format_ip6_address, &t->outer_src, format_ip6_address,
	      &t->outer_dst, t->outer_sport, t->outer_dport);
  return s;
}

VLIB_NODE_FN (overlay_decap_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_left = frame->n_vectors;
  u32 *from = vlib_frame_vector_args (frame);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  overlay_main_t *om = &overlay_main;
  u32 n_decapsulated = 0, n_bad_length = 0, n_no_tunnel = 0;
  u32 overlay_rx_sw_if_index = ~0;

  /* Resolve the overlay sw_if_index once per frame — Phase 1 has a single
     tunnel, so all decapped packets are attributed to it. */
  if (PREDICT_TRUE (om->active_tunnel_index != ~0))
    {
      overlay_tunnel_t *t =
	pool_elt_at_index (om->tunnels, om->active_tunnel_index);
      overlay_rx_sw_if_index = t->sw_if_index;
    }

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left > 0)
    {
      vlib_buffer_t *b0 = b[0];

      /* udp46_local_inline already advanced past the UDP header before
	 dispatching to us; current_data therefore points at the inner
	 IPv6 packet. The outer UDP and outer IPv6 sit immediately
	 before in the buffer — usable for tracing. */
      u8 *inner = vlib_buffer_get_current (b0);
      udp_header_t *udp0 = (udp_header_t *) (inner - sizeof (udp_header_t));
      ip6_header_t *outer0 =
	(ip6_header_t *) ((u8 *) udp0 - sizeof (ip6_header_t));

      if (PREDICT_FALSE (overlay_rx_sw_if_index == ~0))
	{
	  next[0] = OVERLAY_DECAP_NEXT_DROP;
	  b0->error = node->errors[OVERLAY_DECAP_ERROR_NO_TUNNEL];
	  n_no_tunnel++;
	  goto trace0;
	}

      /* Inner must be at least an IPv6 header. */
      if (PREDICT_FALSE (vlib_buffer_length_in_chain (vm, b0) <
			 sizeof (ip6_header_t)))
	{
	  next[0] = OVERLAY_DECAP_NEXT_DROP;
	  b0->error = node->errors[OVERLAY_DECAP_ERROR_BAD_LENGTH];
	  n_bad_length++;
	  goto trace0;
	}

      /* current_data already at inner IPv6 — no further advance needed.
	 Fix metadata so ip6-input sees a clean IPv6 packet. */
      vnet_buffer (b0)->l3_hdr_offset = b0->current_data;
      b0->flags &= ~(VNET_BUFFER_F_L4_CHECKSUM_COMPUTED |
		     VNET_BUFFER_F_L4_CHECKSUM_CORRECT |
		     VNET_BUFFER_F_OFFLOAD);
      b0->flags |= VNET_BUFFER_F_L3_HDR_OFFSET_VALID;

      /* Attribute decapped traffic to the overlay interface. */
      vnet_buffer (b0)->sw_if_index[VLIB_RX] = overlay_rx_sw_if_index;

      next[0] = OVERLAY_DECAP_NEXT_IP6_INPUT;
      n_decapsulated++;

    trace0:
      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  overlay_decap_trace_t *tr =
	    vlib_add_trace (vm, node, b0, sizeof (*tr));
	  tr->outer_src = outer0->src_address;
	  tr->outer_dst = outer0->dst_address;
	  tr->outer_sport = clib_net_to_host_u16 (udp0->src_port);
	  tr->outer_dport = clib_net_to_host_u16 (udp0->dst_port);
	}

      b++;
      next++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  vlib_node_increment_counter (vm, overlay_decap_node.index,
			       OVERLAY_DECAP_ERROR_DECAPSULATED,
			       n_decapsulated);
  if (n_bad_length)
    vlib_node_increment_counter (vm, overlay_decap_node.index,
				 OVERLAY_DECAP_ERROR_BAD_LENGTH, n_bad_length);
  if (n_no_tunnel)
    vlib_node_increment_counter (vm, overlay_decap_node.index,
				 OVERLAY_DECAP_ERROR_NO_TUNNEL, n_no_tunnel);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (overlay_decap_node) = {
  .name = "overlay-decap",
  .vector_size = sizeof (u32),
  .format_trace = format_overlay_decap_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = OVERLAY_DECAP_N_ERROR,
  .error_strings = overlay_decap_error_strings,
  .n_next_nodes = OVERLAY_DECAP_N_NEXT,
  .next_nodes = {
    [OVERLAY_DECAP_NEXT_IP6_INPUT] = "ip6-input",
    [OVERLAY_DECAP_NEXT_DROP]      = "error-drop",
  },
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
