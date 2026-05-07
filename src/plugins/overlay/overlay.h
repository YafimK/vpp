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

#ifndef __included_overlay_h__
#define __included_overlay_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip6_packet.h>
#include <vlib/vlib.h>

/* Per-tunnel state. Phase 1 has at most one entry in the pool;
   the pool stays open in case multi-tunnel becomes a need. */
typedef struct
{
  ip6_address_t src;	      /* informational; outer src is copied at runtime */
  ip6_address_t src_prefix;   /* /src_prefix_len source IPv6 range that
				 triggers encap on egress */
  ip6_address_t src_prefix_mask; /* pre-computed mask for src_prefix_len,
				    populated at arm time so the datapath
				    can use ip6_address_is_equal_masked()
				    instead of building the mask per-packet */
  u8 src_prefix_len;
  u16 dst_port;

  u32 sw_if_index;		/* the overlay interface */
  u32 *armed_nic_sw_if_indices; /* vec — dataplane NICs feature-armed */
} overlay_tunnel_t;

typedef struct
{
  overlay_tunnel_t *tunnels;	/* pool */
  u32 *tunnel_index_by_nic;	/* vec[nic_sw_if_index] = tunnel pool index, ~0 if unarmed */
  u32 active_tunnel_index;	/* Phase 1: at most one tunnel; ~0 when none */
  vnet_main_t *vnet_main;
  u16 msg_id_base;

  /* Per-tunnel TX combined counter; validated at plugin init.
     Indexed by tunnel pool index. */
  vlib_combined_counter_main_t tunnel_counters;
} overlay_main_t;

extern overlay_main_t overlay_main;

/* Result codes returned by overlay_arm() and surfaced via API/CLI. */
#define OVERLAY_RC_OK			   0
#define OVERLAY_RC_BAD_ARG		  -1
#define OVERLAY_RC_NIC_NOT_ARMED	  -3
#define OVERLAY_RC_TUNNEL_PARAM_MISMATCH  -4
#define OVERLAY_RC_INVALID_INTERFACE	  -5

/* Single source of truth for arm/disarm — used by API handler and CLI. */
int overlay_arm (u32 iface_sw_if_index, const ip6_address_t *src,
		 const ip6_address_t *src_prefix, u8 src_prefix_len,
		 u16 dst_port, int enable);

format_function_t format_overlay_state;

/* Decap node (defined in decap.c). Receives IPv6+UDP packets at the
   configured tunnel dst_port via the udp6 dispatch table, strips the
   outer headers, and re-injects to ip6-input so the inner SR pipeline
   runs unchanged. */
extern vlib_node_registration_t overlay_decap_node;

#define foreach_overlay_decap_error                                           \
  _ (DECAPSULATED, "packets decapsulated")                                    \
  _ (BAD_LENGTH, "inner packet too short")                                    \
  _ (NO_TUNNEL, "no tunnel configured for decap")

typedef enum
{
#define _(sym, str) OVERLAY_DECAP_ERROR_##sym,
  foreach_overlay_decap_error
#undef _
    OVERLAY_DECAP_N_ERROR,
} overlay_decap_error_t;

typedef struct
{
  ip6_address_t outer_src;
  ip6_address_t outer_dst;
  u16 outer_sport;
  u16 outer_dport;
} overlay_decap_trace_t;

/* Encap node (defined in node.c). Registered as an ip6-output feature
   on each armed dataplane NIC. For traffic whose inner src matches the
   configured src_prefix, prepends an outer IPv6+UDP wrapper (outer dst
   is copied verbatim from inner dst — the inner destination must be
   routable on the underlay). Other traffic on the same NIC is passed
   through unchanged. */
extern vlib_node_registration_t overlay_encap_node;

#define foreach_overlay_encap_error                                           \
  _ (ENCAPSULATED, "packets encapsulated")                                    \
  _ (PASSED_THROUGH, "non-matching-src packets passed through unchanged")     \
  _ (NO_TUNNEL, "no tunnel armed for this NIC")

typedef enum
{
#define _(sym, str) OVERLAY_ENCAP_ERROR_##sym,
  foreach_overlay_encap_error
#undef _
    OVERLAY_ENCAP_N_ERROR,
} overlay_encap_error_t;

typedef struct
{
  u32 tunnel_index;
  ip6_address_t outer_src;
  ip6_address_t outer_dst;
  u16 outer_sport;
  u16 outer_dport;
  u8 passed_through; /* set when src didn't match src_prefix */
} overlay_encap_trace_t;

/* Bypass node (defined in node.c). Registered as an ip6-unicast feature
   that runs BEFORE ip6-lookup so encap'd packets destined for this VTEP
   are decapsulated before the FIB lookup hands them to the SRv6 localsid
   exclusive DPO. Non-matching traffic is passed through to the next
   feature in the arc unchanged. */
extern vlib_node_registration_t overlay_bypass_node;

#define foreach_overlay_bypass_error                                          \
  _ (DECAPSULATED, "packets decapsulated by bypass")                          \
  _ (BAD_LENGTH, "packet too short for outer+udp+inner ip6")                  \
  _ (NO_TUNNEL, "no tunnel configured for bypass")

typedef enum
{
#define _(sym, str) OVERLAY_BYPASS_ERROR_##sym,
  foreach_overlay_bypass_error
#undef _
    OVERLAY_BYPASS_N_ERROR,
} overlay_bypass_error_t;

typedef struct
{
  ip6_address_t outer_src;
  ip6_address_t outer_dst;
  u16 outer_sport;
  u16 outer_dport;
  u8 decapsulated; /* 0 = passed through to next feature */
} overlay_bypass_trace_t;

#endif /* __included_overlay_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
