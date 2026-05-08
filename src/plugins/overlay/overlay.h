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

/* -------------------------------------------------------------------------
 * Slice C data model
 *
 * The plugin no longer carries an `overlay_tunnel_t` pool. Encap parameters
 * (dst_port, outer_src) live in two places:
 *
 *   - dst_port  → on the per-NIC `overlay_armed_nic_t` record
 *   - outer_src → copied from the inner packet's src per-packet at encap
 *                 time (see `overlay_encap_one` in node.c)
 *
 * Source-prefix matching becomes a separate concept: each NIC owns up to
 * OVERLAY_MAX_MATCHERS_PER_NIC inline matchers. A matcher is a
 * (src_prefix, src_prefix_len) tuple plus the pre-computed mask. Matchers
 * are stored sorted descending by prefix_len so the first hit during the
 * per-packet walk is the longest-prefix match.
 *
 * The hot fields (dst_port_n, n_matchers, matchers0) sit in CL-0 of the
 * armed_nic_t to keep the N=1 encap fast path single-cache-line.
 * matchers12[] and the control-plane fields spill to CL-1.
 * ------------------------------------------------------------------------- */

#define OVERLAY_MAX_MATCHERS_PER_NIC 3

/* Inline matcher: hot fields only. Stored by-value in armed_nic_t.
   Slots [0..n_matchers-1] are valid by construction (compaction on delete
   keeps them dense, sorted desc by prefix_len). */
typedef struct
{
  ip6_address_t src_prefix;	  /* 16B */
  ip6_address_t src_prefix_mask;  /* 16B, pre-computed at add */
  u8 src_prefix_len;		  /*  1B, sort key */
  u8 _pad[7];			  /*  pad to 40B */
} overlay_matcher_t;

STATIC_ASSERT (sizeof (overlay_matcher_t) == 40,
	       "matcher size must be exactly 40B");

/* Per-NIC state. Owns dst_port + cap-3 inline matcher array.
   No outer_src field — outer_src is copied from inner src per-packet.

   Cache layout: CL-0 (64B) holds the N=1 encap hot path
   (dst_port_n + n_matchers + matchers0). matcher_t is 40B so only one fits
   in CL-0 alongside the header — matchers12[] spills to CL-1. The N=1 hot
   path stays single-cache-line; N>=2 touches CL-1.

   Hot-path NIC keying: encap reads sw_if_index[VLIB_TX] (it's an
   ip6-output feature, egress arc); bypass reads VLIB_RX (ip6-unicast
   feature, ingress arc). Same as Slice B. */
typedef struct
{
  /* CL-0: encap N=1 + bypass hot path (64B) */
  u16 dst_port_n;	     /* [0..1]    2B — encap+bypass, net order */
  u8 n_matchers;	     /* [2]       1B — 0..OVERLAY_MAX_MATCHERS_PER_NIC */
  u8 _pad0[21];		     /* [3..23]  21B — align matchers0 to offset 24 */
  overlay_matcher_t matchers0; /* [24..63] 40B — inline first matcher */

  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  /* CL-1: overflow matchers + control plane */
  overlay_matcher_t matchers12[OVERLAY_MAX_MATCHERS_PER_NIC - 1]; /* 80B */
  u32 sw_if_index;	  /*  4B — read at arm only */
  u32 loopback_sw_if;	  /*  4B — for decap attribution */
  u16 dst_port;		  /*  2B — host order, CP/show only */
  u8 enabled;		  /*  1B — CP only */
  u8 _pad1[1];
} overlay_armed_nic_t;

STATIC_ASSERT (offsetof (overlay_armed_nic_t, matchers0) == 24,
	       "matchers0 must be in CL-0 at offset 24");
STATIC_ASSERT (offsetof (overlay_armed_nic_t, cacheline1) == 64,
	       "armed_nic_t hot fields must fit exactly in CL-0");

typedef struct
{
  overlay_armed_nic_t *armed_nics;	/* pool */
  u32 *armed_nic_index_by_sw_if;	/* vec, ~0 if unarmed */

  /* Decap unchanged from Slice B: stateless UDP6 demux on dst_port,
     single global loopback for attribution. ~0 when nothing is armed. */
  u32 decap_overlay_sw_if_index;
  u16 decap_dst_port;	/* dst_port currently registered with udp6, 0 if none */

  vnet_main_t *vnet_main;
  u16 msg_id_base;

  /* Per-NIC TX combined counter, indexed by armed_nic pool index. */
  vlib_combined_counter_main_t nic_counters;
} overlay_main_t;

extern overlay_main_t overlay_main;

/* Result codes. Used by the helpers below and surfaced to API/CLI via
   overlay.c. */
#define OVERLAY_RC_OK		      0
#define OVERLAY_RC_BAD_ARG	     -1
#define OVERLAY_RC_NIC_NOT_ARMED     -3
#define OVERLAY_RC_PORT_CONFLICT     -4
#define OVERLAY_RC_INVALID_INTERFACE -5
#define OVERLAY_RC_TOO_MANY_MATCHERS -6
#define OVERLAY_RC_MATCHER_EXISTS    -7
#define OVERLAY_RC_MATCHER_NOT_FOUND -8
#define OVERLAY_RC_HAS_MATCHERS	     -9

/* Public control-plane helpers. Surfaced via overlay enable/disable and
   overlay matcher add/del CLI commands and the corresponding API RPCs. */
int overlay_enable (u32 sw_if_index, u16 dst_port, int enable_flag, int force);
int overlay_matcher_add (const ip6_address_t *src_prefix, u8 src_prefix_len,
			 const u32 *nic_sw_ifs);
int overlay_matcher_del (const ip6_address_t *src_prefix, u8 src_prefix_len,
			 const u32 *nic_sw_ifs);

format_function_t format_overlay_state;
format_function_t format_overlay_nic;
format_function_t format_overlay_matchers;

/* Decap node (defined in decap.c). Receives IPv6+UDP packets at the
   configured dst_port via the udp6 dispatch table, strips the outer
   headers, and re-injects to ip6-input so the inner SR pipeline runs
   unchanged. */
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

/* Encap node (defined in node.c). Registered as an ip6-output feature on
   each enabled dataplane NIC. For traffic whose inner src matches one of
   the NIC's matchers, prepends an outer IPv6+UDP wrapper (outer src
   copied from inner src; outer dst copied verbatim from inner dst). Other
   traffic on the same NIC is passed through unchanged. */
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
  u32 nic_index;	/* armed_nics pool index, ~0 when no NIC matched */
  ip6_address_t outer_src;
  ip6_address_t outer_dst;
  u16 outer_sport;
  u16 outer_dport;
  u8 passed_through; /* set when src didn't match any matcher */
} overlay_encap_trace_t;

/* Bypass node (defined in node.c). Registered as an ip6-unicast feature
   that runs BEFORE ip6-lookup so encap'd packets destined for this VTEP
   are decapsulated before the FIB lookup hands them to the SRv6 localsid
   exclusive DPO. Non-matching traffic is passed through unchanged. */
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
