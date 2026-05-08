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
#include <vlib/unix/unix.h>
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/feature/feature.h>
#include <vnet/format_fns.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/udp/udp_local.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>

#include <overlay/overlay.h>
#include <overlay/overlay.api_enum.h>
#include <overlay/overlay.api_types.h>

#define REPLY_MSG_ID_BASE overlay_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

#ifndef OVERLAY_BUILD_SHA
#define OVERLAY_BUILD_SHA "unknown"
#endif
#ifndef OVERLAY_BUILD_DATE
#define OVERLAY_BUILD_DATE "unknown"
#endif
#ifndef OVERLAY_BUILD_BRANCH
#define OVERLAY_BUILD_BRANCH "unknown"
#endif

overlay_main_t overlay_main;

/* ---------------------------------------------------------------------------
 * Internal helpers
 * --------------------------------------------------------------------------- */

static overlay_armed_nic_t *
overlay_anic_by_sw_if (overlay_main_t *om, u32 sw_if_index)
{
  if (sw_if_index >= vec_len (om->armed_nic_index_by_sw_if))
    return NULL;
  u32 idx = om->armed_nic_index_by_sw_if[sw_if_index];
  if (idx == ~0u)
    return NULL;
  return pool_elt_at_index (om->armed_nics, idx);
}

static overlay_matcher_t *
overlay_anic_matcher (overlay_armed_nic_t *anic, u8 i)
{
  return (i == 0) ? &anic->matchers0 : &anic->matchers12[i - 1];
}

static int
overlay_matcher_find_slot (overlay_armed_nic_t *anic,
			   const ip6_address_t *p, u8 plen)
{
  for (u8 i = 0; i < anic->n_matchers; i++)
    {
      overlay_matcher_t *m = overlay_anic_matcher (anic, i);
      if (m->src_prefix_len == plen && ip6_address_is_equal (&m->src_prefix, p))
	return (int) i;
    }
  return -1;
}

/* Insert m into anic's matcher slots, sorted desc by prefix_len. */
static void
overlay_matcher_insert_sorted (overlay_armed_nic_t *anic,
			       const overlay_matcher_t *m)
{
  u8 n = anic->n_matchers;
  /* Find insert position (first slot whose prefix_len < m->prefix_len). */
  u8 pos = n;
  for (u8 i = 0; i < n; i++)
    {
      overlay_matcher_t *cur = overlay_anic_matcher (anic, i);
      if (cur->src_prefix_len < m->src_prefix_len)
	{
	  pos = i;
	  break;
	}
    }
  /* Shift [pos..n-1] one slot to the right. Walk from the end. */
  for (int i = (int) n - 1; i >= (int) pos; i--)
    {
      overlay_matcher_t *dst = overlay_anic_matcher (anic, (u8) (i + 1));
      overlay_matcher_t *src = overlay_anic_matcher (anic, (u8) i);
      *dst = *src;
    }
  *overlay_anic_matcher (anic, pos) = *m;
  anic->n_matchers = n + 1;
}

static void
overlay_matcher_remove_at (overlay_armed_nic_t *anic, u8 idx)
{
  u8 n = anic->n_matchers;
  for (u8 i = idx; i + 1 < n; i++)
    {
      overlay_matcher_t *dst = overlay_anic_matcher (anic, i);
      overlay_matcher_t *src = overlay_anic_matcher (anic, (u8) (i + 1));
      *dst = *src;
    }
  anic->n_matchers = n - 1;
  /* Zero the now-unused tail slot for cleanliness (and so the hot path
     never accidentally compares against stale bytes). */
  overlay_matcher_t *last = overlay_anic_matcher (anic, anic->n_matchers);
  clib_memset (last, 0, sizeof (*last));
}

/* ---------------------------------------------------------------------------
 * Public C-1 helpers
 * --------------------------------------------------------------------------- */

int
overlay_enable (u32 sw_if_index, u16 dst_port, int enable_flag, int force)
{
  overlay_main_t *om = &overlay_main;
  vnet_main_t *vnm = om->vnet_main;
  overlay_armed_nic_t *anic;

  if (vnet_get_sw_interface_or_null (vnm, sw_if_index) == NULL)
    return OVERLAY_RC_INVALID_INTERFACE;

  anic = overlay_anic_by_sw_if (om, sw_if_index);

  if (enable_flag)
    {
      if (dst_port == 0)
	return OVERLAY_RC_BAD_ARG;

      if (anic != NULL)
	{
	  /* Idempotent on identical params; reject re-enable with a different
	     dst_port — caller must disable first. */
	  if (anic->dst_port == dst_port)
	    return OVERLAY_RC_OK;
	  return OVERLAY_RC_BAD_ARG;
	}

      /* Single VPP instance → single UDP dst_port for decap. Reject if
	 some other NIC is already enabled on a different port. */
      if (om->decap_dst_port != 0 && om->decap_dst_port != dst_port)
	return OVERLAY_RC_PORT_CONFLICT;

      /* Allocate the loopback for decap attribution on the first enable. */
      u32 loopback_sw_if = om->decap_overlay_sw_if_index;
      if (loopback_sw_if == ~0u)
	{
	  u8 mac[6] = { 0 };
	  int rv =
	    vnet_create_loopback_interface (&loopback_sw_if, mac, 0, 0);
	  if (rv != 0)
	    return OVERLAY_RC_BAD_ARG;
	}

      /* Allocate the armed_nic. pool_get_aligned_zero gives us a
	 cache-line-aligned, zeroed entry — important for layout asserts. */
      pool_get_aligned_zero (om->armed_nics, anic, CLIB_CACHE_LINE_BYTES);
      anic->dst_port = dst_port;
      anic->dst_port_n = clib_host_to_net_u16 (dst_port);
      anic->n_matchers = 0;
      anic->sw_if_index = sw_if_index;
      anic->loopback_sw_if = loopback_sw_if;
      anic->enabled = 1;

      vec_validate_init_empty (om->armed_nic_index_by_sw_if, sw_if_index, ~0);
      om->armed_nic_index_by_sw_if[sw_if_index] = anic - om->armed_nics;

      vlib_validate_combined_counter (&om->nic_counters, anic - om->armed_nics);
      vlib_zero_combined_counter (&om->nic_counters, anic - om->armed_nics);

      /* Register the udp6 dst port + plugin-wide loopback on first enable. */
      if (om->decap_dst_port == 0)
	{
	  udp_register_dst_port (vlib_get_main (), dst_port,
				 overlay_decap_node.index, 0 /* is_ip4 */);
	  om->decap_dst_port = dst_port;
	  om->decap_overlay_sw_if_index = loopback_sw_if;
	}

      vnet_feature_enable_disable ("ip6-output", "overlay-encap", sw_if_index,
				   1, NULL, 0);
      vnet_feature_enable_disable ("ip6-unicast", "overlay-bypass",
				   sw_if_index, 1, NULL, 0);
      return OVERLAY_RC_OK;
    }

  /* Disable */
  if (anic == NULL)
    return OVERLAY_RC_NIC_NOT_ARMED;

  if (anic->n_matchers > 0 && !force)
    return OVERLAY_RC_HAS_MATCHERS;

  /* Detach feature arcs first; clearing the pool index after means any
     in-flight packet still finds its NIC via armed_nic_index_by_sw_if. */
  vnet_feature_enable_disable ("ip6-output", "overlay-encap", sw_if_index, 0,
			       NULL, 0);
  vnet_feature_enable_disable ("ip6-unicast", "overlay-bypass", sw_if_index,
			       0, NULL, 0);

  om->armed_nic_index_by_sw_if[sw_if_index] = ~0u;
  pool_put (om->armed_nics, anic);

  if (pool_elts (om->armed_nics) == 0)
    {
      /* Last NIC gone — tear down the udp port + global loopback. */
      if (om->decap_dst_port != 0)
	{
	  udp_unregister_dst_port (vlib_get_main (), om->decap_dst_port,
				   0 /* is_ip4 */);
	  om->decap_dst_port = 0;
	}
      if (om->decap_overlay_sw_if_index != ~0u)
	{
	  vnet_delete_loopback_interface (om->decap_overlay_sw_if_index);
	  om->decap_overlay_sw_if_index = ~0u;
	}
    }

  return OVERLAY_RC_OK;
}

int
overlay_matcher_add (const ip6_address_t *src_prefix, u8 src_prefix_len,
		     const u32 *nic_sw_ifs)
{
  overlay_main_t *om = &overlay_main;

  if (src_prefix_len == 0 || src_prefix_len > 128)
    return OVERLAY_RC_BAD_ARG;
  if (vec_len (nic_sw_ifs) == 0)
    return OVERLAY_RC_BAD_ARG;

  /* First pass: validate every NIC. Nothing is mutated until all checks
     pass — keeps the operation atomic from the caller's viewpoint. */
  for (u32 i = 0; i < vec_len (nic_sw_ifs); i++)
    {
      overlay_armed_nic_t *anic =
	overlay_anic_by_sw_if (om, nic_sw_ifs[i]);
      if (anic == NULL)
	return OVERLAY_RC_NIC_NOT_ARMED;
      if (overlay_matcher_find_slot (anic, src_prefix, src_prefix_len) >= 0)
	return OVERLAY_RC_MATCHER_EXISTS;
      if (anic->n_matchers >= OVERLAY_MAX_MATCHERS_PER_NIC)
	return OVERLAY_RC_TOO_MANY_MATCHERS;
    }

  /* Second pass: insert. */
  overlay_matcher_t m;
  clib_memset (&m, 0, sizeof (m));
  m.src_prefix = *src_prefix;
  m.src_prefix_len = src_prefix_len;
  ip6_address_mask_from_width (&m.src_prefix_mask, src_prefix_len);
  /* The prefix itself may have stray bits set below the mask in callers'
     input. Canonicalise by masking, so equality compares are stable. */
  m.src_prefix.as_u64[0] &= m.src_prefix_mask.as_u64[0];
  m.src_prefix.as_u64[1] &= m.src_prefix_mask.as_u64[1];

  for (u32 i = 0; i < vec_len (nic_sw_ifs); i++)
    {
      overlay_armed_nic_t *anic =
	overlay_anic_by_sw_if (om, nic_sw_ifs[i]);
      overlay_matcher_insert_sorted (anic, &m);
    }
  return OVERLAY_RC_OK;
}

int
overlay_matcher_del (const ip6_address_t *src_prefix, u8 src_prefix_len,
		     const u32 *nic_sw_ifs)
{
  overlay_main_t *om = &overlay_main;

  if (src_prefix_len == 0 || src_prefix_len > 128)
    return OVERLAY_RC_BAD_ARG;
  if (vec_len (nic_sw_ifs) == 0)
    return OVERLAY_RC_BAD_ARG;

  /* Canonicalise the prefix the same way matcher_add does. */
  ip6_address_t mask, p = *src_prefix;
  ip6_address_mask_from_width (&mask, src_prefix_len);
  p.as_u64[0] &= mask.as_u64[0];
  p.as_u64[1] &= mask.as_u64[1];

  /* Validate first. */
  for (u32 i = 0; i < vec_len (nic_sw_ifs); i++)
    {
      overlay_armed_nic_t *anic =
	overlay_anic_by_sw_if (om, nic_sw_ifs[i]);
      if (anic == NULL)
	return OVERLAY_RC_NIC_NOT_ARMED;
      if (overlay_matcher_find_slot (anic, &p, src_prefix_len) < 0)
	return OVERLAY_RC_MATCHER_NOT_FOUND;
    }

  /* Apply. */
  for (u32 i = 0; i < vec_len (nic_sw_ifs); i++)
    {
      overlay_armed_nic_t *anic =
	overlay_anic_by_sw_if (om, nic_sw_ifs[i]);
      int slot = overlay_matcher_find_slot (anic, &p, src_prefix_len);
      ASSERT (slot >= 0);
      overlay_matcher_remove_at (anic, (u8) slot);
    }
  return OVERLAY_RC_OK;
}

/* ---------------------------------------------------------------------------
 * API <-> internal result code translation.
 * --------------------------------------------------------------------------- */

static int
overlay_rc_to_api (int rc)
{
  switch (rc)
    {
    case OVERLAY_RC_OK:
      return 0;
    case OVERLAY_RC_BAD_ARG:
      return VNET_API_ERROR_INVALID_ARGUMENT;
    case OVERLAY_RC_NIC_NOT_ARMED:
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    case OVERLAY_RC_PORT_CONFLICT:
      return VNET_API_ERROR_INVALID_VALUE;
    case OVERLAY_RC_INVALID_INTERFACE:
      return VNET_API_ERROR_INVALID_SW_IF_INDEX;
    case OVERLAY_RC_TOO_MANY_MATCHERS:
    case OVERLAY_RC_MATCHER_EXISTS:
    case OVERLAY_RC_MATCHER_NOT_FOUND:
    case OVERLAY_RC_HAS_MATCHERS:
      return VNET_API_ERROR_INVALID_ARGUMENT;
    default:
      return VNET_API_ERROR_UNSPECIFIED;
    }
}

/* ---------------------------------------------------------------------------
 * API handlers: overlay_enable, overlay_matcher_add, overlay_matcher_del,
 * overlay_dump.
 * --------------------------------------------------------------------------- */

static void
vl_api_overlay_enable_t_handler (vl_api_overlay_enable_t *mp)
{
  vl_api_overlay_enable_reply_t *rmp;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  u16 dst_port = ntohs (mp->dst_port);
  int rv = overlay_enable (sw_if_index, dst_port, mp->enable ? 1 : 0,
			   mp->force ? 1 : 0);
  rv = overlay_rc_to_api (rv);
  REPLY_MACRO (VL_API_OVERLAY_ENABLE_REPLY);
}

static void
vl_api_overlay_matcher_add_t_handler (vl_api_overlay_matcher_add_t *mp)
{
  vl_api_overlay_matcher_add_reply_t *rmp;
  ip6_address_t prefix;
  ip6_address_decode (mp->src_prefix.address, &prefix);
  u8 prefix_len = mp->src_prefix.len;

  u32 n = ntohl (mp->n_nic_sw_ifs);
  u32 *nics = NULL;
  vec_validate (nics, (n == 0) ? 0 : n - 1);
  if (n == 0)
    vec_set_len (nics, 0);
  for (u32 i = 0; i < n; i++)
    nics[i] = ntohl (mp->nic_sw_ifs[i]);

  int rv = overlay_matcher_add (&prefix, prefix_len, nics);
  vec_free (nics);
  rv = overlay_rc_to_api (rv);
  REPLY_MACRO (VL_API_OVERLAY_MATCHER_ADD_REPLY);
}

static void
vl_api_overlay_matcher_del_t_handler (vl_api_overlay_matcher_del_t *mp)
{
  vl_api_overlay_matcher_del_reply_t *rmp;
  ip6_address_t prefix;
  ip6_address_decode (mp->src_prefix.address, &prefix);
  u8 prefix_len = mp->src_prefix.len;

  u32 n = ntohl (mp->n_nic_sw_ifs);
  u32 *nics = NULL;
  vec_validate (nics, (n == 0) ? 0 : n - 1);
  if (n == 0)
    vec_set_len (nics, 0);
  for (u32 i = 0; i < n; i++)
    nics[i] = ntohl (mp->nic_sw_ifs[i]);

  int rv = overlay_matcher_del (&prefix, prefix_len, nics);
  vec_free (nics);
  rv = overlay_rc_to_api (rv);
  REPLY_MACRO (VL_API_OVERLAY_MATCHER_DEL_REPLY);
}

/* Group matchers by (prefix, len) across NICs for the matcher_details
   stream — same shape as the textual "matcher" view. */
typedef struct
{
  ip6_address_t prefix;
  u8 prefix_len;
  u32 *nic_sw_ifs; /* vec */
} overlay_matcher_group_t;

static overlay_matcher_group_t *
overlay_collect_matcher_groups (overlay_main_t *om)
{
  overlay_matcher_group_t *groups = NULL;
  overlay_armed_nic_t *anic;
  pool_foreach (anic, om->armed_nics)
    {
      for (u8 i = 0; i < anic->n_matchers; i++)
	{
	  overlay_matcher_t *m = overlay_anic_matcher (anic, i);
	  overlay_matcher_group_t *g = NULL;
	  vec_foreach (g, groups)
	    {
	      if (g->prefix_len == m->src_prefix_len
		  && ip6_address_is_equal (&g->prefix, &m->src_prefix))
		break;
	    }
	  if (g >= vec_end (groups))
	    {
	      overlay_matcher_group_t ng = {
		.prefix = m->src_prefix,
		.prefix_len = m->src_prefix_len,
		.nic_sw_ifs = NULL,
	      };
	      vec_add1 (groups, ng);
	      g = vec_elt_at_index (groups, vec_len (groups) - 1);
	    }
	  vec_add1 (g->nic_sw_ifs, anic->sw_if_index);
	}
    }
  return groups;
}

static void
send_overlay_details (vl_api_registration_t *rp, overlay_armed_nic_t *anic,
		      u32 context)
{
  vl_api_overlay_details_t *rmp;
  REPLY_MACRO_DETAILS4 (VL_API_OVERLAY_DETAILS, rp, context, ({
			  rmp->sw_if_index = htonl (anic->sw_if_index);
			  rmp->dst_port = htons (anic->dst_port);
			  rmp->n_matchers = anic->n_matchers;
			}));
}

static void
send_overlay_matcher_details (vl_api_registration_t *rp,
			      overlay_matcher_group_t *g, u32 context)
{
  vl_api_overlay_matcher_details_t *rmp;
  u32 n = vec_len (g->nic_sw_ifs);
  u32 extra = n * sizeof (vl_api_interface_index_t);

  REPLY_MACRO_DETAILS5 (
    VL_API_OVERLAY_MATCHER_DETAILS, extra, rp, context, ({
      ip6_address_encode (&g->prefix, rmp->src_prefix.address);
      rmp->src_prefix.len = g->prefix_len;
      rmp->n_nic_sw_ifs = htonl (n);
      for (u32 i = 0; i < n; i++)
	rmp->nic_sw_ifs[i] = htonl (g->nic_sw_ifs[i]);
    }));
}

static void
vl_api_overlay_dump_t_handler (vl_api_overlay_dump_t *mp)
{
  overlay_main_t *om = &overlay_main;
  vl_api_registration_t *rp;
  overlay_armed_nic_t *anic;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0)
    return;

  pool_foreach (anic, om->armed_nics)
    {
      send_overlay_details (rp, anic, mp->context);
    }
}

static void
vl_api_overlay_matcher_dump_t_handler (vl_api_overlay_matcher_dump_t *mp)
{
  overlay_main_t *om = &overlay_main;
  vl_api_registration_t *rp;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0)
    return;

  overlay_matcher_group_t *groups = overlay_collect_matcher_groups (om);
  overlay_matcher_group_t *g;
  vec_foreach (g, groups)
    {
      send_overlay_matcher_details (rp, g, mp->context);
      vec_free (g->nic_sw_ifs);
    }
  vec_free (groups);
}

#include <overlay/overlay.api.c>

/* ---------------------------------------------------------------------------
 * `show overlay` formatters.
 *
 * Layout (designed to be parseable by dev/tests/conftest.py
 * reset_overlay_state):
 *
 *   overlay (N enabled NICs):
 *     enabled NIC: <iface-name> sw_if_index <X> dst-port <P> n_matchers <M>
 *       matcher: <prefix>/<len>           (one line per matcher, sorted
 *                                          desc by prefix_len — already
 *                                          stored that way)
 *
 * The header line "enabled NIC: <name> ..." is the anchor parsed by
 * reset_overlay_state(): it splits on whitespace, takes the token after
 * "enabled NIC:", and disables that NIC.
 * --------------------------------------------------------------------------- */

static u8 *
format_overlay_one_nic (u8 *s, vnet_main_t *vnm, overlay_armed_nic_t *anic,
			u32 indent)
{
  s = format (
    s, "%Uenabled NIC: %U sw_if_index %u dst-port %u n_matchers: %u\n",
    format_white_space, indent, format_vnet_sw_if_index_name, vnm,
    anic->sw_if_index, anic->sw_if_index, anic->dst_port, anic->n_matchers);
  for (u8 i = 0; i < anic->n_matchers; i++)
    {
      overlay_matcher_t *m = overlay_anic_matcher (anic, i);
      s = format (s, "%Umatcher: %U/%u\n", format_white_space, indent + 2,
		  format_ip6_address, &m->src_prefix, m->src_prefix_len);
    }
  return s;
}

u8 *
format_overlay_state (u8 *s, va_list *args)
{
  overlay_main_t *om = va_arg (*args, overlay_main_t *);
  vnet_main_t *vnm = om->vnet_main;
  overlay_armed_nic_t *anic;

  if (pool_elts (om->armed_nics) == 0)
    return format (s, "no overlay configured");

  s = format (s, "overlay (%u enabled NICs):\n", pool_elts (om->armed_nics));
  pool_foreach (anic, om->armed_nics)
    {
      s = format_overlay_one_nic (s, vnm, anic, 2);
    }
  return s;
}

u8 *
format_overlay_nic (u8 *s, va_list *args)
{
  overlay_main_t *om = va_arg (*args, overlay_main_t *);
  u32 sw_if_index = va_arg (*args, u32);
  overlay_armed_nic_t *anic = overlay_anic_by_sw_if (om, sw_if_index);
  if (anic == NULL)
    return format (s, "NIC not enabled (sw_if_index %u)", sw_if_index);
  return format_overlay_one_nic (s, om->vnet_main, anic, 0);
}

u8 *
format_overlay_matchers (u8 *s, va_list *args)
{
  overlay_main_t *om = va_arg (*args, overlay_main_t *);
  vnet_main_t *vnm = om->vnet_main;

  overlay_matcher_group_t *groups = overlay_collect_matcher_groups (om);
  if (vec_len (groups) == 0)
    {
      vec_free (groups);
      return format (s, "no matchers configured");
    }
  overlay_matcher_group_t *g;
  vec_foreach (g, groups)
    {
      s = format (s, "matcher: %U/%u  nics(%u):", format_ip6_address,
		  &g->prefix, g->prefix_len, vec_len (g->nic_sw_ifs));
      u32 *p;
      vec_foreach (p, g->nic_sw_ifs)
	s = format (s, " %U", format_vnet_sw_if_index_name, vnm, *p);
      s = format (s, "\n");
      vec_free (g->nic_sw_ifs);
    }
  vec_free (groups);
  return s;
}

static const char *
overlay_rc_str (int rc)
{
  switch (rc)
    {
    case OVERLAY_RC_OK:
      return "ok";
    case OVERLAY_RC_BAD_ARG:
      return "invalid argument";
    case OVERLAY_RC_NIC_NOT_ARMED:
      return "NIC not armed";
    case OVERLAY_RC_PORT_CONFLICT:
      return "dst-port conflicts with an existing overlay tunnel";
    case OVERLAY_RC_INVALID_INTERFACE:
      return "invalid interface";
    case OVERLAY_RC_TOO_MANY_MATCHERS:
      return "too many matchers on NIC (max 3)";
    case OVERLAY_RC_MATCHER_EXISTS:
      return "matcher already exists on NIC";
    case OVERLAY_RC_MATCHER_NOT_FOUND:
      return "matcher not found on NIC";
    case OVERLAY_RC_HAS_MATCHERS:
      return "NIC still has matchers; disarm with force";
    default:
      return "unknown error";
    }
}

/* ---------------------------------------------------------------------------
 * CLI: overlay enable / disable / matcher add / matcher del
 *      show overlay [nic <iface> | matcher | version]
 * --------------------------------------------------------------------------- */

static clib_error_t *
overlay_enable_command_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  u32 dst_port = 0;
  int have_iface = 0, have_port = 0;
  clib_error_t *err = 0;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected command arguments");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_sw_interface, vnm,
		    &sw_if_index))
	have_iface = 1;
      else if (unformat (line_input, "dst-port %u", &dst_port))
	have_port = 1;
      else
	{
	  err = clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!have_iface)
    {
      err = clib_error_return (0, "interface required");
      goto done;
    }
  if (!have_port || dst_port == 0 || dst_port > 0xffff)
    {
      err = clib_error_return (0, "dst-port required (1..65535)");
      goto done;
    }

  rv = overlay_enable (sw_if_index, (u16) dst_port, 1, 0);
  if (rv != OVERLAY_RC_OK)
    err = clib_error_return (0, "overlay enable failed: %s",
			     overlay_rc_str (rv));

done:
  unformat_free (line_input);
  return err;
}

static clib_error_t *
overlay_disable_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  int force = 0;
  int have_iface = 0;
  clib_error_t *err = 0;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "interface required");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (!have_iface
	  && unformat (line_input, "%U", unformat_vnet_sw_interface, vnm,
		       &sw_if_index))
	have_iface = 1;
      else if (unformat (line_input, "force"))
	force = 1;
      else
	{
	  err = clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!have_iface)
    {
      err = clib_error_return (0, "interface required");
      goto done;
    }

  rv = overlay_enable (sw_if_index, 0, 0, force);
  if (rv != OVERLAY_RC_OK)
    err = clib_error_return (0, "overlay disable failed: %s",
			     overlay_rc_str (rv));

done:
  unformat_free (line_input);
  return err;
}

static clib_error_t *
overlay_matcher_parse_and_apply (unformat_input_t *input, int is_add)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  ip6_address_t src_prefix = { { 0 } };
  u32 src_prefix_len = 0;
  int have_prefix = 0;
  u32 *nics = NULL;
  clib_error_t *err = 0;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected command arguments");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      u32 nic_sw_if = ~0;
      if (unformat (line_input, "src-prefix %U/%u", unformat_ip6_address,
		    &src_prefix, &src_prefix_len))
	have_prefix = 1;
      else if (unformat (line_input, "nic %U", unformat_vnet_sw_interface, vnm,
			 &nic_sw_if))
	{
	  vec_add1 (nics, nic_sw_if);
	}
      else
	{
	  err = clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!have_prefix)
    {
      err = clib_error_return (0, "src-prefix <prefix>/<len> required");
      goto done;
    }
  if (src_prefix_len == 0 || src_prefix_len > 128)
    {
      err =
	clib_error_return (0, "invalid src-prefix length: must be 1..128");
      goto done;
    }
  if (vec_len (nics) == 0)
    {
      err = clib_error_return (0, "at least one 'nic <iface>' required");
      goto done;
    }

  rv = is_add ? overlay_matcher_add (&src_prefix, (u8) src_prefix_len, nics)
	      : overlay_matcher_del (&src_prefix, (u8) src_prefix_len, nics);
  if (rv != OVERLAY_RC_OK)
    err = clib_error_return (0, "overlay matcher %s failed: %s",
			     is_add ? "add" : "del", overlay_rc_str (rv));

done:
  vec_free (nics);
  unformat_free (line_input);
  return err;
}

static clib_error_t *
overlay_matcher_add_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  return overlay_matcher_parse_and_apply (input, 1);
}

static clib_error_t *
overlay_matcher_del_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  return overlay_matcher_parse_and_apply (input, 0);
}

static clib_error_t *
show_overlay_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *err = 0;

  /* No args → top-level overlay state. */
  if (input == NULL || !unformat_user (input, unformat_line_input, line_input))
    {
      vlib_cli_output (vm, "%U", format_overlay_state, &overlay_main);
      return 0;
    }

  if (unformat_check_input (line_input) == UNFORMAT_END_OF_INPUT)
    {
      vlib_cli_output (vm, "%U", format_overlay_state, &overlay_main);
      goto done;
    }

  u32 sw_if_index = ~0;
  if (unformat (line_input, "nic %U", unformat_vnet_sw_interface, vnm,
		&sw_if_index))
    {
      vlib_cli_output (vm, "%U", format_overlay_nic, &overlay_main,
		       sw_if_index);
    }
  else if (unformat (line_input, "matcher"))
    {
      vlib_cli_output (vm, "%U", format_overlay_matchers, &overlay_main);
    }
  else if (unformat (line_input, "version"))
    {
      vlib_cli_output (vm,
		       "overlay plugin version:\n"
		       "  build sha:    %s\n"
		       "  build date:   %s\n"
		       "  branch:       %s",
		       OVERLAY_BUILD_SHA, OVERLAY_BUILD_DATE,
		       OVERLAY_BUILD_BRANCH);
    }
  else
    {
      err = clib_error_return (0, "unknown input '%U'", format_unformat_error,
			       line_input);
    }

done:
  unformat_free (line_input);
  return err;
}

VLIB_CLI_COMMAND (overlay_enable_command, static) = {
  .path = "overlay enable",
  .short_help = "overlay enable <iface> dst-port <port>",
  .function = overlay_enable_command_fn,
};

VLIB_CLI_COMMAND (overlay_disable_command, static) = {
  .path = "overlay disable",
  .short_help = "overlay disable <iface> [force]",
  .function = overlay_disable_command_fn,
};

VLIB_CLI_COMMAND (overlay_matcher_add_command, static) = {
  .path = "overlay matcher add",
  .short_help = "overlay matcher add src-prefix <p>/<l> "
		"nic <iface> [nic <iface>]...",
  .function = overlay_matcher_add_command_fn,
};

VLIB_CLI_COMMAND (overlay_matcher_del_command, static) = {
  .path = "overlay matcher del",
  .short_help = "overlay matcher del src-prefix <p>/<l> "
		"nic <iface> [nic <iface>]...",
  .function = overlay_matcher_del_command_fn,
};

VLIB_CLI_COMMAND (show_overlay_command, static) = {
  .path = "show overlay",
  .short_help = "show overlay [nic <iface> | matcher | version]",
  .function = show_overlay_command_fn,
};

static clib_error_t *
overlay_init (vlib_main_t *vm)
{
  overlay_main_t *om = &overlay_main;

  om->vnet_main = vnet_get_main ();
  om->armed_nics = 0;
  om->armed_nic_index_by_sw_if = 0;
  om->decap_overlay_sw_if_index = ~0;
  om->decap_dst_port = 0;
  om->msg_id_base = setup_message_id_table ();

  om->nic_counters.name = "overlay-nic";
  om->nic_counters.stat_segment_name = "/net/overlay-nic";

  return 0;
}

VLIB_INIT_FUNCTION (overlay_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "SRv6-over-UDP overlay tunnel",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
