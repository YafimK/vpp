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

overlay_main_t overlay_main;

static int
overlay_tunnel_params_match (const overlay_tunnel_t *t,
			     const ip6_address_t *src,
			     const ip6_address_t *src_prefix,
			     u8 src_prefix_len, u16 dst_port)
{
  return (t->dst_port == dst_port &&
	  t->src_prefix_len == src_prefix_len &&
	  ip6_address_is_equal (&t->src_prefix, src_prefix) &&
	  ip6_address_is_equal (&t->src, src));
}

int
overlay_arm (u32 iface_sw_if_index, const ip6_address_t *src,
	     const ip6_address_t *src_prefix, u8 src_prefix_len, u16 dst_port,
	     int enable)
{
  overlay_main_t *om = &overlay_main;
  vnet_main_t *vnm = om->vnet_main;
  overlay_tunnel_t *t = NULL;
  u32 tunnel_index = ~0;

  if (vnet_get_sw_interface_or_null (vnm, iface_sw_if_index) == NULL)
    return OVERLAY_RC_INVALID_INTERFACE;

  if (iface_sw_if_index < vec_len (om->tunnel_index_by_nic))
    tunnel_index = om->tunnel_index_by_nic[iface_sw_if_index];

  if (enable)
    {
      if (src_prefix_len == 0 || src_prefix_len > 128)
	return OVERLAY_RC_BAD_ARG;
      if (dst_port == 0)
	return OVERLAY_RC_BAD_ARG;

      /* Existing tunnel? */
      if (om->active_tunnel_index != ~0)
	{
	  t = pool_elt_at_index (om->tunnels, om->active_tunnel_index);
	  if (!overlay_tunnel_params_match (t, src, src_prefix, src_prefix_len,
					    dst_port))
	    return OVERLAY_RC_TUNNEL_PARAM_MISMATCH;

	  /* Already armed? Idempotent. */
	  if (tunnel_index != ~0)
	    return OVERLAY_RC_OK;
	}
      else
	{
	  /* Create the tunnel + overlay0 loopback interface. */
	  u32 overlay_sw_if_index = ~0;
	  u8 mac[6] = { 0 };
	  int rv =
	    vnet_create_loopback_interface (&overlay_sw_if_index, mac, 0, 0);
	  if (rv != 0)
	    return OVERLAY_RC_BAD_ARG;

	  pool_get_zero (om->tunnels, t);
	  t->src = *src;
	  t->src_prefix = *src_prefix;
	  t->src_prefix_len = src_prefix_len;
	  /* Pre-compute the prefix mask once so the datapath can use the
	     canonical ip6_address_is_equal_masked() helper. */
	  ip6_address_mask_from_width (&t->src_prefix_mask, src_prefix_len);
	  t->dst_port = dst_port;
	  t->sw_if_index = overlay_sw_if_index;
	  t->armed_nic_sw_if_indices = 0;

	  om->active_tunnel_index = t - om->tunnels;

	  vlib_validate_combined_counter (&om->tunnel_counters,
					  t - om->tunnels);
	  vlib_zero_combined_counter (&om->tunnel_counters, t - om->tunnels);

	  /* Register the decap node on the udp6 dispatch table.
	     is_ip4=0 selects the IPv6 table — passing 1 here would silently
	     drop our IPv6+UDP packets. */
	  udp_register_dst_port (vlib_get_main (), dst_port,
				 overlay_decap_node.index, 0 /* is_ip4 */);
	}

      /* Add NIC to armed list and arm the encap feature on it. */
      vec_add1 (t->armed_nic_sw_if_indices, iface_sw_if_index);
      vec_validate_init_empty (om->tunnel_index_by_nic, iface_sw_if_index,
			       ~0);
      om->tunnel_index_by_nic[iface_sw_if_index] = t - om->tunnels;
      vnet_feature_enable_disable ("ip6-output", "overlay-encap",
				   iface_sw_if_index, 1, NULL, 0);
      vnet_feature_enable_disable ("ip6-unicast", "overlay-bypass",
				   iface_sw_if_index, 1, NULL, 0);
      return OVERLAY_RC_OK;
    }
  else
    {
      /* Disarm */
      if (tunnel_index == ~0)
	return OVERLAY_RC_NIC_NOT_ARMED;
      t = pool_elt_at_index (om->tunnels, tunnel_index);

      uword pos = vec_search (t->armed_nic_sw_if_indices, iface_sw_if_index);
      if (pos == ~0)
	return OVERLAY_RC_NIC_NOT_ARMED;
      /* Disarm the feature before clearing the lookup so any in-flight
	 packet still finds its tunnel via tunnel_index_by_nic. */
      vnet_feature_enable_disable ("ip6-output", "overlay-encap",
				   iface_sw_if_index, 0, NULL, 0);
      vnet_feature_enable_disable ("ip6-unicast", "overlay-bypass",
				   iface_sw_if_index, 0, NULL, 0);
      vec_del1 (t->armed_nic_sw_if_indices, pos);
      om->tunnel_index_by_nic[iface_sw_if_index] = ~0;

      if (vec_len (t->armed_nic_sw_if_indices) == 0)
	{
	  /* Last NIC — destroy tunnel. */
	  u32 overlay_sw_if_index = t->sw_if_index;
	  u16 dst_port_to_unregister = t->dst_port;
	  vec_free (t->armed_nic_sw_if_indices);
	  pool_put (om->tunnels, t);
	  om->active_tunnel_index = ~0;
	  vnet_delete_loopback_interface (overlay_sw_if_index);
	  udp_unregister_dst_port (vlib_get_main (), dst_port_to_unregister,
				   0 /* is_ip4 */);
	}
      return OVERLAY_RC_OK;
    }
}

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
    case OVERLAY_RC_TUNNEL_PARAM_MISMATCH:
      return VNET_API_ERROR_INVALID_VALUE;
    case OVERLAY_RC_INVALID_INTERFACE:
      return VNET_API_ERROR_INVALID_SW_IF_INDEX;
    default:
      return VNET_API_ERROR_UNSPECIFIED;
    }
}

static void
vl_api_overlay_arm_v1_t_handler (vl_api_overlay_arm_v1_t *mp)
{
  vl_api_overlay_arm_v1_reply_t *rmp;
  ip46_address_t src46;
  ip6_address_t src6 = { 0 };
  ip6_address_t src_prefix;
  u32 iface_sw_if_index = ntohl (mp->iface_sw_if_index);
  int rv;

  /* src must be IPv6 when arming. On disarm the src is ignored, so skip
     the AF check to allow callers to pass a zero/empty Address. */
  ip46_type_t af = ip_address_decode (&mp->src, &src46);
  if (mp->enable && af != IP46_TYPE_IP6)
    {
      rv = overlay_rc_to_api (OVERLAY_RC_BAD_ARG);
      goto reply;
    }
  src6 = src46.ip6;

  ip6_address_decode (mp->src_prefix, &src_prefix);

  rv = overlay_arm (iface_sw_if_index, &src6, &src_prefix,
		    mp->src_prefix_len, ntohs (mp->dst_port), mp->enable);
  rv = overlay_rc_to_api (rv);

reply:
  REPLY_MACRO (VL_API_OVERLAY_ARM_V1_REPLY);
}

static void
send_overlay_v1_details (vl_api_registration_t *rp, overlay_tunnel_t *t,
			 u32 context)
{
  vl_api_overlay_v1_details_t *rmp;
  u32 n = vec_len (t->armed_nic_sw_if_indices);
  u32 extra = n * sizeof (vl_api_interface_index_t);

  REPLY_MACRO_DETAILS5 (
    VL_API_OVERLAY_V1_DETAILS, extra, rp, context, ({
      ip46_address_t src46 = ip46_address_initializer;
      src46.ip6 = t->src;
      ip_address_encode (&src46, IP46_TYPE_IP6, &rmp->src);
      rmp->dst_port = htons (t->dst_port);
      ip6_address_encode (&t->src_prefix, rmp->src_prefix);
      rmp->src_prefix_len = t->src_prefix_len;
      rmp->overlay_sw_if_index = htonl (t->sw_if_index);
      rmp->n_armed_interfaces = htonl (n);
      for (u32 i = 0; i < n; i++)
	rmp->armed_interfaces[i] = htonl (t->armed_nic_sw_if_indices[i]);
    }));
}

static void
vl_api_overlay_v1_dump_t_handler (vl_api_overlay_v1_dump_t *mp)
{
  overlay_main_t *om = &overlay_main;
  vl_api_registration_t *rp;
  overlay_tunnel_t *t;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0)
    return;

  if (om->active_tunnel_index == ~0)
    return;

  t = pool_elt_at_index (om->tunnels, om->active_tunnel_index);
  send_overlay_v1_details (rp, t, mp->context);
}

#include <overlay/overlay.api.c>

u8 *
format_overlay_state (u8 *s, va_list *args)
{
  overlay_main_t *om = va_arg (*args, overlay_main_t *);
  vnet_main_t *vnm = om->vnet_main;
  overlay_tunnel_t *t;

  if (om->active_tunnel_index == ~0)
    return format (s, "no overlay configured");

  t = pool_elt_at_index (om->tunnels, om->active_tunnel_index);
  s = format (s, "overlay tunnel:\n");
  s = format (s, "  src:              %U\n", format_ip6_address, &t->src);
  s = format (s, "  src-prefix:       %U/%u\n", format_ip6_address,
	      &t->src_prefix, t->src_prefix_len);
  s = format (s, "  dst-port:         %u\n", t->dst_port);
  s = format (s, "  overlay-sw-if:    %U (sw_if_index %u)\n",
	      format_vnet_sw_if_index_name, vnm, t->sw_if_index,
	      t->sw_if_index);
  s = format (s, "  armed NICs (%u):\n",
	      vec_len (t->armed_nic_sw_if_indices));
  u32 *p;
  vec_foreach (p, t->armed_nic_sw_if_indices)
    {
      s = format (s, "    %U (sw_if_index %u)\n",
		  format_vnet_sw_if_index_name, vnm, *p, *p);
    }
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
    case OVERLAY_RC_TUNNEL_PARAM_MISMATCH:
      return "tunnel parameters do not match existing tunnel";
    case OVERLAY_RC_INVALID_INTERFACE:
      return "invalid interface";
    default:
      return "unknown error";
    }
}

static clib_error_t *
overlay_arm_command_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  u32 iface_sw_if_index = ~0;
  ip6_address_t src = { { 0 } };
  ip6_address_t src_prefix = { { 0 } };
  u32 src_prefix_len = 0;
  u32 dst_port = 0;
  int have_src = 0, have_prefix = 0, have_port = 0, have_iface = 0;
  clib_error_t *err = 0;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected command arguments");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_sw_interface, vnm,
		    &iface_sw_if_index))
	have_iface = 1;
      else if (unformat (line_input, "src %U", unformat_ip6_address, &src))
	have_src = 1;
      else if (unformat (line_input, "src-prefix %U/%u", unformat_ip6_address,
			 &src_prefix, &src_prefix_len))
	have_prefix = 1;
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
  if (!have_src || !have_prefix || !have_port)
    {
      err = clib_error_return (
	0, "src, src-prefix <prefix>/<len>, and dst-port required");
      goto done;
    }
  if (src_prefix_len == 0 || src_prefix_len > 128)
    {
      err = clib_error_return (0, "src-prefix length must be 1..128");
      goto done;
    }

  rv = overlay_arm (iface_sw_if_index, &src, &src_prefix,
		    (u8) src_prefix_len, (u16) dst_port, 1);
  if (rv != OVERLAY_RC_OK)
    err = clib_error_return (0, "overlay arm failed: %s", overlay_rc_str (rv));

done:
  unformat_free (line_input);
  return err;
}

static clib_error_t *
overlay_disarm_command_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  u32 iface_sw_if_index = ~0;
  ip6_address_t zero = { { 0 } };
  clib_error_t *err = 0;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected interface argument");

  if (!unformat (line_input, "%U", unformat_vnet_sw_interface, vnm,
		 &iface_sw_if_index))
    {
      err = clib_error_return (0, "interface required");
      goto done;
    }

  rv = overlay_arm (iface_sw_if_index, &zero, &zero, 0, 0, 0);
  if (rv != OVERLAY_RC_OK)
    err =
      clib_error_return (0, "overlay disarm failed: %s", overlay_rc_str (rv));

done:
  unformat_free (line_input);
  return err;
}

static clib_error_t *
show_overlay_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  vlib_cli_output (vm, "%U", format_overlay_state, &overlay_main);
  return 0;
}

VLIB_CLI_COMMAND (overlay_arm_command, static) = {
  .path = "overlay arm",
  .short_help = "overlay arm <iface> src <local-ipv6> "
		"src-prefix <prefix>/<len> dst-port <port>",
  .function = overlay_arm_command_fn,
};

VLIB_CLI_COMMAND (overlay_disarm_command, static) = {
  .path = "overlay disarm",
  .short_help = "overlay disarm <iface>",
  .function = overlay_disarm_command_fn,
};

VLIB_CLI_COMMAND (show_overlay_command, static) = {
  .path = "show overlay",
  .short_help = "show overlay",
  .function = show_overlay_command_fn,
};

static clib_error_t *
overlay_init (vlib_main_t *vm)
{
  overlay_main_t *om = &overlay_main;

  om->vnet_main = vnet_get_main ();
  om->tunnels = 0;
  om->tunnel_index_by_nic = 0;
  om->active_tunnel_index = ~0;
  om->msg_id_base = setup_message_id_table ();

  om->tunnel_counters.name = "overlay-tunnel";
  om->tunnel_counters.stat_segment_name = "/net/overlay-tunnel";

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
