/* packet-xip.c
 * Routines for XIP dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/xia.h>

/* Next dissector handles. */
static dissector_handle_t data_handle;

#define XIPH_MIN_LEN		36
#define NODE_SIZE		28
#define ETHERTYPE_XIP		0xC0DE
#define XID_LEN			20
#define XIA_NEXT_HEADER_DATA	0

#define XIPH_VERS		0
#define XIPH_NXTH		1
#define XIPH_PLEN		2
#define XIPH_HOPL		4
#define XIPH_NDST		5
#define XIPH_NSRC		6
#define XIPH_LSTN		7
#define XIPH_DSTD		8

static int proto_xip			= -1;

static dissector_table_t xip_dissector_table;

static gint hf_xip_version		= -1;
static gint hf_xip_next_hdr		= -1;
static gint hf_xip_payload_len		= -1;
static gint hf_xip_hop_limit		= -1;
static gint hf_xip_num_dst		= -1;
static gint hf_xip_num_src		= -1;
static gint hf_xip_last_node		= -1;
static gint hf_xip_dst_dag		= -1;
static gint hf_xip_dst_dag_entry	= -1;
static gint hf_xip_src_dag		= -1;
static gint hf_xip_src_dag_entry	= -1;

static gint ett_xip_tree		= -1;
static gint ett_xip_ddag		= -1;
static gint ett_xip_sdag		= -1;

static expert_field ei_xip_invalid_len = EI_INIT;
static expert_field ei_xip_next_header = EI_INIT;
static expert_field ei_xip_invalid_dag = EI_INIT;
static expert_field ei_xip_bad_num_dst = EI_INIT;
static expert_field ei_xip_bad_num_src = EI_INIT;

static void
display_dag(tvbuff_t *tvb, proto_tree *dag_tree, gint hf, gchar *buf,
	guint8 num_nodes, guint8 offset)
{
	gchar *strxid, *p;
	guint8 i;

	strxid = (gchar *)wmem_alloc(wmem_packet_scope(), XIA_MAX_STRXID_SIZE);
	p =  strtok(buf, "\n");

	for (i = 0; i < num_nodes; i++) {
		memset(strxid, 0, XIA_MAX_STRXID_SIZE);
		g_snprintf(strxid, strlen(p) + 1, "%s", p);
		proto_tree_add_string_format(dag_tree, hf, tvb,
			offset + (i * NODE_SIZE), NODE_SIZE, strxid,
			"%s", strxid);
		p = strtok(NULL, "\n");
	}
}

static void
construct_dag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *xip_tree,
	const gint ett, const gint hf, const gint hf_entry,
	const guint8 num_nodes, const guint8 offset)
{
	proto_item *ti = NULL;
	proto_tree *dag_tree = NULL;

	struct xia_addr dag;
	gchar *buf;

	memset(&dag, 0, sizeof(dag));
	ti = proto_tree_add_item(xip_tree, hf, tvb, offset,
		num_nodes * NODE_SIZE, ENC_BIG_ENDIAN);
	dag_tree = proto_item_add_subtree(ti, ett);
	tvb_memcpy(tvb, (guint8 *)(&dag), offset, NODE_SIZE * num_nodes);
	if (xia_ntop(&dag, &buf, 1) < 0)
		expert_add_info_format(pinfo, ti, &ei_xip_invalid_dag,
			"Truncated DAG");
	display_dag(tvb, dag_tree, hf_entry, buf, num_nodes, offset);
}

static void
display_xip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	guint16 xiph_len, gint8 num_dst_nodes, gint8 num_src_nodes)
{
	proto_tree *xip_tree = NULL;

	proto_item *ti = NULL;
	proto_item *payload_ti = NULL;
	proto_item *next_ti = NULL;
	proto_item *num_ti = NULL;

	tvbuff_t *next_tvb;

	guint16 payload_len;
	guint8 last_node, next_header, next_header_offset;

	/* Construct protocol tree. */
	ti = proto_tree_add_item(tree, proto_xip, tvb, 0, xiph_len, ENC_NA);
	xip_tree = proto_item_add_subtree(ti, ett_xip_tree);

	/* Add XIP version. */
	proto_tree_add_item(xip_tree, hf_xip_version, tvb,
		XIPH_VERS, 1, ENC_BIG_ENDIAN);

	/* Add XIP next header. */
	next_ti = proto_tree_add_item(xip_tree, hf_xip_next_hdr, tvb,
		XIPH_NXTH, 1, ENC_BIG_ENDIAN);

	/* Add XIP payload length. */
	payload_len = tvb_get_ntohs(tvb, XIPH_PLEN);
	payload_ti = proto_tree_add_uint_format(xip_tree, hf_xip_payload_len,
		tvb, XIPH_PLEN, 2, payload_len, "Payload Length: %u bytes",
		payload_len);
	if (tvb_captured_length_remaining(tvb, xiph_len) != payload_len)
		expert_add_info_format(pinfo, payload_ti, &ei_xip_invalid_len,
		"Payload length field (%d bytes) does not match actual payload length (%d bytes)",
		payload_len, tvb_captured_length_remaining(tvb, xiph_len));

	/* Add XIP hop limit. */
	proto_tree_add_item(xip_tree, hf_xip_hop_limit, tvb,
		XIPH_HOPL, 1, ENC_BIG_ENDIAN);

	/* Add XIP number of destination DAG nodes. */
	num_ti = proto_tree_add_item(xip_tree, hf_xip_num_dst, tvb,
		XIPH_NDST, 1, ENC_BIG_ENDIAN);
	if (num_dst_nodes > XIA_NODES_MAX || num_dst_nodes < 0) {
		expert_add_info_format(pinfo, num_ti, &ei_xip_bad_num_dst,
		"The number of destination DAG nodes (%d) must be between 0 and XIA_NODES_MAX (%d)",
		num_dst_nodes, XIA_NODES_MAX);

		if (num_dst_nodes > XIA_NODES_MAX)
			num_dst_nodes = XIA_NODES_MAX;
		else
			num_dst_nodes = 0;
	}

	/* Add XIP number of source DAG nodes. */
	num_ti = proto_tree_add_item(xip_tree, hf_xip_num_src, tvb,
		XIPH_NSRC, 1, ENC_BIG_ENDIAN);
	if (num_src_nodes > XIA_NODES_MAX || num_src_nodes < 0) {
		expert_add_info_format(pinfo, num_ti, &ei_xip_bad_num_src,
		"The number of source DAG nodes (%d) must be between 0 and XIA_NODES_MAX (%d)",
		num_src_nodes, XIA_NODES_MAX);

		if (num_src_nodes > XIA_NODES_MAX)
			num_src_nodes = XIA_NODES_MAX;
		else
			num_src_nodes = 0;
	}

	/* Add XIP last node. */
	last_node = tvb_get_guint8(tvb, XIPH_LSTN);
	proto_tree_add_uint_format(xip_tree, hf_xip_last_node, tvb,
		XIPH_LSTN, 1, last_node, "Last Node: %u %s", last_node,
		last_node == XIA_ENTRY_NODE_INDEX ? "(entry node)" : "");

	/* Construct Destination DAG subtree. */
	if (num_dst_nodes > 0)
		construct_dag(tvb, pinfo, xip_tree, ett_xip_ddag,
			hf_xip_dst_dag, hf_xip_dst_dag_entry,
			num_dst_nodes, XIPH_DSTD);

	/* Construct Source DAG subtree. */
	if (num_src_nodes > 0)
		construct_dag(tvb, pinfo, xip_tree, ett_xip_sdag,
			hf_xip_src_dag, hf_xip_src_dag_entry,
			num_src_nodes, XIPH_DSTD + num_dst_nodes * NODE_SIZE);

	next_header_offset = XIPH_DSTD + NODE_SIZE *
		(num_dst_nodes + num_src_nodes);

	next_header = tvb_get_guint8(tvb, XIPH_NXTH);
	switch (next_header) {
	case XIA_NEXT_HEADER_DATA:
		next_tvb = tvb_new_subset(tvb, next_header_offset, -1, -1);
		call_dissector(data_handle, next_tvb, pinfo, tree);
		break;
	default:
		expert_add_info_format(pinfo, next_ti, &ei_xip_next_header,
		 "Unrecognized next header type: 0x%02x", next_header);
		break;
	}
}

static gint
dissect_xip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	void *data _U_)
{
	guint16 xiph_len;
	gint8 num_dst_nodes, num_src_nodes;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "XIP");
	col_set_str(pinfo->cinfo, COL_INFO, "XIP Packet");

	num_dst_nodes = (gint8)tvb_get_guint8(tvb, XIPH_NDST);
	num_src_nodes = (gint8)tvb_get_guint8(tvb, XIPH_NSRC);
	xiph_len = 8 + (NODE_SIZE * num_dst_nodes) +
		(NODE_SIZE * num_src_nodes);

	if (xiph_len < XIPH_MIN_LEN) {
		col_add_fstr(pinfo->cinfo, COL_INFO,
			"Bad XIP header length (%u, should be at least %u)",
			xiph_len, XIPH_MIN_LEN);
		return 0;
	}

	if (tree)
		display_xip(tvb, pinfo, tree, xiph_len,
			num_dst_nodes, num_src_nodes);

	return tvb_captured_length(tvb);
}

void
proto_register_xip(void)
{
	static hf_register_info hf[] = {

		/* XIP Header. */

		{ &hf_xip_version,
		{ "Version", "xip.version", FT_UINT8,
		   BASE_DEC, NULL, 0x0,	NULL, HFILL }},

		{ &hf_xip_next_hdr,
		{ "Next Header", "xip.next_hdr", FT_UINT8,
		   BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_xip_payload_len,
		{ "Payload Length", "xip.payload_len", FT_UINT16,
		   BASE_DEC, NULL, 0x0,	NULL, HFILL }},

		{ &hf_xip_hop_limit,
		{ "Hop Limit", "xip.hop_limit", FT_UINT8,
		   BASE_DEC, NULL, 0x0,	NULL, HFILL }},

		{ &hf_xip_num_dst,
		{ "Number of Destination Nodes", "xip.num_dst", FT_UINT8,
		   BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_xip_num_src,
		{ "Number of Source Nodes", "xip_num_src", FT_UINT8,
		   BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_xip_last_node,
		{ "Last Node", "xip.last_node", FT_UINT8,
		   BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_xip_dst_dag,
		{ "Destination DAG", "xip.dst_dag", FT_NONE,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_xip_dst_dag_entry,
		{ "Destination DAG Entry", "xip.dst_dag_entry", FT_STRING,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_xip_src_dag,
		{ "Source DAG", "xip.src_dag", FT_NONE,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_xip_src_dag_entry,
		{ "Source DAG Entry", "xip.src_dag_entry", FT_STRING,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_xip_tree,
		&ett_xip_ddag,
		&ett_xip_sdag
	};

	static ei_register_info ei[] = {
		{ &ei_xip_invalid_len,
		{ "xip.invalid.len", PI_MALFORMED, PI_ERROR,
		  "Invalid length", EXPFILL }},

		{ &ei_xip_next_header,
		{ "xip.next.header", PI_MALFORMED, PI_ERROR,
		  "Invalid next header", EXPFILL }},

		{ &ei_xip_invalid_dag,
		{ "xip.invalid.dag", PI_MALFORMED, PI_ERROR,
		  "Invalid DAG", EXPFILL }},

		{ &ei_xip_bad_num_dst,
		{ "xip.bad_num_dst", PI_MALFORMED, PI_ERROR,
		  "Invalid number of destination DAG nodes", EXPFILL }},

		{ &ei_xip_bad_num_src,
		{ "xip.bad_num_src", PI_MALFORMED, PI_ERROR,
		  "Invalid number of source DAG nodes", EXPFILL }}
	};

	expert_module_t* expert_xip;

	proto_xip = proto_register_protocol(
		"eXpressive Internet Protocol",
		"XIP",
	        "xip");

  	new_register_dissector("xip", dissect_xip, proto_xip);
	proto_register_field_array(proto_xip, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_xip = expert_register_protocol(proto_xip);
	expert_register_field_array(expert_xip, ei, array_length(ei));

	xip_dissector_table = register_dissector_table("xip",
		"XIP", FT_UINT32, BASE_DEC);
}

void
proto_reg_handoff_xip(void)
{
	dissector_handle_t xip_handle;

	xip_handle = new_create_dissector_handle(dissect_xip, proto_xip);
	dissector_add_uint("ethertype", ETHERTYPE_XIP, xip_handle);

	data_handle = find_dissector("data");
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
