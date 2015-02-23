/* packet-xia-serval.c
 * Routines for XIA Serval dissection
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
#include <epan/in_cksum.h>
#include <epan/proto.h>
#include <ipproto.h>
#include <epan/xia.h>

/* Next dissector handles. */
static dissector_handle_t udp_handle;
static dissector_handle_t tcp_handle;

/*
 *	XIA Serval control extension header
 */

#define XIA_SERVAL_EXT_MIN_LEN		2

#define XIA_SERVAL_CEXT_FLAGS_WIDTH	8
#define XIA_SERVAL_CEXT_NONCE_SIZE	8
#define XIA_SERVAL_CEXT_LEN		20

static gint hf_xia_serval_ext_type	= -1;
static gint hf_xia_serval_ext_length	= -1;

static gint hf_xia_serval_cext		= -1;
static gint hf_xia_serval_cext_flags	= -1;
static gint hf_xia_serval_cext_syn	= -1;
static gint hf_xia_serval_cext_rsyn	= -1;
static gint hf_xia_serval_cext_ack	= -1;
static gint hf_xia_serval_cext_nack	= -1;
static gint hf_xia_serval_cext_rst	= -1;
static gint hf_xia_serval_cext_fin	= -1;
static gint hf_xia_serval_cext_verno	= -1;
static gint hf_xia_serval_cext_ackno	= -1;
static gint hf_xia_serval_cext_nonce	= -1;

static gint ett_xia_serval_cext		= -1;
static gint ett_xia_serval_cext_flags	= -1;

static expert_field ei_xia_serval_cext_bad_len	= EI_INIT;

static const gchar *xia_serval_cext_flags[] = {
	"RES",	/* Reserved. */
	"RES",	/* Reserved. */
	"FIN",
	"RST",
	"NACK",
	"ACK",
	"RSYN",
	"SYN",
};

static gint
display_serval_control_ext(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *xia_serval_tree, guint8 offset, guint8 type, guint8 length)
{
	proto_tree *cext_tree, *cext_flags_tree;
	proto_item *ti;
	gint8 flags, bit;
	gboolean found_flag = FALSE;

	/* Create Serval Control Extension tree. */
	ti = proto_tree_add_item(xia_serval_tree, hf_xia_serval_cext, tvb,
		offset, length, ENC_BIG_ENDIAN);
	cext_tree = proto_item_add_subtree(ti, ett_xia_serval_cext);

	/* Add XIA Serval extension type. */
	proto_tree_add_uint(cext_tree, hf_xia_serval_ext_type, tvb,
		offset, 1, type);
	offset++;

	/* Add XIA Serval extension length. */
	ti = proto_tree_add_uint_format(cext_tree, hf_xia_serval_ext_length,
		tvb, offset, 1, length, "Extension Length: %u bytes", length);
	offset++;

	if (length != XIA_SERVAL_CEXT_LEN) {
		expert_add_info_format(pinfo, ti, &ei_xia_serval_cext_bad_len,
			"Bad Serval Control Extension header length: %d bytes (should be %d bytes)",
			length, XIA_SERVAL_CEXT_LEN);
		return -1;
	}

	/* Create XIA Serval Control Extension flags tree. */
	ti = proto_tree_add_item(cext_tree, hf_xia_serval_cext_flags,
		tvb, offset, 1, ENC_BIG_ENDIAN);
	cext_flags_tree = proto_item_add_subtree(ti, ett_xia_serval_cext_flags);

	/* Add flag strings to tree header, so that the flags can
	 * easily be seen without having to open the tree.
	 */
	flags = tvb_get_guint8(tvb, offset);
	for (bit = 7; bit >= 0; bit--) {
		if (flags & (1 << bit)) {
			if (!found_flag) {
				proto_item_append_text(ti, " (");
				found_flag = TRUE;
			} else {
				proto_item_append_text(ti, ", ");
			}
			proto_item_append_text(ti, "%s",
				xia_serval_cext_flags[bit]);
		}
	}
	if (found_flag)
		proto_item_append_text(ti, ")");

	/* Add individual flag fields. */
	proto_tree_add_bits_item(cext_flags_tree,
		hf_xia_serval_cext_syn, tvb, (offset * 8) + 0,
		1, ENC_BIG_ENDIAN);
	proto_tree_add_bits_item(cext_flags_tree,
		hf_xia_serval_cext_rsyn, tvb, (offset * 8) + 1,
		1, ENC_BIG_ENDIAN);
	proto_tree_add_bits_item(cext_flags_tree,
		hf_xia_serval_cext_ack, tvb, (offset * 8) + 2,
		1, ENC_BIG_ENDIAN);
	proto_tree_add_bits_item(cext_flags_tree,
		hf_xia_serval_cext_nack, tvb, (offset * 8) + 3,
		1, ENC_BIG_ENDIAN);
	proto_tree_add_bits_item(cext_flags_tree,
		hf_xia_serval_cext_rst, tvb, (offset * 8) + 4,
		1, ENC_BIG_ENDIAN);
	proto_tree_add_bits_item(cext_flags_tree,
		hf_xia_serval_cext_fin, tvb, (offset * 8) + 5,
		1, ENC_BIG_ENDIAN);
	/* Skip two bits for res1. */
	offset++;

	/* Skip a byte for res2. */
	offset++;

	/* Add verification number. */
	proto_tree_add_item(cext_tree, hf_xia_serval_cext_verno,
		tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* Add acknowledgement number. */
	proto_tree_add_item(cext_tree, hf_xia_serval_cext_ackno,
		tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* Add nonce. */
	proto_tree_add_string(cext_tree, hf_xia_serval_cext_nonce,
		tvb, offset, 8,
		tvb_bytes_to_str(wmem_packet_scope(), tvb, offset,
			XIA_SERVAL_CEXT_NONCE_SIZE));
	offset += 8;

	/* Displayed XIA_SERVAL_CEXT_LEN bytes. */
	return XIA_SERVAL_CEXT_LEN;
}

/*
 *	XIA Serval extension header
 */

#define XIA_SERVAL_EXT_TYPE_MASK	0xF0
#define XIA_SERVAL_CONTROL_EXT_TYPE	0

static expert_field ei_xia_serval_bad_ext	= EI_INIT;

static gint
display_serval_ext(tvbuff_t *tvb, packet_info *pinfo, proto_item *ti,
	proto_tree *xia_serval_tree, guint8 offset)
{
	guint8 type, length;
	type = tvb_get_guint8(tvb, offset) & XIA_SERVAL_EXT_TYPE_MASK;
	length = tvb_get_guint8(tvb, offset + 1);

	switch (type) {
	case XIA_SERVAL_CONTROL_EXT_TYPE:
		return display_serval_control_ext(tvb, pinfo, xia_serval_tree,
			offset, type, length);
	default:
		expert_add_info_format(pinfo, ti, &ei_xia_serval_bad_ext,
			"Unrecognized Serval extension header type: 0x%02x",
			type);
		return -1;
	}
}

/*
 *	XIA Serval header
 */

#define XSRVL_LEN		0
#define XSRVL_PRO		1
#define XSRVL_CHK		2
#define XSRVL_EXT		4

#define XIA_SERVAL_MIN_LEN	4

#define XIA_SERVAL_PROTO_DATA	0
#define XIA_SERVAL_PROTO_TCP	6
#define XIA_SERVAL_PROTO_UDP	17

static gint proto_xia_serval		= -1;

static gint hf_xia_serval_hl		= -1;
static gint hf_xia_serval_proto		= -1;
static gint hf_xia_serval_check		= -1;

static gint ett_xia_serval_tree		= -1;

static expert_field ei_xia_serval_bad_proto	= EI_INIT;
static expert_field ei_xia_serval_bad_checksum	= EI_INIT;

static const value_string xia_serval_proto_vals[] = {
	{ XIA_SERVAL_PROTO_DATA,	"Data" },
	{ XIA_SERVAL_PROTO_TCP,		"TCP" },
	{ XIA_SERVAL_PROTO_UDP,		"UDP" },
	{ 0,				NULL },
};

static void
display_xia_serval(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	guint8 xsh_len)
{
	proto_tree *xia_serval_tree = NULL;
	proto_item *ti, *cti;
	tvbuff_t *next_tvb;

	guint8 offset, protocol;
	guint16 packet_checksum, actual_checksum;
	vec_t cksum_vec;

	/* Create XIA Serval header tree. */
	ti = proto_tree_add_item(tree, proto_xia_serval, tvb,
		0, xsh_len, ENC_NA);
	xia_serval_tree = proto_item_add_subtree(ti, ett_xia_serval_tree);

	/* Add XIA Serval header length. */
	proto_tree_add_uint_format(xia_serval_tree, hf_xia_serval_hl, tvb,
		XSRVL_LEN, 1, xsh_len, "Header Length: %u bytes", xsh_len);

	/* Add XIA Serval protocol. */
	protocol = tvb_get_guint8(tvb, XSRVL_PRO);
	switch (protocol) {
	case XIA_SERVAL_PROTO_DATA:
	case XIA_SERVAL_PROTO_UDP:
	case XIA_SERVAL_PROTO_TCP:
		proto_tree_add_uint_format(xia_serval_tree,
			hf_xia_serval_proto, tvb, XSRVL_PRO, 1,
			protocol, "Protocol: %u (%s)", protocol,
			val_to_str(protocol, xia_serval_proto_vals, "(%s)"));
		break;
	default:
		expert_add_info_format(pinfo, ti, &ei_xia_serval_bad_proto,
			"Unrecognized protocol type: 0x%02x", protocol);
		break;
	}

	/* Compute checksum. */
	SET_CKSUM_VEC_TVB(cksum_vec, tvb, 0, xsh_len);
	actual_checksum = in_cksum(&cksum_vec, 1);
	/* Get XIA Serval checksum. */
	packet_checksum = tvb_get_ntohs(tvb, XSRVL_CHK);

	if (actual_checksum == 0) {
		/* Add XIA Serval checksum as correct. */
		proto_tree_add_uint_format(xia_serval_tree,
			hf_xia_serval_check, tvb, XSRVL_CHK, 2, packet_checksum,
			"Header checksum: 0x%04x [correct]", packet_checksum);
	} else {
		/* Add XIA Serval checksum as incorrect. */
		cti = proto_tree_add_uint_format(xia_serval_tree,
			hf_xia_serval_check, tvb, XSRVL_CHK, 2, packet_checksum,
			"Header checksum: 0x%04x [incorrect, should be 0x%04x]",
			packet_checksum,
			in_cksum_shouldbe(packet_checksum, actual_checksum));

		expert_add_info_format(pinfo, cti, &ei_xia_serval_bad_checksum,
			"Bad checksum");
	}

	/* If there's still more room, check for extension headers. */
	offset = XSRVL_EXT;
	while (xsh_len - offset >= XIA_SERVAL_EXT_MIN_LEN) {
		gint bytes_displayed = display_serval_ext(tvb, pinfo, ti,
			xia_serval_tree, offset);

		/* Extension headers are malformed, so we can't say
		 * what the rest of the packet holds. Stop dissecting.
		 */
		if (bytes_displayed < 0)
			return;

		offset += bytes_displayed;
	}

	switch (protocol) {
	case XIA_SERVAL_PROTO_DATA:
		/* Let the XIP dissector handle calling the data dissector. */
		break;
	case XIA_SERVAL_PROTO_TCP: {
		guint8 tcp_len = hi_nibble(tvb_get_guint8(tvb,
			offset + 12)) * 4;
		next_tvb = tvb_new_subset(tvb, offset, tcp_len, tcp_len);
		call_dissector(tcp_handle, next_tvb, pinfo, tree);
		break;
	}
	case XIA_SERVAL_PROTO_UDP:
		next_tvb = tvb_new_subset(tvb, offset, 8, 8);
		call_dissector(udp_handle, next_tvb, pinfo, tree);
		break;
	default:
		break;
	}
}

static gint
dissect_xia_serval(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	void *data _U_)
{
	guint8 xsh_len;
	xsh_len = tvb_get_guint8(tvb, XSRVL_LEN) << 2;
	if (xsh_len < XIA_SERVAL_MIN_LEN) {
		col_add_fstr(pinfo->cinfo, COL_INFO,
		"Bad XIA Serval header length (%u, should be at least %u)",
		xsh_len, XIA_SERVAL_MIN_LEN);
		return 0;
	}

	if (tree)
		display_xia_serval(tvb, pinfo, tree, xsh_len);

	return tvb_captured_length(tvb);
}

void
proto_register_xia_serval(void)
{
	static hf_register_info hf[] = {

		/* Serval Header. */

		{ &hf_xia_serval_hl,
		{ "Header Length", "xia_.serval.hl", FT_UINT8,
		   BASE_DEC, NULL, 0x0,	NULL, HFILL }},

		{ &hf_xia_serval_proto,
		{ "Protocol", "xia_serval.proto", FT_UINT8,
		   BASE_DEC, NULL, 0x0,	NULL, HFILL }},

		{ &hf_xia_serval_check,
		{ "Checksum", "xia_serval.check", FT_UINT16,
		   BASE_HEX, NULL, 0x0,	NULL, HFILL }},

		/* Serval Extension Header. */

		{ &hf_xia_serval_ext_type,
		{ "Extension Type", "xia_serval.ext_type", FT_UINT8,
		   BASE_DEC, NULL, 0x0,	NULL, HFILL }},

		{ &hf_xia_serval_ext_length,
		{ "Extension Length", "xia_serval.ext_length", FT_UINT8,
		   BASE_DEC, NULL, 0x0,	NULL, HFILL }},

		/* Serval Control Extension Header. */

		{ &hf_xia_serval_cext,
		{ "Serval Control Extension", "xia_serval.cext",
		   FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_xia_serval_cext_flags,
		{ "Flags", "xia_serval.cext_flags", FT_UINT8, BASE_HEX,
		  NULL, 0x0, NULL, HFILL }},

		{ &hf_xia_serval_cext_syn,
		{ "SYN", "xia_serval.cext_syn", FT_BOOLEAN, BASE_NONE,
		  TFS(&tfs_set_notset), 0x0, NULL, HFILL }},

		{ &hf_xia_serval_cext_rsyn,
		{ "RSYN", "xia_serval.cext_rsyn", FT_BOOLEAN, BASE_NONE,
		  TFS(&tfs_set_notset), 0x0, NULL, HFILL }},

		{ &hf_xia_serval_cext_ack,
		{ "ACK", "xia_serval.cext_ack", FT_BOOLEAN, BASE_NONE,
		  TFS(&tfs_set_notset), 0x0, NULL, HFILL }},

		{ &hf_xia_serval_cext_nack,
		{ "NACK", "xia_serval.cext_nack", FT_BOOLEAN, BASE_NONE,
		  TFS(&tfs_set_notset), 0x0, NULL, HFILL }},

		{ &hf_xia_serval_cext_rst,
		{ "RST", "xia_serval.cext_rst", FT_BOOLEAN, BASE_NONE,
		  TFS(&tfs_set_notset), 0x0, NULL, HFILL }},

		{ &hf_xia_serval_cext_fin,
		{ "FIN", "xia_serval.cext_fin", FT_BOOLEAN, BASE_NONE,
		  TFS(&tfs_set_notset), 0x0, NULL, HFILL }},

		{ &hf_xia_serval_cext_verno,
		{ "Version Number", "xia_serval.cext_verno", FT_UINT32,
		  BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_xia_serval_cext_ackno,
		{ "Acknowledgement Number", "xia_serval.cext_ackno",
		  FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_xia_serval_cext_nonce,
		{ "Nonce", "xia_serval.cext_nonce", FT_STRING,
		  BASE_NONE, NULL, 0x0, NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_xia_serval_tree,
		&ett_xia_serval_cext,
		&ett_xia_serval_cext_flags
	};

	static ei_register_info ei[] = {
		{ &ei_xia_serval_bad_ext,
		{ "xia_serval.bad_ext", PI_MALFORMED, PI_ERROR,
		  "Bad extension header type", EXPFILL }},

		{ &ei_xia_serval_bad_proto,
		{ "xia_serval.bad_proto", PI_MALFORMED, PI_ERROR,
		  "Bad protocol type", EXPFILL }},

		{ &ei_xia_serval_bad_checksum,
		{ "xia_serval.bad_checksum", PI_MALFORMED, PI_ERROR,
		  "Incorrect checksum", EXPFILL }},

		{ &ei_xia_serval_cext_bad_len,
		{ "xia_serval.cext_bad_len", PI_MALFORMED, PI_ERROR,
		  "Bad Control Extension header length", EXPFILL }}
	};

	expert_module_t* expert_xia_serval;

	proto_xia_serval = proto_register_protocol(
		"XIA Serval",
		"XIA Serval",
	        "xiaserval");
  	new_register_dissector("xiaserval", dissect_xia_serval,
		proto_xia_serval);
	proto_register_field_array(proto_xia_serval, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_xia_serval = expert_register_protocol(proto_xia_serval);
	expert_register_field_array(expert_xia_serval, ei, array_length(ei));
}

void
proto_reg_handoff_xia_serval(void)
{
	dissector_handle_t xia_serval_handle;

	xia_serval_handle = new_create_dissector_handle(dissect_xia_serval,
		proto_xia_serval);
	/* We could also use XIDTYPE_FLOWID here for Serval. */
	dissector_add_uint("xip", XIDTYPE_SRVCID, xia_serval_handle);

	udp_handle = find_dissector("udp");
	tcp_handle = find_dissector("tcp");
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
