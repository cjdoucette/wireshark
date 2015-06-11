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
#include <epan/value_string.h>

/* XIA principals. */
#define XIDTYPE_NAT		0x00
#define XIDTYPE_AD		0x10
#define XIDTYPE_HID		0x11
#define XIDTYPE_CID		0x12
#define XIDTYPE_SID		0x13
#define XIDTYPE_UNI4ID		0x14
#define XIDTYPE_I4ID		0x15
#define XIDTYPE_U4ID		0x16
#define XIDTYPE_XDP		0x17
#define XIDTYPE_SRVCID		0x18
#define XIDTYPE_FLOWID		0x19
#define XIDTYPE_ZF		0x20

/* Principal string values. */
static const value_string xidtype_vals[] = {
	{ XIDTYPE_AD,		"ad" },
	{ XIDTYPE_HID,		"hid" },
	{ XIDTYPE_CID,		"cid" },
	{ XIDTYPE_SID,		"sid" },
	{ XIDTYPE_UNI4ID,	"uni4id" },
	{ XIDTYPE_I4ID,		"i4id" },
	{ XIDTYPE_U4ID,		"u4id" },
	{ XIDTYPE_XDP,		"xdp" },
	{ XIDTYPE_SRVCID,	"serval" },
	{ XIDTYPE_FLOWID,	"flowid" },
	{ XIDTYPE_ZF,		"zf" },
	{ 0,			NULL }
};

enum xia_addr_error {
	/* There's a non-XIDTYPE_NAT node after an XIDTYPE_NAT node. */
	XIAEADDR_NAT_MISPLACED = 1,
	/* Edge-selected bit is only valid in packets. */
	XIAEADDR_CHOSEN_EDGE,
	/* There's a non-empty edge after an Empty Edge.
	 * This error can also occur if an empty edge is selected. */
	XIAEADDR_EE_MISPLACED,
	/* An edge of a node is out of range. */
	XIAEADDR_EDGE_OUT_RANGE,
	/* The nodes are not in topological order. Notice that being in
	 * topological guarntees that the graph is acyclic, and has a simple,
	 * cheap test. */
	XIAEADDR_NOT_TOPOLOGICAL,
	/* No single component. */
	XIAEADDR_MULTI_COMPONENTS,
	/* Entry node is not present. */
	XIAEADDR_NO_ENTRY
};

#define XIA_ENTRY_NODE_INDEX	0x7e
#define XIA_XID_MAX		20
#define XIA_OUTDEGREE_MAX	4
#define XIA_NODES_MAX		9

typedef guint32 xid_type_t;

struct xia_xid {
	xid_type_t	xid_type;		/* XID type. */
	guint8		xid_id[XIA_XID_MAX];	/* XID. */
};

struct xia_row {
	struct xia_xid	s_xid;
	union {
		guint8	a[XIA_OUTDEGREE_MAX];
		guint32	i;
	} s_edge;				/* Out edges. */
};

struct xia_addr {
	struct xia_row s_row[XIA_NODES_MAX];
};

/* XIA_MAX_STRADDR_SIZE - The maximum size of an XIA address as a string
 * in bytes. It's the recommended size to call xia_ntop with. It includes space
 * for an invalid sign (i.e. '!'), the type and name of a nodes in
 * hexadecimal, the out-edges, the two separators (i.e. '-') per node,
 * the edge-chosen sign (i.e. '>') for each selected edge,
 * the node separators (i.e. ':' or ":\n"), a string terminator (i.e. '\0'),
 * and an extra '\n' at the end the caller may want to add.
 */
#define MAX_PPAL_NAME_SIZE	32
#define XIA_MAX_STRID_SIZE	(XIA_XID_MAX * 2 + 1)
#define XIA_MAX_STRXID_SIZE	(MAX_PPAL_NAME_SIZE + XIA_MAX_STRID_SIZE)
#define XIA_MAX_STRADDR_SIZE	(1 + XIA_NODES_MAX * \
	(XIA_MAX_STRXID_SIZE + XIA_OUTDEGREE_MAX * 2 + 2) + 1)

/*
 *	Validating addresses
 */

#define XIA_CHOSEN_EDGE		0x80
#define XIA_EMPTY_EDGE		0x7f

#define XIA_EMPTY_EDGES (XIA_EMPTY_EDGE << 24 | XIA_EMPTY_EDGE << 16 |\
			 XIA_EMPTY_EDGE <<  8 | XIA_EMPTY_EDGE)
#define XIA_CHOSEN_EDGES (XIA_CHOSEN_EDGE << 24 | XIA_CHOSEN_EDGE << 16 |\
			 XIA_CHOSEN_EDGE <<  8 | XIA_CHOSEN_EDGE)

static inline gint
is_edge_chosen(guint8 e)
{
	return e & XIA_CHOSEN_EDGE;
}

static inline gint
is_any_edge_chosen(const struct xia_row *row)
{
	return row->s_edge.i & XIA_CHOSEN_EDGES;
}

static inline gint
is_empty_edge(guint8 e)
{
	return (e & XIA_EMPTY_EDGE) == XIA_EMPTY_EDGE;
}

static inline gint
xia_is_nat(xid_type_t ty)
{
	return ty == XIDTYPE_NAT;
}

static gint
xia_are_edges_valid(const struct xia_row *row,
	guint8 node, guint8 num_node, guint32 *pvisited)
{
	const guint8 *edge;
	guint32 all_edges, bits;
	gint i;

	if (is_any_edge_chosen(row)) {
		/* Since at least an edge of last_node has already
		 * been chosen, the address is corrupted.
		 */
		return -XIAEADDR_CHOSEN_EDGE;
	}

	edge = row->s_edge.a;
	all_edges = g_ntohl(row->s_edge.i);
	bits = 0xffffffff;
	for (i = 0; i < XIA_OUTDEGREE_MAX; i++, edge++) {
		guint8 e;
		e = *edge;
		if (e == XIA_EMPTY_EDGE) {
			if ((all_edges & bits) !=
				(XIA_EMPTY_EDGES & bits))
				return -XIAEADDR_EE_MISPLACED;
			else
				break;
		} else if (e >= num_node) {
			return -XIAEADDR_EDGE_OUT_RANGE;
		} else if (node < (num_node - 1) && e <= node) {
			/* Notice that if (node == XIA_ENTRY_NODE_INDEX)
			 * it still works fine because XIA_ENTRY_NODE_INDEX
			 * is greater than (num_node - 1).
			 */
			return -XIAEADDR_NOT_TOPOLOGICAL;
		}
		bits >>= 8;
		*pvisited |= 1 << e;
	}
	return 0;
}

static gint
xia_test_addr(const struct xia_addr *addr)
{
	gint i, n;
	gint saw_nat = 0;
	guint32 visited = 0;

	/* Test that XIDTYPE_NAT is present only on last rows. */
	n = XIA_NODES_MAX;
	for (i = 0; i < XIA_NODES_MAX; i++) {
		xid_type_t ty;
		ty = addr->s_row[i].s_xid.xid_type;
		if (saw_nat) {
			if (!xia_is_nat(ty))
				return -XIAEADDR_NAT_MISPLACED;
		} else if (xia_is_nat(ty)) {
			n = i;
			saw_nat = 1;
		}
	}
	/* n = number of nodes from here. */

	/* Test edges are well formed. */
	for (i = 0; i < n; i++) {
		gint rc;
		rc = xia_are_edges_valid(&addr->s_row[i], i, n, &visited);
		if (rc)
			return rc;
	}

	if (n >= 1) {
		/* Test entry point is present. Notice that it's just a
		 * friendlier error since it's also XIAEADDR_MULTI_COMPONENTS.
		 */
		guint32 all_edges;
		all_edges = addr->s_row[n - 1].s_edge.i;
		if (all_edges == XIA_EMPTY_EDGES)
			return -XIAEADDR_NO_ENTRY;

		if (visited != ((1U << n) - 1))
			return -XIAEADDR_MULTI_COMPONENTS;
	}

	return n;
}

/*
 *	Printing addresses out
 */

#define INDEX_BASE 36

static inline gchar
edge_to_char(guint8 e)
{
	const gchar *ch_edge = "0123456789abcdefghijklmnopqrstuvwxyz";
	e &= ~XIA_CHOSEN_EDGE;
	if (e < INDEX_BASE)
		return ch_edge[e];
	else if (is_empty_edge(e))
		return '*';
	else
		return '+';
}

/* Perform s >= u.
 * It's useful to avoid compilation warnings, and
 * to be sure what's going on when numbers are large.
 */
static inline gint
su_ge(gint s, guint u)
{
	return (s >= 0) && ((guint)s >= u);
}

static inline int
add_str(gchar *dst, size_t dstlen, const gchar *s)
{
	gint rc;
	rc = g_snprintf(dst, dstlen, "%s", s);
	if (su_ge(rc, dstlen))
		return -1;
	return rc;
}

static inline gint
add_char(gchar *dst, size_t dstlen, gchar ch)
{
	if (dstlen <= 1)
		return -1;
	dst[0] = ch;
	dst[1] = '\0';
	return 1;
}

static inline void
move_buf(gchar **dst, size_t *dstlen, gint *tot, gint step)
{
	(*dst) += step;
	(*dstlen) -= step;
	(*tot) += step;
}

static gint
edges_to_str(gint valid, gchar *dst, size_t dstlen, const guint8 *edges)
{
	gint tot = 0;
	gchar *begin;
	gint rc, i;

	begin = dst;
	rc = add_char(dst, dstlen, '-');
	if (rc < 0)
		return rc;
	move_buf(&dst, &dstlen, &tot, rc);

	for (i = 0; i < XIA_OUTDEGREE_MAX; i++) {
		if (valid && edges[i] == XIA_EMPTY_EDGE) {
			if (i == 0) {
				*begin = '\0';
				return 0;
			}
			break;
		}

		if (is_edge_chosen(edges[i])) {
			rc = add_char(dst, dstlen, '>');
			if (rc < 0)
				return rc;
			move_buf(&dst, &dstlen, &tot, rc);
		}

		rc = add_char(dst, dstlen, edge_to_char(edges[i]));
		if (rc < 0)
			return rc;
		move_buf(&dst, &dstlen, &tot, rc);
	}
	return tot;
}

static inline gint
ppal_type_to_name(xid_type_t ty, gchar *dst)
{
	const gchar *xid_name = val_to_str_const(ty, xidtype_vals, "!");
	if (strcmp(xid_name, "!") != 0) {
		g_snprintf(dst, strlen(xid_name) + 1, "%s", xid_name);
		return 0;
	} else {
		return -1;
	}
}

static gint
xia_tytop(xid_type_t ty, gchar *dst, size_t dstlen)
{
	if (dstlen < MAX_PPAL_NAME_SIZE)
		return -1;
	if (ppal_type_to_name(ty, dst)) {
		/* Number format. */
		gint rc;
		rc = g_snprintf(dst, dstlen, "0x%x", g_ntohl(ty));
		if (su_ge(rc, dstlen))
			return -1;
		return rc;
	} else {
		/* Return length of principal name.
		 * MAX_PPAL_NAME_SIZE << range(gint), so
		 * this cast is safe.
		 */
		return (gint)strlen(dst);
	}
}

static gint
xia_idtop(const struct xia_xid *src, gchar *dst, size_t dstlen)
{
	const guint32 *pxid;
	gint rc;
	guint32 a, b, c, d, e;

	pxid = (const guint32 *)src->xid_id;
	a = g_ntohl(pxid[0]);
	b = g_ntohl(pxid[1]);
	c = g_ntohl(pxid[2]);
	d = g_ntohl(pxid[3]);
	e = g_ntohl(pxid[4]);

	rc = g_snprintf(dst, dstlen, "%08x%08x%08x%08x%08x", a, b, c, d, e);
	if (su_ge(rc, dstlen))
		return -1;
	return rc;
}

static gint
xia_xidtop(const struct xia_xid *src, gchar *dst, size_t dstlen)
{
	gint tot = 0;
	gint rc;

	rc = xia_tytop(g_ntohl(src->xid_type), dst, dstlen);
	if (rc < 0)
		return rc;
	move_buf(&dst, &dstlen, &tot, rc);

	rc = add_char(dst, dstlen, '-');
	if (rc < 0)
		return rc;
	move_buf(&dst, &dstlen, &tot, rc);

	rc = xia_idtop(src, dst, dstlen);
	if (rc < 0)
		return rc;
	move_buf(&dst, &dstlen, &tot, rc);

	return tot;
}

/* xia_ntop - convert an XIA address to a string.
 * @src can be ill-formed, but xia_ntop won't report an error and will return
 * a string that approximates that ill-formed address.
 * If @include_nl is non-zero, '\n' is added after ':', but not at the end of
 * the address because it's easier to add a '\n' than to remove it.
 *
 * RETURN
 *	-1 on failure. The converted address string is truncated. It may, or
 *	   may not, include the trailing '\0'.
 *	Total number of written bytes on success, NOT including the
 *	   trailing '\0'.
 */
static gint
xia_ntop(const struct xia_addr *src, gchar **buf, gint include_nl)
{
	gint tot = 0;
	gint valid, rc, i;
	const gchar *node_sep;
	gchar *dst, *begin;
	size_t dstlen;

	dst = (gchar *)wmem_alloc(wmem_packet_scope(), XIA_MAX_STRADDR_SIZE);
	if (!dst)
		return -1;
	begin = dst;
	dstlen = XIA_MAX_STRADDR_SIZE;

	valid = xia_test_addr(src) >= 1;
	node_sep = include_nl ? ":\n" : ":";
	if (!valid) {
		rc = add_char(dst, dstlen, '!');
		if (rc < 0)
			return rc;
		move_buf(&dst, &dstlen, &tot, rc);
	}

	for (i = 0; i < XIA_NODES_MAX; i++) {
		const struct xia_row *row;
		row = &src->s_row[i];

		if (xia_is_nat(row->s_xid.xid_type))
			break;

		if (i > 0) {
			rc = add_str(dst, dstlen, node_sep);
			if (rc < 0)
				return rc;
			move_buf(&dst, &dstlen, &tot, rc);
		}

		rc = xia_xidtop(&row->s_xid, dst, dstlen);
		if (rc < 0)
			return rc;
		move_buf(&dst, &dstlen, &tot, rc);

		rc = edges_to_str(valid, dst, dstlen, row->s_edge.a);
		if (rc < 0)
			return rc;
		move_buf(&dst, &dstlen, &tot, rc);
	}

	*buf = begin;
	return tot;
}

void proto_register_xip(void);
void proto_reg_handoff_xip(void);

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
construct_dag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *xip_tree,
	const gint ett, const gint hf, const gint hf_entry,
	const guint8 num_nodes, const guint8 offset)
{
	proto_item *ti = NULL;
	proto_tree *dag_tree = NULL;

	struct xia_addr dag;
	gchar *buf = NULL;

	memset(&dag, 0, sizeof(dag));
	ti = proto_tree_add_item(xip_tree, hf, tvb, offset,
		num_nodes * NODE_SIZE, ENC_BIG_ENDIAN);
	dag_tree = proto_item_add_subtree(ti, ett);
	tvb_memcpy(tvb, (guint8 *)(&dag), offset, NODE_SIZE * num_nodes);
	if (xia_ntop(&dag, &buf, 1) < 0)
		expert_add_info_format(pinfo, ti, &ei_xip_invalid_dag,
			"Truncated DAG");
	proto_tree_add_string_format(dag_tree, hf_entry, tvb, offset,
		NODE_SIZE * num_nodes, buf, "%s", buf);
}

static void
display_xip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	guint16 xiph_len, guint8 num_dst_nodes, guint8 num_src_nodes)
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
	if (num_dst_nodes > XIA_NODES_MAX) {
		expert_add_info_format(pinfo, num_ti, &ei_xip_bad_num_dst,
		"The number of destination DAG nodes (%d) must be less than XIA_NODES_MAX (%d)",
		num_dst_nodes, XIA_NODES_MAX);
		num_dst_nodes = XIA_NODES_MAX;
	}

	/* Add XIP number of source DAG nodes. */
	num_ti = proto_tree_add_item(xip_tree, hf_xip_num_src, tvb,
		XIPH_NSRC, 1, ENC_BIG_ENDIAN);
	if (num_src_nodes > XIA_NODES_MAX) {
		expert_add_info_format(pinfo, num_ti, &ei_xip_bad_num_src,
		"The number of source DAG nodes (%d) must be less than XIA_NODES_MAX (%d)",
		num_src_nodes, XIA_NODES_MAX);
		num_src_nodes = XIA_NODES_MAX;
	}

	/* Add XIP last node. */
	last_node = tvb_get_guint8(tvb, XIPH_LSTN);
	proto_tree_add_uint_format_value(xip_tree, hf_xip_last_node, tvb,
		XIPH_LSTN, 1, last_node, "%d%s", last_node,
		last_node == XIA_ENTRY_NODE_INDEX ? " (entry node)" : "");

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
	guint8 num_dst_nodes, num_src_nodes;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "XIP");
	col_set_str(pinfo->cinfo, COL_INFO, "XIP Packet");

	num_dst_nodes = tvb_get_guint8(tvb, XIPH_NDST);
	num_src_nodes = tvb_get_guint8(tvb, XIPH_NSRC);
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
		{ "Number of Source Nodes", "xip.num_src", FT_UINT8,
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
