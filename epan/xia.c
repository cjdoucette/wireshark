/* xia.c
 * Utility routines and definitions for XIP packet dissection.
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

#include <epan/xia.h>

/*
 *	Validating addresses
 */

/* To be used when flipping bytes isn't necessary. */
#define be32_to_raw_cpu(n)	((__u32)(n))

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
	return be32_to_raw_cpu(row->s_edge.i) & XIA_CHOSEN_EDGES;
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
	all_edges = __be32_to_cpu(row->s_edge.i);
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
		if (be32_to_raw_cpu(all_edges) == XIA_EMPTY_EDGES)
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
ppal_type_to_name(xid_type_t type, gchar *name)
{
	const gchar *xid_name;
	xid_name = val_to_str_const(type, xidtype_vals, "nat");
	if (xid_name) {
		g_snprintf(name, strlen(xid_name) + 1, "%s", xid_name);
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
		rc = g_snprintf(dst, dstlen, "0x%x", __be32_to_cpu(ty));
		if (su_ge(rc, dstlen))
			return -1;
		return rc;
	} else {
		return strlen(dst);
	}
}

static gint
xia_idtop(const struct xia_xid *src, gchar *dst, size_t dstlen)
{
	const guint32 *pxid;
	gint rc;
	guint32 a, b, c, d, e;

	pxid = (const guint32 *)src->xid_id;
	a = __be32_to_cpu(pxid[0]);
	b = __be32_to_cpu(pxid[1]);
	c = __be32_to_cpu(pxid[2]);
	d = __be32_to_cpu(pxid[3]);
	e = __be32_to_cpu(pxid[4]);

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

	rc = xia_tytop(__be32_to_cpu(src->xid_type), dst, dstlen);
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

gint
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
