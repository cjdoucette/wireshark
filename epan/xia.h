/* xia.h
 * Utility routines and definitions for XIA addresses.
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

#ifndef __XIA_H__
#define __XIA_H__

#include <asm/byteorder.h>
#include <epan/value_string.h>

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
extern gint xia_ntop(const struct xia_addr *src, gchar **buf, gint include_nl);

#endif
