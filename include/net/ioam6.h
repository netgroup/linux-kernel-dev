/* SPDX-License-Identifier: GPL-2.0+ */
/*
 *  IPv6 IOAM implementation
 *
 *  Author:
 *  Justin Iurman <justin.iurman@uliege.be>
 */

#ifndef _NET_IOAM6_H
#define _NET_IOAM6_H

#include <linux/net.h>
#include <linux/ipv6.h>
#include <linux/ioam6.h>
#include <linux/ioam6_genl.h>
#include <linux/rhashtable-types.h>
#include <linux/bpf.h>
#include <linux/percpu.h>

struct ioam6_namespace {
	struct rhash_head head;
	struct rcu_head rcu;

	struct ioam6_schema __rcu *schema;
#ifdef CONFIG_IPV6_IOAM6_GOB
	struct ioam6_gob_schema __rcu *gob_schema;

	/* Namespace-implied GOB: size in octets of the GOB payload carried,
	 * without trailer, at the tail of every option of this namespace.
	 * 0 if the namespace follows the default (trailer-based) mode.
	 */
	u8 gob_implied_len;
#endif

	__be16 id;
	__be32 data;
	__be64 data_wide;
};

struct ioam6_schema {
	struct rhash_head head;
	struct rcu_head rcu;

	struct ioam6_namespace __rcu *ns;

	u32 id;
	int len;
	__be32 hdr;

	u8 data[];
};

struct bpf_hbh_prog {
	struct bpf_prog *prog;
	char *name;
};

struct ioam6_gob_schema {
	struct rhash_head head;
	struct rcu_head rcu;

	struct ioam6_namespace __rcu *ns;

	u32 id;
	struct bpf_hbh_prog bpf;
};

struct ioam6_pernet_data {
	struct mutex lock;
	struct rhashtable namespaces;
	struct rhashtable schemas;
#ifdef CONFIG_IPV6_IOAM6_GOB
	struct rhashtable gob_schemas;
#endif
};

static inline struct ioam6_pernet_data *ioam6_pernet(struct net *net)
{
#if IS_ENABLED(CONFIG_IPV6)
	return net->ipv6.ioam6_data;
#else
	return NULL;
#endif
}

/* bpf context for BPF_PROG_TYPE_IOAM6_GOB.
 *
 * @len:    length in octets of the GOB payload, i.e. data_end - data. The GOB
 *          trailer, when the option has one, is not counted.
 * @schema: Schema ID of the GOB payload: the one carried by the GOB trailer
 *          in the default mode, the one of the GOB schema bound to the
 *          namespace in the namespace-implied mode.
 */
struct bpf_ioam6_trace_gob_ctx {
	__u32 len;
	__u32 schema;
	void *data;
	void *data_end;

	struct sk_buff *skb;
};

static inline bool ioam6_trace_gob_enabled(struct ioam6_trace_hdr *trace)
{
	return !!trace->type.gob;
}

/*
 * IOAM Pre-allocated Trace Option layout inside the IPv6 Hop-by-Hop
 * options. The option header (ioam6_hdr) always immediately precedes
 * the trace header (ioam6_trace_hdr):
 *
 *   +----------------+----------------------+--------------------------+
 *   | ioam6_hdr (4B) | ioam6_trace_hdr (8B) | data[]: node data | GOB  |
 *   +----------------+----------------------+--------------------------+
 *   ^                ^
 *   opt              trace   (trace == opt + 1,  opt == trace - 1)
 *
 * opt   : opt_type, opt_len, reserved, IOAM Option-Type (the TLV header).
 * trace : namespace_id, nodelen, remlen, trace-type, then data[].
 */
static inline struct ioam6_trace_hdr *
ioam6_opt_to_trace(struct ioam6_hdr *opt)
{
	return (struct ioam6_trace_hdr *)(opt + 1);
}

static inline struct ioam6_hdr *
ioam6_trace_to_opt(struct ioam6_trace_hdr *trace)
{
	return (struct ioam6_hdr *)trace - 1;
}

static inline struct ioam6_trace_gob_hdr *
ioam6_trace_gob_hdr_get(struct ioam6_hdr *hdr)
{
	struct ioam6_trace_hdr *trace = ioam6_opt_to_trace(hdr);
	struct ioam6_trace_gob_hdr *gob;
	u8 *opt_end;

	if (!ioam6_trace_gob_enabled(trace))
		return NULL;

	/* opt_len counts the bytes after opt_type and opt_len (2B). The PadN
	 * stays outside the option, so opt_len ends right at the GOB header,
	 * which is the last 4-byte word of the option.
	 */
	opt_end = (u8 *)hdr + 2 + hdr->opt_len;
	gob = (struct ioam6_trace_gob_hdr *)(opt_end - sizeof(*gob));

	return gob;
}

static inline u32 ioam6_trace_gob_plen(struct ioam6_trace_gob_hdr *gob_hdr)
{
	u32 hdr = be32_to_cpu(gob_hdr->hdr);

	return (hdr >> IOAM6_TRACE_GOB_LEN_SHIFT) * 4;
}

static inline u32 ioam6_trace_gob_schema(struct ioam6_trace_gob_hdr *gob_hdr)
{
	u32 hdr = be32_to_cpu(gob_hdr->hdr);

	return hdr & IOAM6_TRACE_GOB_SCHEMA_ID_MASK;
}

static inline u8 ioam6_ns_gob_implied_len(const struct ioam6_namespace *ns)
{
#ifdef CONFIG_IPV6_IOAM6_GOB
	return READ_ONCE(ns->gob_implied_len);
#else
	return 0;
#endif
}

enum ioam6_gob_mode {
	IOAM6_GOB_MODE_NONE	= 0,
	IOAM6_GOB_MODE_TRAILER,		/* default mode: G bit and GOB trailer */
	IOAM6_GOB_MODE_IMPLIED,		/* namespace-implied mode: payload only */
};

/* Where the GOB of a Pre-allocated Trace Option is, and how long it is. */
struct ioam6_gob_desc {
	enum ioam6_gob_mode mode;

	/* The namespace implies a GOB but the option has no room for it: the
	 * packet does not match the local configuration. mode is NONE.
	 */
	bool mismatch;

	struct ioam6_trace_gob_hdr *trailer;	/* MODE_TRAILER only */
	u8 *payload;				/* first octet of the payload */
	u32 plen;				/* payload length, in octets */
	u32 len;				/* octets taken at the option tail */
};

/**
 * ioam6_trace_gob_resolve - locate the GOB of a Pre-allocated Trace Option
 * @ns: IOAM namespace of the option, as configured on this node
 * @hdr: IOAM option header
 * @remlen: RemainingLen the option was received (or built) with
 * @desc: result
 *
 * The first step is the namespace, the G bit comes only afterwards:
 *
 *  A) the namespace implies a GOB: the last gob_implied_len octets of the
 *     option are the GOB payload and there is no trailer. Size and schema
 *     come from the namespace; the G bit is not looked at.
 *  B) the namespace says nothing about the GOB: the G bit tells whether the
 *     last 4-octet word of the option is a GOB trailer, which carries the
 *     payload length and the Schema ID (default mode). G unset: no GOB.
 *
 * In both cases the GOB must fit in the octets left at the tail of the
 * option, beyond the RemainingLen window.
 *
 * The caller guarantees that the whole option is readable and that opt_len
 * covers the trace header.
 *
 * Return: 0 with @desc filled, or -EINVAL when the option is inconsistent
 * with itself (node data space or trailer-based GOB out of the option). An
 * implied GOB that does not fit is not an error of the packet: 0 is returned
 * with @desc->mode set to NONE and @desc->mismatch set.
 */
static inline int
ioam6_trace_gob_resolve(const struct ioam6_namespace *ns,
			struct ioam6_hdr *hdr, u8 remlen,
			struct ioam6_gob_desc *desc)
{
	struct ioam6_trace_hdr *trace = ioam6_opt_to_trace(hdr);
	u8 *opt_end = (u8 *)hdr + 2 + hdr->opt_len;
	struct ioam6_trace_gob_hdr *gob;
	u32 used, room, implied, plen;

	memset(desc, 0, sizeof(*desc));

	/* opt_len counts the bytes after opt_type and opt_len (2B) */
	used = 2 + sizeof(*trace) + remlen * 4;
	if (hdr->opt_len < used)
		return -EINVAL;

	room = hdr->opt_len - used;

	implied = ioam6_ns_gob_implied_len(ns);
	if (implied) {
		if (implied > room) {
			desc->mismatch = true;
			return 0;
		}

		desc->mode = IOAM6_GOB_MODE_IMPLIED;
		desc->payload = opt_end - implied;
		desc->plen = implied;
		desc->len = implied;
		return 0;
	}

	if (!ioam6_trace_gob_enabled(trace))
		return 0;

	if (room < sizeof(*gob))
		return -EINVAL;

	/* the GOB trailer is the last 4-byte word of the option */
	gob = (struct ioam6_trace_gob_hdr *)(opt_end - sizeof(*gob));
	plen = ioam6_trace_gob_plen(gob);
	if (sizeof(*gob) + plen > room)
		return -EINVAL;

	desc->mode = IOAM6_GOB_MODE_TRAILER;
	desc->trailer = gob;
	desc->payload = (u8 *)gob - plen;
	desc->plen = plen;
	desc->len = sizeof(*gob) + plen;
	return 0;
}

struct ioam6_namespace *ioam6_namespace(struct net *net, __be16 id);
int ioam6_fill_trace_data(struct sk_buff *skb,
			  struct ioam6_namespace *ns,
			  struct ioam6_trace_hdr *trace,
			  bool is_input);

int ioam6_init(void);
void ioam6_exit(void);

int ioam6_iptunnel_init(void);
void ioam6_iptunnel_exit(void);

void ioam6_event(enum ioam6_event_type type, struct net *net, gfp_t gfp,
		 void *opt, unsigned int opt_len, unsigned int gob_len);

#endif /* _NET_IOAM6_H */
