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

/* bpf context for BPF_PROG_TYPE_IOAM6_GOB */
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
		 void *opt, unsigned int opt_len);

#endif /* _NET_IOAM6_H */
