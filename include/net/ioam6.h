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
	struct ioam6_gob_schema __rcu *gob_schema;

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
	struct rhashtable gob_schemas;
};

struct ioam6_bpf_trace_state {
	local_lock_t bh_lock;
	struct ioam6_trace_hdr *trace;
};

DECLARE_PER_CPU(struct ioam6_bpf_trace_state, ioam6_bpf_trace_states);

static inline struct ioam6_pernet_data *ioam6_pernet(struct net *net)
{
#if IS_ENABLED(CONFIG_IPV6)
	return net->ipv6.ioam6_data;
#else
	return NULL;
#endif
}

bool is_ioam6_trace_gob_present(struct ioam6_trace_hdr *trace);
struct ioam6_trace_gob_hdr *
ioam6_trace_gob_hdr_start(struct ioam6_trace_hdr *trace);
int ioam6_fill_gob_trace_data(struct sk_buff *skb, struct ioam6_namespace *ns,
			      struct ioam6_trace_hdr *trace);

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
