// SPDX-License-Identifier: GPL-2.0+
/*
 *  IPv6 IOAM implementation
 *
 *  Author:
 *  Justin Iurman <justin.iurman@uliege.be>
 */

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/ioam6.h>
#include <linux/ioam6_genl.h>
#include <linux/rhashtable.h>
#include <linux/netdevice.h>

#include <net/addrconf.h>
#include <net/genetlink.h>
#include <net/ioam6.h>
#include <net/sch_generic.h>

#ifdef CONFIG_IPV6_IOAM6_GOB
#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#endif


static struct genl_family ioam6_genl_family;

#ifdef CONFIG_IPV6_IOAM6_GOB
static int ptroff_by_skb_data(struct sk_buff *skb, void *ptr)
{
	int off = ptr - (void *)skb->data;

	WARN_ON_ONCE(off < 0);
	return off;
}

static bool
ioam6_range_is_linear(struct sk_buff *skb, void *ptr, int len)
{
	/* true if [ptr, ptr + len) is in the linear skb data */
	return skb_pointer_if_linear(skb, ptroff_by_skb_data(skb, ptr), len);
}

static void ioam6_gob_sc_free_callback_rcu(struct rcu_head *head)
{
	struct ioam6_gob_schema *gobsc;

	gobsc = container_of(head, struct ioam6_gob_schema, rcu);
	kfree(gobsc->bpf.name);
	if (gobsc->bpf.prog)
		bpf_prog_put(gobsc->bpf.prog);

	kfree(gobsc);
}

static void ioam6_gob_sc_release(struct ioam6_gob_schema *gobsc)
{
	call_rcu(&gobsc->rcu, ioam6_gob_sc_free_callback_rcu);
}

static void ioam6_free_gob_sc(void *ptr, void *arg)
{
	struct ioam6_gob_schema *gobsc = (struct ioam6_gob_schema *)ptr;

	if (gobsc)
		ioam6_gob_sc_release(gobsc);
}

static int ioam6_gob_sc_cmpfn(struct rhashtable_compare_arg *arg,
			      const void *obj)
{
	const struct ioam6_gob_schema *gobsc = obj;

	return (gobsc->id != *(u32 *)arg->key);
}

static const struct rhashtable_params rht_gob_sc_params = {
	.key_len		= sizeof(u32),
	.key_offset		= offsetof(struct ioam6_gob_schema, id),
	.head_offset		= offsetof(struct ioam6_gob_schema, head),
	.automatic_shrinking	= true,
	.obj_cmpfn		= ioam6_gob_sc_cmpfn,
};

static const struct nla_policy ioam6_genl_policy_add_gobsc[] = {
	[IOAM6_ATTR_GOB_SC_ID]	= { .type = NLA_U32 },
	[IOAM6_ATTR_GOB_SC_BPF]	= { .type = NLA_NESTED },
};

#define MAX_PROG_NAME 256
static const struct nla_policy
ioam_gob_bpf_prog_policy[IOAM6_TRACE_GOB_BPF_PROG_MAX + 1] = {
	[IOAM6_TRACE_GOB_BPF_PROG]	= { .type = NLA_U32, },
	[IOAM6_TRACE_GOB_BPF_PROG_NAME]	= { .type = NLA_NUL_STRING,
					    .len = MAX_PROG_NAME },
};

static const struct nla_policy ioam6_genl_policy_del_gobsc[] = {
	[IOAM6_ATTR_GOB_SC_ID]	= { .type = NLA_U32 },
};

static const struct nla_policy ioam6_genl_policy_ns_gob_sc[] = {
	[IOAM6_ATTR_NS_ID]	= { .type = NLA_U16 },
	[IOAM6_ATTR_GOB_SC_ID]	= { .type = NLA_U32 },
	[IOAM6_ATTR_GOB_SC_NONE] = { .type = NLA_FLAG },
	[IOAM6_ATTR_GOB_IMPLIED_LEN] =
		NLA_POLICY_MAX(NLA_U8, IOAM6_TRACE_GOB_DATA_SIZE_MAX),
};

static void ioam6_genl_delns_gob_cleanup(struct ioam6_pernet_data *nsdata,
					 struct ioam6_namespace *ns)
{
	struct ioam6_gob_schema *gobsc;

	gobsc = rcu_dereference_protected(ns->gob_schema,
					  lockdep_is_held(&nsdata->lock));
	if (gobsc)
		rcu_assign_pointer(gobsc->ns, NULL);
}

static int
__ioam6_genl_dumpns_element_gob_rcu(struct ioam6_namespace *ns,
				    struct sk_buff *skb)
{
	struct ioam6_gob_schema *gobsc = rcu_dereference(ns->gob_schema);
	u8 implied = ioam6_ns_gob_implied_len(ns);

	if (gobsc && nla_put_u32(skb, IOAM6_ATTR_GOB_SC_ID, gobsc->id))
		return -EMSGSIZE;

	if (implied && nla_put_u8(skb, IOAM6_ATTR_GOB_IMPLIED_LEN, implied))
		return -EMSGSIZE;

	return 0;
}

static int __ioam6_genl_dump_gobsc_element(struct ioam6_gob_schema *gobsc,
					   u32 portid, u32 seq, u32 flags,
					   struct sk_buff *skb, u8 cmd)
{
	struct ioam6_namespace *ns;
	struct nlattr *nest;
	void *hdr;

	hdr = genlmsg_put(skb, portid, seq, &ioam6_genl_family, flags, cmd);
	if (!hdr)
		return -ENOMEM;

	if (nla_put_u32(skb, IOAM6_ATTR_GOB_SC_ID, gobsc->id))
		goto nla_put_failure;

	nest = nla_nest_start_noflag(skb, IOAM6_ATTR_GOB_SC_BPF);
	if (!nest)
		goto nla_put_failure;

	if (nla_put_u32(skb, IOAM6_TRACE_GOB_BPF_PROG,
			gobsc->bpf.prog->aux->id))
		goto nla_put_failure;

	if (gobsc->bpf.name &&
	    nla_put_string(skb, IOAM6_TRACE_GOB_BPF_PROG_NAME, gobsc->bpf.name))
		goto nla_put_failure;

	nla_nest_end(skb, nest);

	rcu_read_lock();

	ns = rcu_dereference(gobsc->ns);
	if (ns && nla_put_u16(skb, IOAM6_ATTR_NS_ID, be16_to_cpu(ns->id))) {
		rcu_read_unlock();
		goto nla_put_failure;
	}

	rcu_read_unlock();

	genlmsg_end(skb, hdr);
	return 0;

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -EMSGSIZE;
}

static int ioam6_genl_dump_gobsc_start(struct netlink_callback *cb)
{
	struct ioam6_pernet_data *nsdata = ioam6_pernet(sock_net(cb->skb->sk));
	struct rhashtable_iter *iter = (struct rhashtable_iter *)cb->args[0];

	if (!iter) {
		iter = kmalloc(sizeof(*iter), GFP_KERNEL);
		if (!iter)
			return -ENOMEM;

		cb->args[0] = (long)iter;
	}

	rhashtable_walk_enter(&nsdata->gob_schemas, iter);

	return 0;
}

#define ioam6_genl_dump_gobsc_done ioam6_genl_dumpsc_done

static int
ioam6_genl_dump_gobsc(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct ioam6_gob_schema *gobsc;
	struct rhashtable_iter *iter;
	int err;

	iter = (struct rhashtable_iter *)cb->args[0];
	rhashtable_walk_start(iter);

	for (;;) {
		gobsc = rhashtable_walk_next(iter);

		if (IS_ERR(gobsc)) {
			if (PTR_ERR(gobsc) == -EAGAIN)
				continue;
			err = PTR_ERR(gobsc);
			goto done;
		} else if (!gobsc) {
			break;
		}

		err = __ioam6_genl_dump_gobsc_element(gobsc,
						      NETLINK_CB(cb->skb).portid,
						      cb->nlh->nlmsg_seq,
						      NLM_F_MULTI,
						      skb,
						      IOAM6_CMD_DUMP_GOB_SCHEMAS);
		if (err)
			goto done;
	}

	err = skb->len;

done:
	rhashtable_walk_stop(iter);
	return err;
}

static int ioam6_genl_add_gobsc(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *tb[IOAM6_TRACE_GOB_BPF_PROG_MAX + 1];
	struct ioam6_pernet_data *nsdata;
	struct ioam6_gob_schema *gobsc;
	struct bpf_prog *p;
	u32 id, fd;
	int err;

	if (!info->attrs[IOAM6_ATTR_GOB_SC_ID] ||
	    !info->attrs[IOAM6_ATTR_GOB_SC_BPF])
		return -EINVAL;

	id = nla_get_u32(info->attrs[IOAM6_ATTR_GOB_SC_ID]);

	err = nla_parse_nested_deprecated(tb, IOAM6_TRACE_GOB_BPF_PROG_MAX,
					  info->attrs[IOAM6_ATTR_GOB_SC_BPF],
					  ioam_gob_bpf_prog_policy, NULL);
	if (err < 0)
		return err;

	if (!tb[IOAM6_TRACE_GOB_BPF_PROG] || !tb[IOAM6_TRACE_GOB_BPF_PROG_NAME])
		return -EINVAL;

	nsdata = ioam6_pernet(genl_info_net(info));

	mutex_lock(&nsdata->lock);

	gobsc = rhashtable_lookup_fast(&nsdata->gob_schemas, &id,
				       rht_gob_sc_params);
	if (gobsc) {
		err = -EEXIST;
		goto out_unlock;
	}

	gobsc = kzalloc(sizeof(*gobsc), GFP_KERNEL);
	if (!gobsc) {
		err = -ENOMEM;
		goto out_unlock;
	}

	gobsc->id = id;
	gobsc->bpf.name = nla_memdup(tb[IOAM6_TRACE_GOB_BPF_PROG_NAME],
				     GFP_KERNEL);
	if (!gobsc->bpf.name) {
		err = -ENOMEM;
		goto free_sc;
	}

	fd = nla_get_u32(tb[IOAM6_TRACE_GOB_BPF_PROG]);

	p = bpf_prog_get_type(fd, BPF_PROG_TYPE_IOAM6_GOB);
	if (IS_ERR(p)) {
		err = PTR_ERR(p);
		goto free_bpf_name;
	}

	gobsc->bpf.prog = p;

	err = rhashtable_lookup_insert_fast(&nsdata->gob_schemas, &gobsc->head,
					    rht_gob_sc_params);
	if (err)
		goto free_bpf_prog;

out_unlock:
	mutex_unlock(&nsdata->lock);
	return err;
free_bpf_prog:
	bpf_prog_put(gobsc->bpf.prog);
free_bpf_name:
	kfree(gobsc->bpf.name);
free_sc:
	kfree(gobsc);
	goto out_unlock;
}

static int ioam6_genl_del_gobsc(struct sk_buff *skb, struct genl_info *info)
{
	struct ioam6_pernet_data *nsdata;
	struct ioam6_gob_schema *gobsc;
	struct ioam6_namespace *ns;
	int err;
	u32 id;

	if (!info->attrs[IOAM6_ATTR_GOB_SC_ID])
		return -EINVAL;

	id = nla_get_u32(info->attrs[IOAM6_ATTR_GOB_SC_ID]);
	nsdata = ioam6_pernet(genl_info_net(info));

	mutex_lock(&nsdata->lock);

	gobsc = rhashtable_lookup_fast(&nsdata->gob_schemas, &id,
				       rht_gob_sc_params);
	if (!gobsc) {
		err = -ENOENT;
		goto out_unlock;
	}

	err = rhashtable_remove_fast(&nsdata->gob_schemas, &gobsc->head,
				     rht_gob_sc_params);
	if (err)
		goto out_unlock;

	ns = rcu_dereference_protected(gobsc->ns,
				       lockdep_is_held(&nsdata->lock));
	if (ns)
		rcu_assign_pointer(ns->gob_schema, NULL);

	ioam6_gob_sc_release(gobsc);

out_unlock:
	mutex_unlock(&nsdata->lock);
	return err;
}

static const struct rhashtable_params rht_ns_params;

static int
ioam6_genl_ns_set_gob_schema(struct sk_buff *skb, struct genl_info *info)
{
	struct ioam6_gob_schema *gobsc, *gobsc_ref;
	struct ioam6_namespace *ns, *ns_ref;
	struct ioam6_pernet_data *nsdata;
	__be16 ns_id;
	u32 gobsc_id;
	u8 implied;
	int err;

	if (!info->attrs[IOAM6_ATTR_NS_ID] ||
	    (!info->attrs[IOAM6_ATTR_GOB_SC_ID] &&
	     !info->attrs[IOAM6_ATTR_GOB_SC_NONE]))
		return -EINVAL;

	/* Namespace-implied GOB: the size of the GOB payload is bound to the
	 * namespace together with the schema, so that the two are applied
	 * under the same lock. Without the attribute the namespace is in the
	 * default (trailer-based) mode.
	 */
	implied = nla_get_u8_default(info->attrs[IOAM6_ATTR_GOB_IMPLIED_LEN],
				     0);
	if (implied % 4)
		return -EINVAL;

	ns_id = cpu_to_be16(nla_get_u16(info->attrs[IOAM6_ATTR_NS_ID]));
	nsdata = ioam6_pernet(genl_info_net(info));

	mutex_lock(&nsdata->lock);

	ns = rhashtable_lookup_fast(&nsdata->namespaces, &ns_id, rht_ns_params);
	if (!ns) {
		err = -ENOENT;
		goto out_unlock;
	}

	if (info->attrs[IOAM6_ATTR_GOB_SC_NONE]) {
		gobsc = NULL;
	} else {
		gobsc_id = nla_get_u32(info->attrs[IOAM6_ATTR_GOB_SC_ID]);
		gobsc = rhashtable_lookup_fast(&nsdata->gob_schemas, &gobsc_id,
					       rht_gob_sc_params);
		if (!gobsc) {
			err = -ENOENT;
			goto out_unlock;
		}
	}

	gobsc_ref = rcu_dereference_protected(ns->gob_schema,
					      lockdep_is_held(&nsdata->lock));
	if (gobsc_ref)
		rcu_assign_pointer(gobsc_ref->ns, NULL);
	rcu_assign_pointer(ns->gob_schema, gobsc);

	if (gobsc) {
		ns_ref = rcu_dereference_protected(gobsc->ns,
						   lockdep_is_held(&nsdata->lock));
		if (ns_ref)
			rcu_assign_pointer(ns_ref->gob_schema, NULL);
		rcu_assign_pointer(gobsc->ns, ns);
	}

	WRITE_ONCE(ns->gob_implied_len, implied);

	err = 0;

out_unlock:
	mutex_unlock(&nsdata->lock);
	return err;
}

static int
ioam6_gob_run_prog(struct sk_buff *skb, const struct ioam6_gob_desc *gob,
		   u32 gob_schema, struct bpf_prog *prog)
{
	struct bpf_ioam6_trace_gob_ctx ctx;
	int ret, err = 0;

	/* initialize the bpf prog context. Only the GOB payload is exposed:
	 * in the tail layout it precedes the GOB trailer, when there is one
	 * (default mode); in the namespace-implied mode it is the whole GOB.
	 *
	 *   +--------------------+------------------+
	 *   | GOB payload (plen) | GOB trailer (4B) |   default mode
	 *   +--------------------+------------------+
	 *   | GOB payload (plen) |                      namespace-implied mode
	 *   +--------------------+
	 *   ^
	 *   payload
	 */
	memset(&ctx, 0, sizeof(ctx));
	ctx.len = gob->plen;
	ctx.schema = gob_schema;
	ctx.data = gob->payload;
	ctx.data_end = ctx.data + gob->plen;
	ctx.skb = skb;

	/* XXX: compute the linear packet data range is not needed anymore.
	 * We are not accessing the ctx->skb data directly but only using
	 * dynptrs which don't require the cb->data_end/meta_data_end to be
	 * set; in other words, the bpf_compute_data_pointers() et simila are
	 * not required and this avoids to mangle/alter the skb's CB.
	 */

	/* Note that a IOAM6_GOB eBPF program cannot change the size of the
	 * packet, and the ioam6 code already checked if the whole HBH was
	 * writable or not. So in theory, we don't expect to clone or expand
	 * the packet again, and thus change the skb pointers.
	 * Moreover, this eBPF program does not allow to use helpers who mangle
	 * the packet in a way that pointers to the skb must be invalidated.
	 */
	ret = bpf_prog_run_pin_on_cpu(prog, &ctx);
	switch (ret) {
	case BPF_OK:
		break;
	case BPF_DROP:
		err = -EINVAL;
		break;
	default:
		pr_warn_once("bpf-ioam6-gob: Illegal return value %d\n", ret);
		err = -EFAULT;
		break;
	}

	return err;
}

static bool ioam6_gob_schema_id_eq(u32 schema_a, u32 schema_b)
{
	return schema_a == schema_b;
}

/* called with rcu_read_lock(). @remlen is the RemainingLen the option was
 * received (or built) with, i.e. before this node recorded its node data.
 */
static int
__ioam6_fill_gob_trace_data(struct sk_buff *skb, struct ioam6_namespace *ns,
			    struct ioam6_trace_hdr *trace, u8 remlen)
{
	struct ioam6_hdr *hdr = ioam6_trace_to_opt(trace);
	struct ioam6_gob_schema *gobsc;
	struct ioam6_gob_desc gob;
	u32 schema_id;

	/* fast path: neither an implied GOB nor a trailer-based one */
	if (!ioam6_ns_gob_implied_len(ns) && !ioam6_trace_gob_enabled(trace))
		return 0;

	/* the IOAM has been check if is writable, e.g., is cloned if
	 * needed or expanded as well, see@ ipv6_hop_ioam().
	 * Thus, the whole option (GOB included) must be in the linear part of
	 * the skb's data before we read it, fail otherwise.
	 */
	if (unlikely(!ioam6_range_is_linear(skb, hdr, 2 + hdr->opt_len)))
		goto err;

	/* the GOB sits at the tail of the option: the namespace tells whether
	 * it is an implied one (payload only), otherwise the G bit tells
	 * whether there is a trailer-based one.
	 */
	if (unlikely(ioam6_trace_gob_resolve(ns, hdr, remlen, &gob)))
		goto err;

	if (gob.mode == IOAM6_GOB_MODE_NONE) {
		/* The namespace implies a GOB but the option has no room for
		 * it: the packet does not match the local configuration. Do
		 * not touch the GOB, the packet goes on as a plain
		 * Pre-allocated Trace.
		 */
		if (unlikely(gob.mismatch))
			net_dbg_ratelimited("ioam6: no room for the namespace-implied GOB\n");

		return 0;
	}

	gobsc = rcu_dereference(ns->gob_schema);
	if (!gobsc)
		/* no GOB schema ID associated with this configuration; thus,
		 * early return since we don't have any eBPF program to be run.
		 */
		return 0;

	if (gob.mode == IOAM6_GOB_MODE_TRAILER) {
		/* GOB Schema is available, let's retrieve the GOB Schema ID
		 * associated with this namespace and compare it with the
		 * Schema ID carried by the GOB trailer.
		 */
		schema_id = ioam6_trace_gob_schema(gob.trailer);
		if (!ioam6_gob_schema_id_eq(schema_id, gobsc->id))
			return 0;
	} else {
		/* namespace-implied GOB: no Schema ID on the wire, the schema
		 * is the one bound to the namespace.
		 */
		schema_id = gobsc->id;
	}

	/* check if the GOB region size is within the max limits or not */
	if (unlikely(gob.len > IOAM6_TRACE_GOB_DATA_SIZE_MAX))
		goto err;

	/* The GOB is processed with the Schema ID active on the current node
	 * (due to the binding to the current namespace).
	 */
	return ioam6_gob_run_prog(skb, &gob, schema_id, gobsc->bpf.prog);

err:
	/* received weird and/or malformed packet */
	net_dbg_ratelimited("ioam6: invalid GOB header");
	return -EINVAL;
}

enum bpf_ioam6_gob_op {
	BPF_IOAM6_GOB_OP_UNSPEC		= 0,
	BPF_IOAM6_GOB_OP_READ,
	BPF_IOAM6_GOB_OP_WRITE,
};

static int
__bpf_ioam6_gob_common(struct bpf_ioam6_trace_gob_ctx *ctx, u32 offset,
		       void *usrptr, u32 usrlen, enum bpf_ioam6_gob_op op)
{
	const u32 plen = ctx->len;
	void *target;

	/* offset is relative to the GOB payload and ctx->len is the payload
	 * length. The GOB trailer, if any, is not addressable here and is
	 * never writable. The payload is in the linear skb data part, already
	 * cloned/expanded if needed.
	 */
	if (offset + usrlen > plen)
		/* out of bounds */
		return -EFAULT;

	target = (u8 *)ctx->data + offset;

	switch (op) {
	case BPF_IOAM6_GOB_OP_WRITE:
		memcpy(target, usrptr, usrlen);
		return 0;
	case BPF_IOAM6_GOB_OP_READ:
		memcpy(usrptr, target, usrlen);
		return 0;
	case BPF_IOAM6_GOB_OP_UNSPEC:
		/* fallthrough */
	default:
		WARN_ON_ONCE(1);
		return -EINVAL;
	}
}

__bpf_kfunc_start_defs();

__bpf_kfunc int
bpf_ioam6_trace_gob_store_bytes(struct bpf_ioam6_trace_gob_ctx *ctx,
				u32 offset, const void *from, u32 from__sz)
{
	return __bpf_ioam6_gob_common(ctx, offset, (void *)from, from__sz,
				      BPF_IOAM6_GOB_OP_WRITE);
}

__bpf_kfunc int
bpf_ioam6_trace_gob_load_bytes(struct bpf_ioam6_trace_gob_ctx *ctx,
			       u32 offset, void *to, u32 to__sz)
{
	return __bpf_ioam6_gob_common(ctx, offset, to, to__sz,
				      BPF_IOAM6_GOB_OP_READ);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(ioam6_kfunc_fset)
BTF_ID_FLAGS(func, bpf_ioam6_trace_gob_store_bytes)
BTF_ID_FLAGS(func, bpf_ioam6_trace_gob_load_bytes);
BTF_KFUNCS_END(ioam6_kfunc_fset)

static const struct btf_kfunc_id_set ioam6_bpf_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &ioam6_kfunc_fset,
};
#endif /* CONFIG_IPV6_IOAM6_GOB */

static void ioam6_ns_release(struct ioam6_namespace *ns)
{
	kfree_rcu(ns, rcu);
}

static void ioam6_sc_release(struct ioam6_schema *sc)
{
	kfree_rcu(sc, rcu);
}

static void ioam6_free_ns(void *ptr, void *arg)
{
	struct ioam6_namespace *ns = (struct ioam6_namespace *)ptr;

	if (ns)
		ioam6_ns_release(ns);
}

static void ioam6_free_sc(void *ptr, void *arg)
{
	struct ioam6_schema *sc = (struct ioam6_schema *)ptr;

	if (sc)
		ioam6_sc_release(sc);
}

static int ioam6_ns_cmpfn(struct rhashtable_compare_arg *arg, const void *obj)
{
	const struct ioam6_namespace *ns = obj;

	return (ns->id != *(__be16 *)arg->key);
}

static int ioam6_sc_cmpfn(struct rhashtable_compare_arg *arg, const void *obj)
{
	const struct ioam6_schema *sc = obj;

	return (sc->id != *(u32 *)arg->key);
}

static const struct rhashtable_params rht_ns_params = {
	.key_len		= sizeof(__be16),
	.key_offset		= offsetof(struct ioam6_namespace, id),
	.head_offset		= offsetof(struct ioam6_namespace, head),
	.automatic_shrinking	= true,
	.obj_cmpfn		= ioam6_ns_cmpfn,
};

static const struct rhashtable_params rht_sc_params = {
	.key_len		= sizeof(u32),
	.key_offset		= offsetof(struct ioam6_schema, id),
	.head_offset		= offsetof(struct ioam6_schema, head),
	.automatic_shrinking	= true,
	.obj_cmpfn		= ioam6_sc_cmpfn,
};

static const struct nla_policy ioam6_genl_policy_addns[] = {
	[IOAM6_ATTR_NS_ID]	= { .type = NLA_U16 },
	[IOAM6_ATTR_NS_DATA]	= { .type = NLA_U32 },
	[IOAM6_ATTR_NS_DATA_WIDE] = { .type = NLA_U64 },
};

static const struct nla_policy ioam6_genl_policy_delns[] = {
	[IOAM6_ATTR_NS_ID]	= { .type = NLA_U16 },
};

static const struct nla_policy ioam6_genl_policy_addsc[] = {
	[IOAM6_ATTR_SC_ID]	= { .type = NLA_U32 },
	[IOAM6_ATTR_SC_DATA]	= { .type = NLA_BINARY,
				    .len = IOAM6_MAX_SCHEMA_DATA_LEN },
};

static const struct nla_policy ioam6_genl_policy_delsc[] = {
	[IOAM6_ATTR_SC_ID]	= { .type = NLA_U32 },
};

static const struct nla_policy ioam6_genl_policy_ns_sc[] = {
	[IOAM6_ATTR_NS_ID]	= { .type = NLA_U16 },
	[IOAM6_ATTR_SC_ID]	= { .type = NLA_U32 },
	[IOAM6_ATTR_SC_NONE]	= { .type = NLA_FLAG },
};

static int ioam6_genl_addns(struct sk_buff *skb, struct genl_info *info)
{
	struct ioam6_pernet_data *nsdata;
	struct ioam6_namespace *ns;
	u64 data64;
	u32 data32;
	__be16 id;
	int err;

	if (!info->attrs[IOAM6_ATTR_NS_ID])
		return -EINVAL;

	id = cpu_to_be16(nla_get_u16(info->attrs[IOAM6_ATTR_NS_ID]));
	nsdata = ioam6_pernet(genl_info_net(info));

	mutex_lock(&nsdata->lock);

	ns = rhashtable_lookup_fast(&nsdata->namespaces, &id, rht_ns_params);
	if (ns) {
		err = -EEXIST;
		goto out_unlock;
	}

	ns = kzalloc(sizeof(*ns), GFP_KERNEL);
	if (!ns) {
		err = -ENOMEM;
		goto out_unlock;
	}

	ns->id = id;

	data32 = nla_get_u32_default(info->attrs[IOAM6_ATTR_NS_DATA],
				     IOAM6_U32_UNAVAILABLE);

	data64 = nla_get_u64_default(info->attrs[IOAM6_ATTR_NS_DATA_WIDE],
				     IOAM6_U64_UNAVAILABLE);

	ns->data = cpu_to_be32(data32);
	ns->data_wide = cpu_to_be64(data64);

	err = rhashtable_lookup_insert_fast(&nsdata->namespaces, &ns->head,
					    rht_ns_params);
	if (err)
		kfree(ns);

out_unlock:
	mutex_unlock(&nsdata->lock);
	return err;
}

static int ioam6_genl_delns(struct sk_buff *skb, struct genl_info *info)
{
	struct ioam6_pernet_data *nsdata;
	struct ioam6_namespace *ns;
	struct ioam6_schema *sc;
	__be16 id;
	int err;

	if (!info->attrs[IOAM6_ATTR_NS_ID])
		return -EINVAL;

	id = cpu_to_be16(nla_get_u16(info->attrs[IOAM6_ATTR_NS_ID]));
	nsdata = ioam6_pernet(genl_info_net(info));

	mutex_lock(&nsdata->lock);

	ns = rhashtable_lookup_fast(&nsdata->namespaces, &id, rht_ns_params);
	if (!ns) {
		err = -ENOENT;
		goto out_unlock;
	}

	sc = rcu_dereference_protected(ns->schema,
				       lockdep_is_held(&nsdata->lock));

	err = rhashtable_remove_fast(&nsdata->namespaces, &ns->head,
				     rht_ns_params);
	if (err)
		goto out_unlock;

	if (sc)
		rcu_assign_pointer(sc->ns, NULL);
#ifdef CONFIG_IPV6_IOAM6_GOB
	ioam6_genl_delns_gob_cleanup(nsdata, ns);
#endif

	ioam6_ns_release(ns);

out_unlock:
	mutex_unlock(&nsdata->lock);
	return err;
}

static int __ioam6_genl_dumpns_element(struct ioam6_namespace *ns,
				       u32 portid,
				       u32 seq,
				       u32 flags,
				       struct sk_buff *skb,
				       u8 cmd)
{
	struct ioam6_schema *sc;
	u64 data64;
	u32 data32;
	void *hdr;

	hdr = genlmsg_put(skb, portid, seq, &ioam6_genl_family, flags, cmd);
	if (!hdr)
		return -ENOMEM;

	data32 = be32_to_cpu(ns->data);
	data64 = be64_to_cpu(ns->data_wide);

	if (nla_put_u16(skb, IOAM6_ATTR_NS_ID, be16_to_cpu(ns->id)) ||
	    (data32 != IOAM6_U32_UNAVAILABLE &&
	     nla_put_u32(skb, IOAM6_ATTR_NS_DATA, data32)) ||
	    (data64 != IOAM6_U64_UNAVAILABLE &&
	     nla_put_u64_64bit(skb, IOAM6_ATTR_NS_DATA_WIDE,
			       data64, IOAM6_ATTR_PAD)))
		goto nla_put_failure;

	rcu_read_lock();

	sc = rcu_dereference(ns->schema);
	if (sc && nla_put_u32(skb, IOAM6_ATTR_SC_ID, sc->id))
		goto unlock_and_fail;

#ifdef CONFIG_IPV6_IOAM6_GOB
	if (__ioam6_genl_dumpns_element_gob_rcu(ns, skb))
		goto unlock_and_fail;
#endif
	rcu_read_unlock();

	genlmsg_end(skb, hdr);
	return 0;

unlock_and_fail:
	rcu_read_unlock();
nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -EMSGSIZE;
}

static int ioam6_genl_dumpns_start(struct netlink_callback *cb)
{
	struct ioam6_pernet_data *nsdata = ioam6_pernet(sock_net(cb->skb->sk));
	struct rhashtable_iter *iter = (struct rhashtable_iter *)cb->args[0];

	if (!iter) {
		iter = kmalloc(sizeof(*iter), GFP_KERNEL);
		if (!iter)
			return -ENOMEM;

		cb->args[0] = (long)iter;
	}

	rhashtable_walk_enter(&nsdata->namespaces, iter);

	return 0;
}

static int ioam6_genl_dumpns_done(struct netlink_callback *cb)
{
	struct rhashtable_iter *iter = (struct rhashtable_iter *)cb->args[0];

	rhashtable_walk_exit(iter);
	kfree(iter);

	return 0;
}

static int ioam6_genl_dumpns(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct rhashtable_iter *iter;
	struct ioam6_namespace *ns;
	int err;

	iter = (struct rhashtable_iter *)cb->args[0];
	rhashtable_walk_start(iter);

	for (;;) {
		ns = rhashtable_walk_next(iter);

		if (IS_ERR(ns)) {
			if (PTR_ERR(ns) == -EAGAIN)
				continue;
			err = PTR_ERR(ns);
			goto done;
		} else if (!ns) {
			break;
		}

		err = __ioam6_genl_dumpns_element(ns,
						  NETLINK_CB(cb->skb).portid,
						  cb->nlh->nlmsg_seq,
						  NLM_F_MULTI,
						  skb,
						  IOAM6_CMD_DUMP_NAMESPACES);
		if (err)
			goto done;
	}

	err = skb->len;

done:
	rhashtable_walk_stop(iter);
	return err;
}

static int ioam6_genl_addsc(struct sk_buff *skb, struct genl_info *info)
{
	struct ioam6_pernet_data *nsdata;
	int len, len_aligned, err;
	struct ioam6_schema *sc;
	u32 id;

	if (!info->attrs[IOAM6_ATTR_SC_ID] || !info->attrs[IOAM6_ATTR_SC_DATA])
		return -EINVAL;

	id = nla_get_u32(info->attrs[IOAM6_ATTR_SC_ID]);
	nsdata = ioam6_pernet(genl_info_net(info));

	mutex_lock(&nsdata->lock);

	sc = rhashtable_lookup_fast(&nsdata->schemas, &id, rht_sc_params);
	if (sc) {
		err = -EEXIST;
		goto out_unlock;
	}

	len = nla_len(info->attrs[IOAM6_ATTR_SC_DATA]);
	len_aligned = ALIGN(len, 4);

	sc = kzalloc(sizeof(*sc) + len_aligned, GFP_KERNEL);
	if (!sc) {
		err = -ENOMEM;
		goto out_unlock;
	}

	sc->id = id;
	sc->len = len_aligned;
	sc->hdr = cpu_to_be32(sc->id | ((u8)(sc->len / 4) << 24));
	nla_memcpy(sc->data, info->attrs[IOAM6_ATTR_SC_DATA], len);

	err = rhashtable_lookup_insert_fast(&nsdata->schemas, &sc->head,
					    rht_sc_params);
	if (err)
		goto free_sc;

out_unlock:
	mutex_unlock(&nsdata->lock);
	return err;
free_sc:
	kfree(sc);
	goto out_unlock;
}

static int ioam6_genl_delsc(struct sk_buff *skb, struct genl_info *info)
{
	struct ioam6_pernet_data *nsdata;
	struct ioam6_namespace *ns;
	struct ioam6_schema *sc;
	int err;
	u32 id;

	if (!info->attrs[IOAM6_ATTR_SC_ID])
		return -EINVAL;

	id = nla_get_u32(info->attrs[IOAM6_ATTR_SC_ID]);
	nsdata = ioam6_pernet(genl_info_net(info));

	mutex_lock(&nsdata->lock);

	sc = rhashtable_lookup_fast(&nsdata->schemas, &id, rht_sc_params);
	if (!sc) {
		err = -ENOENT;
		goto out_unlock;
	}

	ns = rcu_dereference_protected(sc->ns, lockdep_is_held(&nsdata->lock));

	err = rhashtable_remove_fast(&nsdata->schemas, &sc->head,
				     rht_sc_params);
	if (err)
		goto out_unlock;

	if (ns)
		rcu_assign_pointer(ns->schema, NULL);

	ioam6_sc_release(sc);

out_unlock:
	mutex_unlock(&nsdata->lock);
	return err;
}

static int __ioam6_genl_dumpsc_element(struct ioam6_schema *sc,
				       u32 portid, u32 seq, u32 flags,
				       struct sk_buff *skb, u8 cmd)
{
	struct ioam6_namespace *ns;
	void *hdr;

	hdr = genlmsg_put(skb, portid, seq, &ioam6_genl_family, flags, cmd);
	if (!hdr)
		return -ENOMEM;

	if (nla_put_u32(skb, IOAM6_ATTR_SC_ID, sc->id) ||
	    nla_put(skb, IOAM6_ATTR_SC_DATA, sc->len, sc->data))
		goto nla_put_failure;

	rcu_read_lock();

	ns = rcu_dereference(sc->ns);
	if (ns && nla_put_u16(skb, IOAM6_ATTR_NS_ID, be16_to_cpu(ns->id))) {
		rcu_read_unlock();
		goto nla_put_failure;
	}

	rcu_read_unlock();

	genlmsg_end(skb, hdr);
	return 0;

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -EMSGSIZE;
}

static int ioam6_genl_dumpsc_start(struct netlink_callback *cb)
{
	struct ioam6_pernet_data *nsdata = ioam6_pernet(sock_net(cb->skb->sk));
	struct rhashtable_iter *iter = (struct rhashtable_iter *)cb->args[0];

	if (!iter) {
		iter = kmalloc(sizeof(*iter), GFP_KERNEL);
		if (!iter)
			return -ENOMEM;

		cb->args[0] = (long)iter;
	}

	rhashtable_walk_enter(&nsdata->schemas, iter);

	return 0;
}

static int ioam6_genl_dumpsc_done(struct netlink_callback *cb)
{
	struct rhashtable_iter *iter = (struct rhashtable_iter *)cb->args[0];

	rhashtable_walk_exit(iter);
	kfree(iter);

	return 0;
}

static int ioam6_genl_dumpsc(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct rhashtable_iter *iter;
	struct ioam6_schema *sc;
	int err;

	iter = (struct rhashtable_iter *)cb->args[0];
	rhashtable_walk_start(iter);

	for (;;) {
		sc = rhashtable_walk_next(iter);

		if (IS_ERR(sc)) {
			if (PTR_ERR(sc) == -EAGAIN)
				continue;
			err = PTR_ERR(sc);
			goto done;
		} else if (!sc) {
			break;
		}

		err = __ioam6_genl_dumpsc_element(sc,
						  NETLINK_CB(cb->skb).portid,
						  cb->nlh->nlmsg_seq,
						  NLM_F_MULTI,
						  skb,
						  IOAM6_CMD_DUMP_SCHEMAS);
		if (err)
			goto done;
	}

	err = skb->len;

done:
	rhashtable_walk_stop(iter);
	return err;
}

static int ioam6_genl_ns_set_schema(struct sk_buff *skb, struct genl_info *info)
{
	struct ioam6_namespace *ns, *ns_ref;
	struct ioam6_schema *sc, *sc_ref;
	struct ioam6_pernet_data *nsdata;
	__be16 ns_id;
	u32 sc_id;
	int err;

	if (!info->attrs[IOAM6_ATTR_NS_ID] ||
	    (!info->attrs[IOAM6_ATTR_SC_ID] &&
	     !info->attrs[IOAM6_ATTR_SC_NONE]))
		return -EINVAL;

	ns_id = cpu_to_be16(nla_get_u16(info->attrs[IOAM6_ATTR_NS_ID]));
	nsdata = ioam6_pernet(genl_info_net(info));

	mutex_lock(&nsdata->lock);

	ns = rhashtable_lookup_fast(&nsdata->namespaces, &ns_id, rht_ns_params);
	if (!ns) {
		err = -ENOENT;
		goto out_unlock;
	}

	if (info->attrs[IOAM6_ATTR_SC_NONE]) {
		sc = NULL;
	} else {
		sc_id = nla_get_u32(info->attrs[IOAM6_ATTR_SC_ID]);
		sc = rhashtable_lookup_fast(&nsdata->schemas, &sc_id,
					    rht_sc_params);
		if (!sc) {
			err = -ENOENT;
			goto out_unlock;
		}
	}

	sc_ref = rcu_dereference_protected(ns->schema,
					   lockdep_is_held(&nsdata->lock));
	if (sc_ref)
		rcu_assign_pointer(sc_ref->ns, NULL);
	rcu_assign_pointer(ns->schema, sc);

	if (sc) {
		ns_ref = rcu_dereference_protected(sc->ns,
						   lockdep_is_held(&nsdata->lock));
		if (ns_ref)
			rcu_assign_pointer(ns_ref->schema, NULL);
		rcu_assign_pointer(sc->ns, ns);
	}

	err = 0;

out_unlock:
	mutex_unlock(&nsdata->lock);
	return err;
}

static const struct genl_ops ioam6_genl_ops[] = {
	{
		.cmd	= IOAM6_CMD_ADD_NAMESPACE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit	= ioam6_genl_addns,
		.flags	= GENL_ADMIN_PERM,
		.policy	= ioam6_genl_policy_addns,
		.maxattr = ARRAY_SIZE(ioam6_genl_policy_addns) - 1,
	},
	{
		.cmd	= IOAM6_CMD_DEL_NAMESPACE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit	= ioam6_genl_delns,
		.flags	= GENL_ADMIN_PERM,
		.policy	= ioam6_genl_policy_delns,
		.maxattr = ARRAY_SIZE(ioam6_genl_policy_delns) - 1,
	},
	{
		.cmd	= IOAM6_CMD_DUMP_NAMESPACES,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.start	= ioam6_genl_dumpns_start,
		.dumpit	= ioam6_genl_dumpns,
		.done	= ioam6_genl_dumpns_done,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= IOAM6_CMD_ADD_SCHEMA,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit	= ioam6_genl_addsc,
		.flags	= GENL_ADMIN_PERM,
		.policy	= ioam6_genl_policy_addsc,
		.maxattr = ARRAY_SIZE(ioam6_genl_policy_addsc) - 1,
	},
	{
		.cmd	= IOAM6_CMD_DEL_SCHEMA,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit	= ioam6_genl_delsc,
		.flags	= GENL_ADMIN_PERM,
		.policy	= ioam6_genl_policy_delsc,
		.maxattr = ARRAY_SIZE(ioam6_genl_policy_delsc) - 1,
	},
	{
		.cmd	= IOAM6_CMD_DUMP_SCHEMAS,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.start	= ioam6_genl_dumpsc_start,
		.dumpit	= ioam6_genl_dumpsc,
		.done	= ioam6_genl_dumpsc_done,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= IOAM6_CMD_NS_SET_SCHEMA,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit	= ioam6_genl_ns_set_schema,
		.flags	= GENL_ADMIN_PERM,
		.policy	= ioam6_genl_policy_ns_sc,
		.maxattr = ARRAY_SIZE(ioam6_genl_policy_ns_sc) - 1,
	},
#ifdef CONFIG_IPV6_IOAM6_GOB
	{
		.cmd	= IOAM6_CMD_ADD_GOB_SCHEMA,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit	= ioam6_genl_add_gobsc,
		.flags	= GENL_ADMIN_PERM,
		.policy	= ioam6_genl_policy_add_gobsc,
		.maxattr = ARRAY_SIZE(ioam6_genl_policy_add_gobsc) - 1,
	},
	{
		.cmd	= IOAM6_CMD_DEL_GOB_SCHEMA,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit	= ioam6_genl_del_gobsc,
		.flags	= GENL_ADMIN_PERM,
		.policy	= ioam6_genl_policy_del_gobsc,
		.maxattr = ARRAY_SIZE(ioam6_genl_policy_del_gobsc) - 1,
	},
	{
		.cmd	= IOAM6_CMD_NS_SET_GOB_SCHEMA,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit	= ioam6_genl_ns_set_gob_schema,
		.flags	= GENL_ADMIN_PERM,
		.policy	= ioam6_genl_policy_ns_gob_sc,
		.maxattr = ARRAY_SIZE(ioam6_genl_policy_ns_gob_sc) - 1,
	},
	{
		.cmd	= IOAM6_CMD_DUMP_GOB_SCHEMAS,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.start	= ioam6_genl_dump_gobsc_start,
		.dumpit	= ioam6_genl_dump_gobsc,
		.done	= ioam6_genl_dump_gobsc_done,
		.flags	= GENL_ADMIN_PERM,
	},
#endif
};

#define IOAM6_GENL_EV_GRP_OFFSET 0

static const struct genl_multicast_group ioam6_mcgrps[] = {
	[IOAM6_GENL_EV_GRP_OFFSET] = { .name = IOAM6_GENL_EV_GRP_NAME,
				       .flags = GENL_MCAST_CAP_NET_ADMIN },
};

static int ioam6_event_put_trace(struct sk_buff *skb,
				 struct ioam6_trace_hdr *trace,
				 unsigned int len, unsigned int gob_len)
{
	if (nla_put_u16(skb, IOAM6_EVENT_ATTR_TRACE_NAMESPACE,
			be16_to_cpu(trace->namespace_id)) ||
	    nla_put_u8(skb, IOAM6_EVENT_ATTR_TRACE_NODELEN, trace->nodelen) ||
	    nla_put_u32(skb, IOAM6_EVENT_ATTR_TRACE_TYPE,
			be32_to_cpu(trace->type_be32)))
		return 1;

	/* the GOB (trailer-based or namespace-implied) sits at the tail of
	 * the option and is not part of the node data: its length comes from
	 * the caller, who resolved it against the namespace.
	 */
	if (nla_put(skb, IOAM6_EVENT_ATTR_TRACE_DATA,
		    len - sizeof(struct ioam6_trace_hdr) - gob_len -
		    trace->remlen * 4, trace->data + trace->remlen * 4))
		return 1;

	return 0;
}

void ioam6_event(enum ioam6_event_type type, struct net *net, gfp_t gfp,
		 void *opt, unsigned int opt_len, unsigned int gob_len)
{
	struct nlmsghdr *nlh;
	struct sk_buff *skb;

	if (!genl_has_listeners(&ioam6_genl_family, net,
				IOAM6_GENL_EV_GRP_OFFSET))
		return;

	skb = nlmsg_new(NLMSG_DEFAULT_SIZE, gfp);
	if (!skb)
		return;

	nlh = genlmsg_put(skb, 0, 0, &ioam6_genl_family, 0, type);
	if (!nlh)
		goto nla_put_failure;

	switch (type) {
	case IOAM6_EVENT_UNSPEC:
		WARN_ON_ONCE(1);
		break;
	case IOAM6_EVENT_TRACE:
		if (ioam6_event_put_trace(skb, (struct ioam6_trace_hdr *)opt,
					  opt_len, gob_len))
			goto nla_put_failure;
		break;
	}

	genlmsg_end(skb, nlh);
	genlmsg_multicast_netns(&ioam6_genl_family, net, skb, 0,
				IOAM6_GENL_EV_GRP_OFFSET, gfp);
	return;

nla_put_failure:
	nlmsg_free(skb);
}

static struct genl_family ioam6_genl_family __ro_after_init = {
	.name		= IOAM6_GENL_NAME,
	.version	= IOAM6_GENL_VERSION,
	.netnsok	= true,
	.parallel_ops	= true,
	.ops		= ioam6_genl_ops,
	.n_ops		= ARRAY_SIZE(ioam6_genl_ops),
	.resv_start_op	= IOAM6_CMD_MAX + 1,
	.mcgrps		= ioam6_mcgrps,
	.n_mcgrps	= ARRAY_SIZE(ioam6_mcgrps),
	.module		= THIS_MODULE,
};

struct ioam6_namespace *ioam6_namespace(struct net *net, __be16 id)
{
	struct ioam6_pernet_data *nsdata = ioam6_pernet(net);

	return rhashtable_lookup_fast(&nsdata->namespaces, &id, rht_ns_params);
}


static __u8 *ioam6_trace_data_get(struct ioam6_trace_hdr *trace)
{
	/* the node data space is anchored at the start of the trace data,
	 * per RFC 9197. The GOB, when present, sits at the tail of the
	 * option and is never reached by the node data recording.
	 */
	return trace->data;
}

static void __ioam6_fill_trace_data(struct sk_buff *skb,
				    struct ioam6_namespace *ns,
				    struct ioam6_trace_hdr *trace,
				    struct ioam6_schema *sc,
				    u8 sclen, bool is_input)
{
	struct net_device *dev = skb_dst_dev(skb);
	struct timespec64 ts;
	ktime_t tstamp;
	u64 raw64;
	u32 raw32;
	u16 raw16;
	u8 *data;
	u8 byte;

	data = ioam6_trace_data_get(trace) + trace->remlen * 4 -
	       trace->nodelen * 4 - sclen * 4;

	/* hop_lim and node_id */
	if (trace->type.bit0) {
		byte = ipv6_hdr(skb)->hop_limit;
		if (is_input)
			byte--;

		raw32 = dev_net(dev)->ipv6.sysctl.ioam6_id;

		*(__be32 *)data = cpu_to_be32((byte << 24) | raw32);
		data += sizeof(__be32);
	}

	/* ingress_if_id and egress_if_id */
	if (trace->type.bit1) {
		if (!skb->dev)
			raw16 = IOAM6_U16_UNAVAILABLE;
		else
			raw16 = (__force u16)READ_ONCE(__in6_dev_get(skb->dev)->cnf.ioam6_id);

		*(__be16 *)data = cpu_to_be16(raw16);
		data += sizeof(__be16);

		if (dev->flags & IFF_LOOPBACK)
			raw16 = IOAM6_U16_UNAVAILABLE;
		else
			raw16 = (__force u16)READ_ONCE(__in6_dev_get(dev)->cnf.ioam6_id);

		*(__be16 *)data = cpu_to_be16(raw16);
		data += sizeof(__be16);
	}

	/* timestamp seconds */
	if (trace->type.bit2) {
		if (!skb->dev) {
			*(__be32 *)data = cpu_to_be32(IOAM6_U32_UNAVAILABLE);
		} else {
			tstamp = skb_tstamp_cond(skb, true);
			ts = ktime_to_timespec64(tstamp);

			*(__be32 *)data = cpu_to_be32((u32)ts.tv_sec);
		}
		data += sizeof(__be32);
	}

	/* timestamp subseconds */
	if (trace->type.bit3) {
		if (!skb->dev) {
			*(__be32 *)data = cpu_to_be32(IOAM6_U32_UNAVAILABLE);
		} else {
			if (!trace->type.bit2) {
				tstamp = skb_tstamp_cond(skb, true);
				ts = ktime_to_timespec64(tstamp);
			}

			*(__be32 *)data = cpu_to_be32((u32)(ts.tv_nsec / NSEC_PER_USEC));
		}
		data += sizeof(__be32);
	}

	/* transit delay */
	if (trace->type.bit4) {
		*(__be32 *)data = cpu_to_be32(IOAM6_U32_UNAVAILABLE);
		data += sizeof(__be32);
	}

	/* namespace data */
	if (trace->type.bit5) {
		*(__be32 *)data = ns->data;
		data += sizeof(__be32);
	}

	/* queue depth */
	if (trace->type.bit6) {
		struct netdev_queue *queue;
		struct Qdisc *qdisc;
		__u32 qlen, backlog;

		if (dev->flags & IFF_LOOPBACK) {
			*(__be32 *)data = cpu_to_be32(IOAM6_U32_UNAVAILABLE);
		} else {
			queue = skb_get_tx_queue(dev, skb);
			qdisc = rcu_dereference(queue->qdisc);
			qdisc_qstats_qlen_backlog(qdisc, &qlen, &backlog);

			*(__be32 *)data = cpu_to_be32(backlog);
		}
		data += sizeof(__be32);
	}

	/* checksum complement */
	if (trace->type.bit7) {
		*(__be32 *)data = cpu_to_be32(IOAM6_U32_UNAVAILABLE);
		data += sizeof(__be32);
	}

	/* hop_lim and node_id (wide) */
	if (trace->type.bit8) {
		byte = ipv6_hdr(skb)->hop_limit;
		if (is_input)
			byte--;

		raw64 = dev_net(dev)->ipv6.sysctl.ioam6_id_wide;

		*(__be64 *)data = cpu_to_be64(((u64)byte << 56) | raw64);
		data += sizeof(__be64);
	}

	/* ingress_if_id and egress_if_id (wide) */
	if (trace->type.bit9) {
		if (!skb->dev)
			raw32 = IOAM6_U32_UNAVAILABLE;
		else
			raw32 = READ_ONCE(__in6_dev_get(skb->dev)->cnf.ioam6_id_wide);

		*(__be32 *)data = cpu_to_be32(raw32);
		data += sizeof(__be32);

		if (dev->flags & IFF_LOOPBACK)
			raw32 = IOAM6_U32_UNAVAILABLE;
		else
			raw32 = READ_ONCE(__in6_dev_get(dev)->cnf.ioam6_id_wide);

		*(__be32 *)data = cpu_to_be32(raw32);
		data += sizeof(__be32);
	}

	/* namespace data (wide) */
	if (trace->type.bit10) {
		*(__be64 *)data = ns->data_wide;
		data += sizeof(__be64);
	}

	/* buffer occupancy */
	if (trace->type.bit11) {
		*(__be32 *)data = cpu_to_be32(IOAM6_U32_UNAVAILABLE);
		data += sizeof(__be32);
	}

	/* bit12 undefined: filled with empty value */
	if (trace->type.bit12) {
		*(__be32 *)data = cpu_to_be32(IOAM6_U32_UNAVAILABLE);
		data += sizeof(__be32);
	}

	/* bit13 undefined: filled with empty value */
	if (trace->type.bit13) {
		*(__be32 *)data = cpu_to_be32(IOAM6_U32_UNAVAILABLE);
		data += sizeof(__be32);
	}

	/* bit14 undefined: filled with empty value */
	if (trace->type.bit14) {
		*(__be32 *)data = cpu_to_be32(IOAM6_U32_UNAVAILABLE);
		data += sizeof(__be32);
	}

	/* bit15 undefined: filled with empty value */
	if (trace->type.bit15) {
		*(__be32 *)data = cpu_to_be32(IOAM6_U32_UNAVAILABLE);
		data += sizeof(__be32);
	}

	/* bit16 undefined: filled with empty value */
	if (trace->type.bit16) {
		*(__be32 *)data = cpu_to_be32(IOAM6_U32_UNAVAILABLE);
		data += sizeof(__be32);
	}

	/* bit17 undefined: filled with empty value */
	if (trace->type.bit17) {
		*(__be32 *)data = cpu_to_be32(IOAM6_U32_UNAVAILABLE);
		data += sizeof(__be32);
	}

	/* bit18 undefined: filled with empty value */
	if (trace->type.bit18) {
		*(__be32 *)data = cpu_to_be32(IOAM6_U32_UNAVAILABLE);
		data += sizeof(__be32);
	}

	/* bit19 undefined: filled with empty value */
	if (trace->type.bit19) {
		*(__be32 *)data = cpu_to_be32(IOAM6_U32_UNAVAILABLE);
		data += sizeof(__be32);
	}

	/* bit20 undefined: filled with empty value */
	if (trace->type.bit20) {
		*(__be32 *)data = cpu_to_be32(IOAM6_U32_UNAVAILABLE);
		data += sizeof(__be32);
	}

	/* bit21 undefined: filled with empty value */
	if (trace->type.bit21) {
		*(__be32 *)data = cpu_to_be32(IOAM6_U32_UNAVAILABLE);
		data += sizeof(__be32);
	}

	/* opaque state snapshot */
	if (trace->type.bit22) {
		if (!sc) {
			*(__be32 *)data = cpu_to_be32(IOAM6_U32_UNAVAILABLE >> 8);
		} else {
			*(__be32 *)data = sc->hdr;
			data += sizeof(__be32);

			memcpy(data, sc->data, sc->len);
		}
	}
}

/* called with rcu_read_lock() */
int ioam6_fill_trace_data(struct sk_buff *skb,
			  struct ioam6_namespace *ns,
			  struct ioam6_trace_hdr *trace,
			  bool is_input)
{
	/* RemainingLen as received: the GOB is located against this value */
	u8 remlen __maybe_unused = trace->remlen;
	struct ioam6_schema *sc;
	u8 sclen = 0;

	/* Skip if Overflow flag is set
	 */
	if (trace->overflow)
		goto out;

	/* NodeLen does not include Opaque State Snapshot length. We need to
	 * take it into account if the corresponding bit is set (bit 22) and
	 * if the current IOAM namespace has an active schema attached to it
	 */
	sc = rcu_dereference(ns->schema);
	if (trace->type.bit22) {
		sclen = sizeof_field(struct ioam6_schema, hdr) / 4;

		if (sc)
			sclen += sc->len / 4;
	}

	/* If there is no space remaining, we set the Overflow flag and we
	 * skip without filling the trace
	 */
	if (!trace->remlen || trace->remlen < trace->nodelen + sclen) {
		trace->overflow = 1;
		goto out;
	}

	__ioam6_fill_trace_data(skb, ns, trace, sc, sclen, is_input);
	trace->remlen -= trace->nodelen + sclen;

out:
#ifdef CONFIG_IPV6_IOAM6_GOB
	/* a GOB may be there with the G bit unset (namespace-implied mode) */
	return __ioam6_fill_gob_trace_data(skb, ns, trace, remlen);
#else
	return 0;
#endif
}

static int __net_init ioam6_net_init(struct net *net)
{
	struct ioam6_pernet_data *nsdata;
	int err = -ENOMEM;

	nsdata = kzalloc(sizeof(*nsdata), GFP_KERNEL);
	if (!nsdata)
		goto out;

	mutex_init(&nsdata->lock);
	net->ipv6.ioam6_data = nsdata;

	err = rhashtable_init(&nsdata->namespaces, &rht_ns_params);
	if (err)
		goto free_nsdata;

	err = rhashtable_init(&nsdata->schemas, &rht_sc_params);
	if (err)
		goto free_rht_ns;

#ifdef CONFIG_IPV6_IOAM6_GOB
	err = rhashtable_init(&nsdata->gob_schemas, &rht_gob_sc_params);
	if (err) {
		rhashtable_destroy(&nsdata->schemas);
		goto free_rht_ns;
	}
#endif
out:
	return err;
free_rht_ns:
	rhashtable_destroy(&nsdata->namespaces);
free_nsdata:
	kfree(nsdata);
	net->ipv6.ioam6_data = NULL;
	goto out;
}

static void __net_exit ioam6_net_exit(struct net *net)
{
	struct ioam6_pernet_data *nsdata = ioam6_pernet(net);

	rhashtable_free_and_destroy(&nsdata->namespaces, ioam6_free_ns, NULL);
	rhashtable_free_and_destroy(&nsdata->schemas, ioam6_free_sc, NULL);
#ifdef CONFIG_IPV6_IOAM6_GOB
	rhashtable_free_and_destroy(&nsdata->gob_schemas, ioam6_free_gob_sc,
				    NULL);
#endif

	kfree(nsdata);
}

static struct pernet_operations ioam6_net_ops = {
	.init = ioam6_net_init,
	.exit = ioam6_net_exit,
};

int __init ioam6_init(void)
{
	int err = register_pernet_subsys(&ioam6_net_ops);
	if (err)
		goto out;

	err = genl_register_family(&ioam6_genl_family);
	if (err)
		goto out_unregister_pernet_subsys;

#ifdef CONFIG_IPV6_IOAM6_GOB
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_IOAM6_GOB,
					&ioam6_bpf_kfunc_set);
	if (err)
		goto out_unregister_genl;
#endif
#ifdef CONFIG_IPV6_IOAM6_LWTUNNEL
	err = ioam6_iptunnel_init();
	if (err)
		goto out_unregister_genl;
#endif

	pr_info("In-situ OAM (IOAM) with IPv6\n");

out:
	return err;
#if defined(CONFIG_IPV6_IOAM6_LWTUNNEL) || defined(CONFIG_IPV6_IOAM6_GOB)
out_unregister_genl:
        genl_unregister_family(&ioam6_genl_family);
#endif
out_unregister_pernet_subsys:
	unregister_pernet_subsys(&ioam6_net_ops);
	goto out;
}

void ioam6_exit(void)
{
#ifdef CONFIG_IPV6_IOAM6_LWTUNNEL
	ioam6_iptunnel_exit();
#endif
	genl_unregister_family(&ioam6_genl_family);
	unregister_pernet_subsys(&ioam6_net_ops);
}
