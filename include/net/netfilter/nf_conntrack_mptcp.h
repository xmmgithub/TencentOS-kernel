/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NF_CONNTRACK_MPTCP_H
#define _NF_CONNTRACK_MPTCP_H

#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/types.h>

#include <net/mptcp.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_extend.h>

#include <uapi/linux/netfilter/nf_conntrack_tuple_common.h>

struct nf_ct_mptcp_ext {
	u64	client_key;
	u64	server_key;
	/* this is the token that used by client(subflow) */
	u32	token;
	bool	finished;
};

extern void (*nf_nat_mptcp_hook)(struct nf_conn *ct,
				 struct nf_conntrack_expect *this);

#ifdef CONFIG_NF_CT_PROTO_MPTCP
int nf_ct_mptcp_state(struct sk_buff *skb, unsigned int dataoff,
		      struct nf_conn *ct, unsigned int index);
int __mptcp_token_to_tuple(struct sk_buff *skb, unsigned int dataoff,
			   const struct nf_conntrack_tuple *tuple,
			   struct nf_conntrack_tuple *target);
bool nf_ct_expect_is_mptcp(struct nf_conntrack_expect *exp);
void nf_conntrack_mptcp_init_net(struct net *net);

static inline bool nf_ct_mptcp_enabled(struct net *net)
{
	return mptcp_is_enabled(net);
}

static inline bool nf_ct_is_mptcp(struct nf_conn *ct)
{
	return nf_ct_ext_exist(ct, NF_CT_EXT_MPTCP);
}

static inline struct nf_ct_mptcp_ext
*nf_ct_ext_get_mptcp(struct nf_conn *ct)
{
	return (struct nf_ct_mptcp_ext *)nf_ct_ext_find(ct, NF_CT_EXT_MPTCP);
}

static inline void nf_ct_expect_inc_mptcp(struct nf_conntrack_expect *exp)
{
	if (likely(!nf_ct_expect_is_mptcp(exp)))
		return;
	nf_ct_exp_net(exp)->ct.nf_ct_proto.tcp.mptcp_expect_count++;
}

static inline void nf_ct_expect_dec_mptcp(struct nf_conntrack_expect *exp)
{
	if (likely(!nf_ct_expect_is_mptcp(exp)))
		return;
	nf_ct_exp_net(exp)->ct.nf_ct_proto.tcp.mptcp_expect_count--;
}

static inline int
mptcp_token_to_tuple(struct net *net, struct sk_buff *skb,
		     unsigned int dataoff,
		     const struct nf_conntrack_tuple *tuple,
		     struct nf_conntrack_tuple *target)
{
	struct tcphdr *tcp = (void *)skb->data + dataoff;
	u_int16_t l3num = tuple->src.l3num;

	if (!net->ct.nf_ct_proto.tcp.mptcp_expect_count)
		return -ENOENT;

	if (l3num != NFPROTO_IPV4 && l3num != NFPROTO_IPV6)
		return -ENOENT;

	if (tuple->dst.protonum != IPPROTO_TCP || !tcp->syn || tcp->ack)
		return -ENOENT;

	return __mptcp_token_to_tuple(skb, dataoff, tuple, target);
}

#else
static inline int
nf_ct_mptcp_state(struct sk_buff *skb, unsigned int dataoff,
		  struct nf_conn *ct, unsigned int index)
{
	return 0;
}

static void nf_conntrack_mptcp_init_net(struct net *net) { }

static inline int
mptcp_token_to_tuple(struct net *net, struct sk_buff *skb,
		     unsigned int dataoff,
		     const struct nf_conntrack_tuple *tuple,
		     struct nf_conntrack_tuple *target)
{
	return -ENOENT;
}

static inline bool nf_ct_mptcp_enabled(struct net *net)
{
	return false;
}

static inline bool nf_ct_is_mptcp(struct nf_conn *ct)
{
	return false;
}

static inline struct nf_ct_mptcp_ext
*nf_ct_ext_get_mptcp(struct nf_conn *ct)
{
	return NULL;
}

static inline bool nf_ct_expect_is_mptcp(struct nf_conntrack_expect *exp)
{
	return false;
}

static inline void nf_ct_expect_inc_mptcp(struct nf_conntrack_expect *exp)
{
}

static inline void nf_ct_expect_dec_mptcp(struct nf_conntrack_expect *exp)
{
}

#endif
#endif /* _NF_CONNTRACK_MPTCP_H */
