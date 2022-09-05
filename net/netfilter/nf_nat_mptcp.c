// SPDX-License-Identifier: GPL-2.0-only
/* MPTCP extension for TCP NAT alteration. */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/inet.h>
#include <linux/tcp.h>
#include <linux/netfilter_ipv4.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_helper.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_mptcp.h>

#define NAT_HELPER_NAME "mptcp"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Menglong Dong <imagedong@tencent.com>");
MODULE_DESCRIPTION("mptcp NAT helper");
MODULE_ALIAS_NF_NAT_HELPER(NAT_HELPER_NAME);

static struct nf_conntrack_nat_helper nat_helper_mptcp =
	NF_CT_NAT_HELPER_INIT(NAT_HELPER_NAME);

static void nf_nat_mptcp(struct nf_conn *ct,
			 struct nf_conntrack_expect *this)
{
	struct nf_conn *master = this->master;
	struct nf_conntrack_tuple *tuple;
	struct nf_nat_range2 range;

	if (!(master->status & IPS_NAT_MASK))
		return;

	tuple = &master->tuplehash[IP_CT_DIR_REPLY].tuple;

	/* This must be a fresh one. */
	WARN_ON(ct->status & IPS_NAT_DONE_MASK);

	/* do only DST nat, as the source IP need to keep still. ( Our
	 * goal is to make the subflow connect to the same server, so
	 * only DNAT seems enough?)
	 * 
	 * Make the dest ip and dest port the same as the master
	 * connection.
	 */
	range.flags = (NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED);
	range.min_proto = range.max_proto = tuple->src.u;
	range.min_addr = range.max_addr = tuple->src.u3;
	nf_nat_setup_info(ct, &range, NF_NAT_MANIP_DST);
}

static int __init nf_nat_mpctp_init(void)
{
	BUG_ON(nf_nat_mptcp_hook != NULL);
	nf_nat_helper_register(&nat_helper_mptcp);
	RCU_INIT_POINTER(nf_nat_mptcp_hook, nf_nat_mptcp);
	return 0;
}

static void __exit nf_nat_mpctp_fini(void)
{
	nf_nat_helper_unregister(&nat_helper_mptcp);
	RCU_INIT_POINTER(nf_nat_mptcp_hook, NULL);
	synchronize_rcu();
}

module_init(nf_nat_mpctp_init);
module_exit(nf_nat_mpctp_fini);
