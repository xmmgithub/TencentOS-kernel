// SPDX-License-Identifier: GPL-2.0
/* Multipath TCP
 *
 * Copyright (c) 2019, Tessares SA.
 */

#include <linux/sysctl.h>
#include <linux/proc_fs.h>

#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include "protocol.h"
#include "ctrl.h"

#define MPTCP_SYSCTL_PATH "net/mptcp"

static int mptcp_pernet_id;
struct mptcp_pernet {
	struct ctl_table_header *ctl_table_hdr;

	int mptcp_enabled;
	int tcp_enabled;
	int dup_addr;
};

static struct mptcp_pernet *mptcp_get_pernet(struct net *net)
{
	return net_generic(net, mptcp_pernet_id);
}

int mptcp_is_enabled(struct net *net)
{
	return mptcp_get_pernet(net)->mptcp_enabled;
}
EXPORT_SYMBOL(mptcp_is_enabled);

static struct ctl_table mptcp_sysctl_table[] = {
	{
		.procname = "enabled",
		.maxlen = sizeof(int),
		.mode = 0644,
		/* users with CAP_NET_ADMIN or root (not and) can change this
		 * value, same as other sysctl or the 'net' tree.
		 */
		.proc_handler = proc_dointvec,
	},
	{
		.procname = "tcp_enabled",
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = proc_dointvec,
	},
	{
		.procname = "dup_addr",
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = proc_dointvec,
	},
	{}
};

int mptcp_tcp_enabled(const struct net *net)
{
	return mptcp_is_enabled(net) && mptcp_get_pernet(net)->tcp_enabled;
}
EXPORT_SYMBOL_GPL(mptcp_tcp_enabled);

int mptcp_dup_addr_enabled(struct net *net)
{
	return mptcp_get_pernet(net)->dup_addr;
}

static void mptcp_pernet_set_defaults(struct mptcp_pernet *pernet)
{
	pernet->mptcp_enabled = 1;
}

static int mptcp_pernet_new_table(struct net *net, struct mptcp_pernet *pernet)
{
	struct ctl_table_header *hdr;
	struct ctl_table *table;

	table = mptcp_sysctl_table;
	if (!net_eq(net, &init_net)) {
		table = kmemdup(table, sizeof(mptcp_sysctl_table), GFP_KERNEL);
		if (!table)
			goto err_alloc;
	}

	table[0].data = &pernet->mptcp_enabled;
	table[1].data = &pernet->tcp_enabled;
	table[2].data = &pernet->dup_addr;

	hdr = register_net_sysctl(net, MPTCP_SYSCTL_PATH, table);
	if (!hdr)
		goto err_reg;

	pernet->ctl_table_hdr = hdr;

	return 0;

err_reg:
	if (!net_eq(net, &init_net))
		kfree(table);
err_alloc:
	return -ENOMEM;
}

static void mptcp_pernet_del_table(struct mptcp_pernet *pernet)
{
	struct ctl_table *table = pernet->ctl_table_hdr->ctl_table_arg;

	unregister_net_sysctl_table(pernet->ctl_table_hdr);

	kfree(table);
}

#ifdef CONFIG_PROC_FS

#define SEQ_AFINFO	\
	((struct mptcp_seq_afinfo *)PDE_DATA(file_inode(seq->file)))->family

static struct sock *mptcp_get_idx(struct seq_file *seq, loff_t pos)
{
	struct net *net = seq_file_net(seq);
	struct mptcp_sock *msk;
	struct sock *sk;

	hlist_for_each_entry_rcu(msk, &net->mptcp.sklist, all_list) {
		sk = (struct sock *)msk;
		if (sk->sk_family != SEQ_AFINFO)
			continue;
		if (!(pos--))
			return sk;
	}
	return NULL;
}

static void *mptcp_seq_start(struct seq_file *seq, loff_t *pos)
	__acquires(RCU)
{
	struct mptcp_iter_state *state = seq->private;

	rcu_read_lock();
	state->num = 0;
	return *pos ? mptcp_get_idx(seq, *pos - 1) : SEQ_START_TOKEN;
}

static void *mptcp_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct mptcp_iter_state *state = seq->private;
	struct sock *sk;

	if (v != SEQ_START_TOKEN) {
		do {
			sk = mptcp_sk_next(v);
		} while (sk && sk->sk_family != SEQ_AFINFO);
		state->num++;
	} else {
		sk = mptcp_get_idx(seq, 0);
	}

	(*pos)++;
	return sk;
}

static void mptcp_seq_stop(struct seq_file *seq, void *v)
	__releases(RCU)
{
	rcu_read_unlock();
}

static inline int mpctp_format_sock(struct seq_file *seq, struct sock *sk)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct mptcp_iter_state *state = seq->private;
	const struct inet_sock *inet = inet_sk(sk);
	struct mptcp_sock *msk = mptcp_sk(sk);
	__u16 destp = ntohs(inet->inet_dport);
	__u16 srcp = ntohs(inet->inet_sport);
	const struct in6_addr *dest6, *src6;
	unsigned long timer_expires;
	__be32 src, dest;
	int timer_active;
	int rx_queue = 0;

	/* retrans timer seems to be the only timer that used */
	if (icsk->icsk_pending == ICSK_TIME_RETRANS) {
		timer_active	= 1;
		timer_expires	= icsk->icsk_timeout;
	} else {
		timer_active	= 0;
		timer_expires = jiffies;
	}

	if (mptcp_is_fully_established(sk))
		rx_queue = msk->ack_seq - msk->copied_seq - 1;

	if (SEQ_AFINFO == AF_INET6)
		goto fmt_ipv6;

	src = inet->inet_rcv_saddr;
	dest = inet->inet_daddr;
	seq_printf(seq, MPTCP_SEQ_CONT,
		state->num, src, srcp, dest, destp, sk->sk_state,
		msk->write_seq - atomic64_read(&msk->snd_una),
		rx_queue,
		timer_active,
		jiffies_delta_to_clock_t(timer_expires - jiffies),
		atomic_read(&msk->subflow_count),
		icsk->icsk_retransmits,
		from_kuid_munged(seq_user_ns(seq), sock_i_uid(sk)),
		sock_i_ino(sk),
		refcount_read(&sk->sk_refcnt), sk);

	return 0;

fmt_ipv6:
	dest6 = &sk->sk_v6_daddr;
	src6 = &sk->sk_v6_rcv_saddr;
	seq_printf(seq, MPTCP6_SEQ_CONT, state->num,
		src6->s6_addr32[0], src6->s6_addr32[1],
		src6->s6_addr32[2], src6->s6_addr32[3], srcp,
		dest6->s6_addr32[0], dest6->s6_addr32[1],
		dest6->s6_addr32[2], dest6->s6_addr32[3], destp,
		sk->sk_state,
		msk->write_seq - atomic64_read(&msk->snd_una),
		rx_queue,
		timer_active,
		jiffies_delta_to_clock_t(timer_expires - jiffies),
		atomic_read(&msk->subflow_count),
		icsk->icsk_retransmits,
		from_kuid_munged(seq_user_ns(seq), sock_i_uid(sk)),
		sock_i_ino(sk),
		refcount_read(&sk->sk_refcnt), sk);
	return 0;
}

static int mptcp_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, SEQ_AFINFO == AF_INET ? MPTCP_SEQ_HEADER :
				MPTCP6_SEQ_HEADER);
		return 0;
	}
	return mpctp_format_sock(seq, v);
}

static const struct seq_operations mptcp_seq_ops = {
	.start	= mptcp_seq_start,
	.next	= mptcp_seq_next,
	.stop	= mptcp_seq_stop,
	.show	= mptcp_seq_show,
};
#endif

struct mptcp_seq_afinfo mptcp_seq_afinfo = {
	.family = AF_INET,
};

struct mptcp_seq_afinfo mptcp6_seq_afinfo = {
	.family = AF_INET6,
};

static int __net_init mptcp_net_init(struct net *net)
{
	struct mptcp_pernet *pernet = mptcp_get_pernet(net);

	mptcp_pernet_set_defaults(pernet);

	mutex_init(&net->mptcp.sklist_lock);
	INIT_HLIST_HEAD(&net->mptcp.sklist);

#ifdef CONFIG_PROC_FS
	if (!proc_create_net_data("mptcp", 0444, net->proc_net,
				  &mptcp_seq_ops,
				  sizeof(struct mptcp_iter_state),
				  &mptcp_seq_afinfo))
		return -ENOMEM;

#ifdef CONFIG_MPTCP_IPV6
	if (!proc_create_net_data("mptcp6", 0444, net->proc_net,
				  &mptcp_seq_ops,
				  sizeof(struct mptcp_iter_state),
				  &mptcp6_seq_afinfo)) {
		remove_proc_entry("mptcp", net->proc_net);
		return -ENOMEM;
	}
#endif
#endif

	return mptcp_pernet_new_table(net, pernet);
}

/* Note: the callback will only be called per extra netns */
static void __net_exit mptcp_net_exit(struct net *net)
{
	struct mptcp_pernet *pernet = mptcp_get_pernet(net);

	remove_proc_entry("mptcp", net->proc_net);
	remove_proc_entry("mptcp6", net->proc_net);
	mptcp_pernet_del_table(pernet);
}

static struct pernet_operations mptcp_pernet_ops = {
	.init = mptcp_net_init,
	.exit = mptcp_net_exit,
	.id = &mptcp_pernet_id,
	.size = sizeof(struct mptcp_pernet),
};

void __init mptcp_init(void)
{
	mptcp_join_cookie_init();
	mptcp_proto_init();

	if (register_pernet_subsys(&mptcp_pernet_ops) < 0)
		panic("Failed to register MPTCP pernet subsystem.\n");
}

#if IS_ENABLED(CONFIG_MPTCP_IPV6)
int __init mptcpv6_init(void)
{
	int err;

	err = mptcp_proto_v6_init();

	return err;
}
#endif
