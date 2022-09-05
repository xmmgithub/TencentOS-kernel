/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Packet network namespace
 */
#ifndef __NETNS_MPTCP_H__
#define __NETNS_MPTCP_H__

#include <linux/rculist.h>
#include <linux/mutex.h>

struct netns_mptcp {
	struct mutex		sklist_lock;
	struct hlist_head	sklist;
};

#endif /* __NETNS_MPTCP_H__ */
