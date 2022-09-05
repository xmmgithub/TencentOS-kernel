#include <linux/module.h>
#include <linux/types.h>
#include <linux/timer.h>
#include <linux/list.h>
#include <linux/seq_file.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>

#include <net/mptcp.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_mptcp.h>

#define HELPER_NAME "mptcp"

void (*nf_nat_mptcp_hook)(struct nf_conn *ct,
			  struct nf_conntrack_expect *this);
EXPORT_SYMBOL_GPL(nf_nat_mptcp_hook);

static const struct nf_conntrack_helper mptcp_helper;

/* 
 * Convert token to tuple. This tuple is used to match the expect,
 * therefore the format of it should be the same as mptcp_setup_expect()
 */
int __mptcp_token_to_tuple(struct sk_buff *skb, unsigned int dataoff,
			   const struct nf_conntrack_tuple *tuple,
			   struct nf_conntrack_tuple *target)
{
	struct tcphdr *tcp = (void *)skb->data + dataoff;
	struct mptcp_options_received options;
	u_int16_t l3num = tuple->src.l3num;

	if (l3num != NFPROTO_IPV4 && l3num != NFPROTO_IPV6)
		goto err;

	if (tuple->dst.protonum != IPPROTO_TCP || !tcp->syn || tcp->ack)
		goto err;

	skb_pull(skb, dataoff);
	mptcp_get_options(skb, &options);
	skb_push(skb, dataoff);
	if (!options.mp_join)
		goto err;

	memset(target, 0, sizeof(*target));
	target->src.u3 = tuple->dst.u3;
	target->src.l3num = l3num;
	target->dst.protonum = IPPROTO_TCP;
	target->dst.u3.ip = options.token;
	target->dst.u.tcp.port = options.token >> 16;

	return 0;
err:
	return -1;
}

/* 
 * create expection for current ct. The tunple in the expect is made up
 * of:
 * 	AF_INET, IPPROTO_TCP, daddr:0, token(saddr):stoken
 */
static int
mptcp_setup_expect(struct sk_buff *skb, struct nf_conn *ct)
{
	struct nf_conntrack_expect *exp = nf_ct_expect_alloc(ct);
	u32 token = nf_ct_ext_get_mptcp(ct)->token;
	struct nf_conntrack_tuple *tuple;
	union nf_inet_addr iaddr = {
		.ip = token,
	};
	u16 stoken = token >> 16;
	int err;

	if (!exp)
		return -ENOMEM;

	tuple = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
	nf_ct_expect_init(exp, NF_CT_EXPECT_CLASS_DEFAULT, AF_INET,
			  &tuple->dst.u3, &iaddr, IPPROTO_TCP,
			  NULL, &stoken);
	exp->helper = &mptcp_helper;

	if (ct->status & IPS_NAT_MASK && nf_nat_mptcp_hook)
		exp->expectfn = nf_nat_mptcp_hook;

	exp->flags = NF_CT_EXPECT_PERMANENT;

	err = nf_ct_expect_related(exp, 0);
	if (err)
		return -EINVAL;

	return 0;
}

bool nf_ct_expect_is_mptcp(struct nf_conntrack_expect *exp)
{
	return exp->helper == &mptcp_helper;
}

static bool mpctp_state_valid(unsigned int index)
{
	switch (index) {
	case TCP_SYN_SET:
	case TCP_SYNACK_SET:
	case TCP_ACK_SET:
	case TCP_NONE_SET:
		return true;
	default:
		return false;
	}
}

/* 
 * Called when the state of the init connection changes. This is used to
 * update the info in ext of ct.
 */
int nf_ct_mptcp_state(struct sk_buff *skb, unsigned int dataoff,
		      struct nf_conn *ct, unsigned int index)
{
	struct mptcp_options_received options;
	struct nf_ct_mptcp_ext *ext;
	struct nf_conn_help *help;
	unsigned int last_index;

	if (!nf_ct_mptcp_enabled(nf_ct_net(ct)))
		goto err;

	last_index = ct->proto.tcp.last_index;
	/* state not changed, ignore */
	if (last_index == index)
		goto err;

	if (!mpctp_state_valid(index) || !mpctp_state_valid(last_index))
		goto err;

	/* this is not a mptcp connecttion */
	if (index != TCP_SYN_SET && !nf_ct_is_mptcp(ct))
		goto err;

	skb_pull(skb, dataoff);
	mptcp_get_options(skb, &options);
	skb_push(skb, dataoff);

	if (!options.mp_capable) {
		if (index == TCP_SYN_SENT)
			goto err;
		else
			goto clean; /* mptcp is not supported by server */
	}

	/* create ext for MPTCP on SYN packet */
	if (index == TCP_SYN_SET) {
		if (nf_ct_is_mptcp(ct))
			goto err;

		ext = nf_ct_ext_add(ct, NF_CT_EXT_MPTCP, GFP_ATOMIC);
		if (!ext)
			goto err;

		if (!nf_ct_ext_exist(ct, NF_CT_EXT_HELPER) &&
		    !nf_ct_is_confirmed(ct)) {
			help = nf_ct_helper_ext_add(ct, GFP_ATOMIC);
			rcu_assign_pointer(help->helper, &mptcp_helper);
			set_bit(IPS_HELPER_BIT, &ct->status);
		}
		return 0;
	}

	if (!nf_ct_is_mptcp(ct))
		goto err;

	ext = nf_ct_ext_get_mptcp(ct);

	switch (index) {
	case TCP_SYNACK_SET:
		ext->server_key = options.sndr_key;
		break;
	case TCP_ACK_SET:
		ext->client_key = options.sndr_key;
		mptcp_crypto_key_sha(ext->server_key, &ext->token, NULL);
		ext->finished = true;
		return mptcp_setup_expect(skb, ct);
	default:
		break;
	}

	return 0;
clean:
	nf_ct_ext_clear(ct->ext, NF_CT_EXT_MPTCP);
err:
	return -1;
}

static const struct nf_ct_ext_type mpctp_ext_type = {
	.len	= sizeof(struct nf_ct_mptcp_ext),
	.align	= __alignof__(struct nf_ct_mptcp_ext),
	.id	= NF_CT_EXT_MPTCP,
};

static const struct nf_conntrack_expect_policy mptcp_exp_policy = {
	.max_expected	= 64,
	.timeout	= 5 * 60,
};

static const struct nf_conntrack_helper mptcp_helper = {
	.name = HELPER_NAME,
	.me = THIS_MODULE,
	.nat_mod_name = NF_NAT_HELPER_PREFIX HELPER_NAME,
	.expect_policy = &mptcp_exp_policy,
	.help = NULL,
};

void nf_conntrack_mptcp_init_net(struct net *net)
{
	int ret = nf_ct_extend_register(&mpctp_ext_type);
	if (ret < 0)
		pr_err("nf_conntrack_mptcp: Unable to register mptcp extension.\n");
}
