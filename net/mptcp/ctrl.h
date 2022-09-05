
struct mptcp_iter_state {
	struct seq_net_private p;
	int num;
};

struct mptcp_seq_afinfo {
	sa_family_t family;
};

#define MPTCP_SEQ_HEADER					\
	"  sl  local_address rem_address   st tx_queue "	\
	"rx_queue tr tm->when flow_cnt retrnsmt   "		\
	"uid  inode\n"

#define MPTCP_SEQ_CONT						\
	"%4d: %08X:%04X %08X:%04X %02X %08llX:%08X %02X:%08lX "	\
	"%8X %08X %5u %6lu %d %pK\n"

#define MPTCP6_SEQ_HEADER					\
	"  sl  local_address                         "		\
	 "remote_address                        "		\
	 "st tx_queue rx_queue tr tm->when subflow_count "	\
	 "retrnsmt   uid  inode\n"

#define MPTCP6_SEQ_CONT						\
	"%4d: %08X%08X%08X%08X:%04X %08X%08X%08X%08X:%04X "	\
	"%02X %08llX:%08X %02X:%08lX %8X %08X %5u %6lu %d "	\
	"%pK\n"
