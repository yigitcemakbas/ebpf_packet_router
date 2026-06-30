#ifndef __GTP_ROUTER_H
#define __GTP_ROUTER_H

#include <linux/types.h>

/* GTP-U constants */
#define GTP_UDP_PORT 	 	2152
#define GTP_VERSION_1	 	0x20
#define GTP_PT_BIT 		0x10
#define GTPU_MSG_GPDU		0xFF

/* forwarding action codes */
#define FWD_ACTION_DROP		0 /* drop packet */
#define FWD_ACTION_DECAP_FWD	1 /* strip GTP header. forward inner PDU */
#define FWD_ACTION_ENCAP_FWD	2 /* re-encapsulate and forward */
#define FWD_ACTION_REDIRECT 	3 /* MAC-rewrite + redirect */

/* map sizing */
#define MAX_TEID_ENTRIES 	65536
#define MAX_UEIP_ENTRIES	65536

/* forwarding descriptor */
struct fwd_rule{
	__u32 action;
	__u32 out_ifindex;
	__u8 dmac[6];
	__u8 smac[6];
	__u32 teid_out;
	__be32 dst_ip;
	__be32 src_ip;
	__u16 dst_port;
	__u8 _pad[6]; /* pad so pkt_count/byte_count land on their natural 8-byte
	              * alignment and the struct is exactly 56 bytes, matching the
	              * Go mirror in control/maps/types.go (FwdRule). */
	__u64 pkt_count;
	__u64 byte_count;

	/* Per-rule rate limiting: a fixed 1-second window counter (not a true
	 * token bucket), enforced in the XDP hook before the rest of the kernel
	 * network stack ever sees the packet. rate_pps=0 means unlimited. These
	 * fields keep the struct 8-byte aligned with no extra padding needed
	 * (offsets 56/60/64/72, ending at 80). */
	__u32 rate_pps;        /* configured cap, packets/sec; 0 = unlimited */
	__u32 window_count;    /* packets seen in the current 1s window */
	__u64 window_start_ns; /* bpf_ktime_get_ns() when the window started */
	__u64 rate_drop_count; /* packets dropped specifically by this cap */
};

#endif /* __GTP_ROUTER_H */
