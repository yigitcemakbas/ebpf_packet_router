#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

#include "gtp_router.h"

struct gtpuhdr {
	__u8 flags;
	__u8 msg_type;
	__be16 length;
	__be32 teid;
} __attribute__((packed));

struct gtpu_opt {
	__be16 seq_num;
	__u8 n_pdu;
	__u8 next_ext;
} __attribute__((packed));

#define GTPU_OPT_FLAG_MASK 0x07
#define GTPU_MANDATORY_SZ  (sizeof(struct gtpuhdr))
#define GTPU_OPTIONAL_SZ   (sizeof(struct gtpu_opt))

#define STAT_PASS     0
#define STAT_DROP     1
#define STAT_REDIRECT 3

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_TEID_ENTRIES);
	__type(key, __u32);
	__type(value, struct fwd_rule);
} teid_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_UEIP_ENTRIES);
	__type(key, __be32);
	__type(value, struct fwd_rule);
} ueip_map SEC(".maps");

struct global_stats {
	__u64 packets;
	__u64 bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, struct global_stats);
} stats_map SEC(".maps");

#define CURSOR_ADVANCE(cursor, data_end, type)                      \
	({                                                              \
		type *__p = (type *)(cursor);                               \
		if ((void *)(__p + 1) > (data_end))                         \
			return XDP_DROP;                                        \
		(cursor) = (void *)(__p + 1);                               \
		__p;                                                        \
	})

static __always_inline void bump_stats(__u32 key, __u64 bytes)
{
	struct global_stats *s = bpf_map_lookup_elem(&stats_map, &key);
	if (s) {
		s->packets++;
		s->bytes += bytes;
	}
}

static __always_inline void bump_rule(struct fwd_rule *rule, __u64 bytes)
{
	/* Plain read-modify-write on the rule's own map-value memory. A true
	 * atomic (__sync_fetch_and_add / BPF_ATOMIC) on a hash-map value is
	 * unreliable on this kernel and is not needed here, so we avoid it. The
	 * counters are best-effort and may slightly undercount under concurrent
	 * multi-CPU traffic hitting the same rule. */
	rule->pkt_count += 1;
	rule->byte_count += bytes;
}

static __always_inline void rewrite_eth(struct ethhdr *eth, const struct fwd_rule *rule)
{
	__builtin_memcpy(eth->h_dest, rule->dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, rule->smac, ETH_ALEN);
}

static __always_inline int decap_gtpu(struct xdp_md *ctx,
				      const struct fwd_rule *rule, __u32 strip_bytes)
{
	/* strip_bytes = outer IP + UDP + GTP (not outer Ethernet, 14 B).
	 * After advancing ctx->data by strip_bytes the layout becomes:
	 *   new offset  0-13 : old UDP/GTP tail bytes — will be overwritten
	 *   new offset 14+   : inner IP (correct position after Ethernet)
	 * Write the new Ethernet header at the new ctx->data. */
	if (bpf_xdp_adjust_head(ctx, (int)strip_bytes))
		return -1;

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *new_eth = (struct ethhdr *)data;
	if ((void *)(new_eth + 1) > data_end)
		return -1;

	__builtin_memcpy(new_eth->h_dest, rule->dmac, ETH_ALEN);
	__builtin_memcpy(new_eth->h_source, rule->smac, ETH_ALEN);
	new_eth->h_proto = bpf_htons(ETH_P_IP);

	struct iphdr *inner = (struct iphdr *)(new_eth + 1);
	if ((void *)(inner + 1) > data_end || inner->version != 4)
		return -1;

	return 0;
}

SEC("xdp")
int xdp_gtp_router(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *cursor = (void *)(long)ctx->data;
	__u64 pkt_len = data_end - cursor;

	struct ethhdr *eth = CURSOR_ADVANCE(cursor, data_end, struct ethhdr);

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		goto pass;

	struct iphdr *iph = CURSOR_ADVANCE(cursor, data_end, struct iphdr);

	if (iph->version != 4 || iph->ihl < 5)
		goto pass;

	if (iph->protocol != IPPROTO_UDP)
		goto pass;

	__u32 ip_hdr_len = (__u32)iph->ihl * 4;
	cursor = (void *)iph + ip_hdr_len;
	if (cursor > data_end)
		goto pass;

	struct udphdr *udph = CURSOR_ADVANCE(cursor, data_end, struct udphdr);

	if (udph->dest != bpf_htons(GTP_UDP_PORT))
		goto pass;

	struct gtpuhdr *gtph = CURSOR_ADVANCE(cursor, data_end, struct gtpuhdr);

	if ((gtph->flags & 0xE0) != GTP_VERSION_1)
		goto pass;
	if (!(gtph->flags & GTP_PT_BIT))
		goto pass;
	if (gtph->msg_type != GTPU_MSG_GPDU)
		goto pass;

	__u32 teid = bpf_ntohl(gtph->teid);

	__u32 opt_sz = 0;
	if (gtph->flags & GTPU_OPT_FLAG_MASK) {
		struct gtpu_opt *opt = CURSOR_ADVANCE(cursor, data_end, struct gtpu_opt);
		(void)opt;
		opt_sz = GTPU_OPTIONAL_SZ;
	}

	struct iphdr *inner_iph = CURSOR_ADVANCE(cursor, data_end, struct iphdr);
	if (inner_iph->version != 4)
		goto pass;

	__be32 ue_ip = inner_iph->daddr;

	struct fwd_rule *rule = bpf_map_lookup_elem(&teid_map, &teid);
	if (!rule) {
		rule = bpf_map_lookup_elem(&ueip_map, &ue_ip);
		if (!rule)
			goto pass;
	}

	switch (rule->action) {
	case FWD_ACTION_DROP:
		bump_rule(rule, pkt_len);
		bump_stats(STAT_DROP, pkt_len);
		return XDP_DROP;
	case FWD_ACTION_DECAP_FWD: {
		/* Strip tunnel headers only — outer Ethernet stays at ctx->data. */
		__u32 strip = ip_hdr_len + sizeof(struct udphdr)
			+ sizeof(struct gtpuhdr) + opt_sz;

		if (decap_gtpu(ctx, rule, strip) < 0)
			goto drop;

		bump_rule(rule, pkt_len);
		bump_stats(STAT_REDIRECT, pkt_len);
		return bpf_redirect(rule->out_ifindex, 0);
	}
	case FWD_ACTION_REDIRECT:
		rewrite_eth(eth, rule);
		bump_rule(rule, pkt_len);
		bump_stats(STAT_REDIRECT, pkt_len);
		return bpf_redirect(rule->out_ifindex, 0);
	case FWD_ACTION_ENCAP_FWD:
		goto pass;
	default:
		goto drop;
	}

pass:
	bump_stats(STAT_PASS, pkt_len);
	return XDP_PASS;
drop:
	bump_stats(STAT_DROP, pkt_len);
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
