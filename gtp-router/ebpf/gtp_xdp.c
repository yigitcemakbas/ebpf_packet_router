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

/* Per-rule rate cap: a fixed 1-second window counter, not a true token
 * bucket. Plain read-modify-write on map-value memory, same precedent as
 * bump_rule() above (a real atomic on this kernel caused a packet-delivery
 * regression; this is correct enough for per-rule enforcement without it).
 * Returns 1 if the packet is over budget and should be dropped, 0
 * otherwise. Plain int, not bool/true/false - no other helper in this file
 * uses <stdbool.h>-style types, and this avoids relying on it being
 * available on every clang/kernel-headers combination this builds against. */
static __always_inline int rate_limited(struct fwd_rule *rule)
{
	if (rule->rate_pps == 0)
		return 0;

	__u64 now = bpf_ktime_get_ns();
	if (now - rule->window_start_ns >= 1000000000ULL) {
		rule->window_start_ns = now;
		rule->window_count = 1;
		return 0;
	}
	if (rule->window_count >= rule->rate_pps) {
		rule->rate_drop_count++;
		return 1;
	}
	rule->window_count++;
	return 0;
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
	 *   new offset  0-13 : old UDP/GTP tail bytes - will be overwritten
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

/* GTP-U encapsulation overhead prepended to a downlink packet:
 * outer IP (20) + UDP (8) + GTP-U (8) = 36 bytes. */
#define ENCAP_OVERHEAD (sizeof(struct iphdr) + sizeof(struct udphdr) \
			+ sizeof(struct gtpuhdr))

/* Wrap a bare inner IPv4 packet in a fresh GTP-U tunnel described by @rule and
 * leave it ready for bpf_redirect(rule->out_ifindex). Returns 0 on success,
 * -1 on failure (caller should drop). The rule's src_ip/dst_ip are stored in
 * host byte order (see control/maps IPToUint32). */
static __always_inline int encap_gtpu(struct xdp_md *ctx, const struct fwd_rule *rule)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/* Read the inner IP total length while the packet is still bare. */
	struct ethhdr *eth0 = data;
	if ((void *)(eth0 + 1) > data_end)
		return -1;
	struct iphdr *inner = (struct iphdr *)(eth0 + 1);
	if ((void *)(inner + 1) > data_end)
		return -1;
	__u16 inner_tot = bpf_ntohs(inner->tot_len);

	/* Grow the packet at the front to fit the new outer headers. Layout after
	 * the move (outer Ethernet is rewritten in place at the new start):
	 *   0  : new Ethernet (14)
	 *   14 : new outer IP (20)
	 *   34 : new UDP (8)
	 *   42 : new GTP-U (8)
	 *   50 : original inner IP (unchanged) */
	if (bpf_xdp_adjust_head(ctx, -(int)ENCAP_OVERHEAD))
		return -1;

	data     = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(struct ethhdr) + ENCAP_OVERHEAD > data_end)
		return -1;

	struct ethhdr *eth = data;
	__builtin_memcpy(eth->h_dest, rule->dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, rule->smac, ETH_ALEN);
	eth->h_proto = bpf_htons(ETH_P_IP);

	__u32 sip = (__u32)rule->src_ip;
	__u32 dip = (__u32)rule->dst_ip;

	struct iphdr *oip = (struct iphdr *)(eth + 1);
	oip->version  = 4;
	oip->ihl      = 5;
	oip->tos      = 0;
	oip->tot_len  = bpf_htons((__u16)(inner_tot + ENCAP_OVERHEAD));
	oip->id       = 0;
	oip->frag_off = 0;
	oip->ttl      = 64;
	oip->protocol = IPPROTO_UDP;
	oip->saddr    = bpf_htonl(sip);
	oip->daddr    = bpf_htonl(dip);

	/* IPv4 header checksum over the fields above (id/frag/check are 0). The
	 * host-order address halves equal the on-wire big-endian 16-bit words. */
	{
		__u32 csum = 0x4500
			   + (__u32)(__u16)(inner_tot + ENCAP_OVERHEAD)
			   + 0x4011                       /* ttl=64, proto=17 (UDP) */
			   + (sip >> 16) + (sip & 0xffff)
			   + (dip >> 16) + (dip & 0xffff);
		csum = (csum & 0xffff) + (csum >> 16);
		csum = (csum & 0xffff) + (csum >> 16);
		oip->check = bpf_htons((__u16)~csum);
	}

	struct udphdr *udp = (struct udphdr *)(oip + 1);
	udp->source = bpf_htons(GTP_UDP_PORT);
	udp->dest   = bpf_htons(GTP_UDP_PORT);
	udp->len    = bpf_htons((__u16)(inner_tot + sizeof(struct udphdr)
					+ sizeof(struct gtpuhdr)));
	udp->check  = 0;   /* UDP checksum is optional for IPv4 */

	struct gtpuhdr *gtp = (struct gtpuhdr *)(udp + 1);
	gtp->flags    = GTP_VERSION_1 | GTP_PT_BIT;   /* 0x30: version 1, PT=1 */
	gtp->msg_type = GTPU_MSG_GPDU;
	gtp->length   = bpf_htons(inner_tot);
	gtp->teid     = bpf_htonl(rule->teid_out);

	return 0;
}

/* Downlink fast path: if @ue_dst matches a UE rule whose action is ENCAP_FWD,
 * wrap the packet in GTP-U and redirect it toward the gNB; otherwise pass it. */
static __always_inline int try_encap(struct xdp_md *ctx, __be32 ue_dst, __u64 pkt_len)
{
	__u32 key = bpf_ntohl(ue_dst);
	struct fwd_rule *rule = bpf_map_lookup_elem(&ueip_map, &key);
	if (!rule || rule->action != FWD_ACTION_ENCAP_FWD) {
		bump_stats(STAT_PASS, pkt_len);
		return XDP_PASS;
	}

	if (rate_limited(rule)) {
		bump_rule(rule, pkt_len);
		bump_stats(STAT_DROP, pkt_len);
		return XDP_DROP;
	}

	if (encap_gtpu(ctx, rule) < 0) {
		bump_stats(STAT_DROP, pkt_len);
		return XDP_DROP;
	}

	bump_rule(rule, pkt_len);
	bump_stats(STAT_REDIRECT, pkt_len);
	return bpf_redirect(rule->out_ifindex, 0);
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

	/* Non-UDP IPv4 packet -> candidate downlink packet to encapsulate. */
	if (iph->protocol != IPPROTO_UDP)
		return try_encap(ctx, iph->daddr, pkt_len);

	__u32 ip_hdr_len = (__u32)iph->ihl * 4;
	cursor = (void *)iph + ip_hdr_len;
	if (cursor > data_end)
		goto pass;

	struct udphdr *udph = CURSOR_ADVANCE(cursor, data_end, struct udphdr);

	/* UDP but not GTP-U -> also a downlink encap candidate. */
	if (udph->dest != bpf_htons(GTP_UDP_PORT))
		return try_encap(ctx, iph->daddr, pkt_len);

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

	/* ueip_map is keyed by the UE IP in host byte order (matching the Go
	 * control plane), so convert the inner destination before lookup. */
	__u32 ue_ip = bpf_ntohl(inner_iph->daddr);

	struct fwd_rule *rule = bpf_map_lookup_elem(&teid_map, &teid);
	if (!rule) {
		rule = bpf_map_lookup_elem(&ueip_map, &ue_ip);
		if (!rule)
			goto pass;
	}

	if (rate_limited(rule)) {
		bump_rule(rule, pkt_len);
		goto drop;
	}

	switch (rule->action) {
	case FWD_ACTION_DROP:
		bump_rule(rule, pkt_len);
		bump_stats(STAT_DROP, pkt_len);
		return XDP_DROP;
	case FWD_ACTION_DECAP_FWD: {
		/* Strip tunnel headers only - outer Ethernet stays at ctx->data. */
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
