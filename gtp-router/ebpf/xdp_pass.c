/* Minimal pass-through XDP program.
 *
 * Purpose: attaching ANY native XDP program to a veth switches it into
 * NAPI/XDP receive mode, which is the precondition for that veth to RECEIVE
 * frames delivered by a peer's bpf_redirect_map()/bpf_redirect() (veth's
 * ndo_xdp_xmit silently drops redirected frames if the receiving peer has no
 * XDP program loaded). The router redirects decapped/encapped frames into the
 * veth-inet and veth-ran peers, so those peers must carry this stub for the
 * in-XDP forwarding to be delivered. It does nothing but XDP_PASS, so it is
 * transparent to all other traffic on those interfaces.
 *
 * Not part of the router's data path; it only unblocks native XDP redirect on
 * the far side of a veth pair. Attach with:
 *   ip link set dev <veth-peer> xdpdrv obj build/xdp_pass.o sec xdp
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
