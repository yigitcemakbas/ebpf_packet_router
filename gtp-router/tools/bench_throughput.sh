# tools/bench_throughput.sh
#
# Three-way forwarding-throughput benchmark for the GTP-U XDP router, on the
# self-contained synthetic setup_netns.sh topology. Compares, at a single
# uniform measurement point (packets actually delivered to veth-core1):
#
#   native   - router in native/driver XDP (pre-sk_buff): GTP-U decap + redirect
#   generic  - the SAME program in generic/SKB XDP (post-sk_buff): decap + redirect
#   plain    - no XDP at all: the kernel's general-purpose IP forwarding of an
#              equivalent plain packet (the honest "what the stack does without
#              us" baseline; the stack has no native GTP-U decap, so the plain
#              row forwards a plain IP packet rather than decapsulating one)
#
# Method: a single crafted frame is replayed at maximum rate with tcpreplay for
# a fixed duration (scapy cannot generate enough pps to saturate an XDP path;
# tcpreplay replaying a pcap can). Throughput is the delta of veth-core1's
# rx_packets counter over the run divided by the duration - the same metric for
# all three modes, so the numbers are directly comparable. This measures the
# forwarding fast path, which is exactly where native XDP's pre-sk_buff
# advantage over generic mode and over the general-purpose stack shows.
#
# Prerequisites: root; tcpreplay (apt install tcpreplay); scapy; a built
# gtp-ctrl; ebpf object built. Run from the repo root.
#
# Usage:
#   sudo bash tools/bench_throughput.sh [--duration 10] [--pkt-size 64]

set -uo pipefail

DURATION="${DURATION:-10}"
PKT_SIZE="${PKT_SIZE:-64}"
TEID="${TEID:-0xDEAD}"
GTP_CTRL="${GTP_CTRL:-./build/gtp-ctrl}"
PASS_OBJ="${PASS_OBJ:-build/xdp_pass.o}"
PCAP_GTP="/tmp/bench_gtp_$$.pcap"
PCAP_PLAIN="/tmp/bench_plain_$$.pcap"
RESULTS="/tmp/gtp-bench-results.txt"

while [[ $# -gt 0 ]]; do
  case $1 in
    --duration) DURATION="$2"; shift 2 ;;
    --pkt-size) PKT_SIZE="$2"; shift 2 ;;
    *) echo "Unknown flag: $1"; exit 1 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "error: must be run as root" >&2
  exit 1
fi
command -v tcpreplay >/dev/null || { echo "error: tcpreplay not installed (apt install tcpreplay)" >&2; exit 1; }
[[ -x "$GTP_CTRL" ]] || { echo "error: $GTP_CTRL not built - run 'make all'" >&2; exit 1; }
python3 -c "import scapy" 2>/dev/null || { echo "error: scapy not installed (pip install scapy)" >&2; exit 1; }

cleanup() { rm -f "$PCAP_GTP" "$PCAP_PLAIN"; }
trap cleanup EXIT

# rx_packets counter on veth-core1 inside the core namespace - the uniform
# measurement point for every mode.
core_rx() { ip netns exec core cat /sys/class/net/veth-core1/statistics/rx_packets 2>/dev/null || echo 0; }

# The router redirects decapped frames to veth-core0 with bpf_redirect; in native
# XDP that reaches the peer veth-core1 via veth's ndo_xdp_xmit, which ONLY
# delivers to a peer that has an XDP program attached. Without a stub on
# veth-core1 the frames are silently dropped and the native/generic rows measure
# ~0 even while the router's own REDIRECT counter shows full rate (bug G1).
# setup_netns.sh recreates the core namespace on every call, so re-attach after
# each one.
attach_core_stub() {
  [[ -f "$PASS_OBJ" ]] || { echo "error: $PASS_OBJ not built - run 'make all'" >&2; exit 1; }
  ip netns exec core ip link set dev veth-core1 xdpdrv obj "$PASS_OBJ" sec xdp 2>/dev/null || true
}
# core_has_xdp - true if veth-core1 currently has any XDP program attached.
core_has_xdp() { ip netns exec core ip link show veth-core1 2>/dev/null | grep -q 'xdp'; }

# run_replay <pcap> <duration> - blast <pcap> at max rate from the gnb namespace
# for <duration> seconds. tcpreplay --loop 0 loops forever; timeout bounds it.
run_replay() {
  local pcap="$1" dur="$2"
  timeout "$dur" ip netns exec gnb tcpreplay --topspeed --loop 0 -i veth-gnb0 "$pcap" >/dev/null 2>&1 || true
}

# measure <pcap> <label> - snapshot core rx, replay, snapshot again, print pps.
measure() {
  local pcap="$1" label="$2" before after delta pps
  before=$(core_rx)
  run_replay "$pcap" "$DURATION"
  sleep 0.3
  after=$(core_rx)
  delta=$(( after - before ))
  pps=$(awk -v d="$delta" -v t="$DURATION" 'BEGIN{ printf "%.0f", d / t }')
  # human line to stderr so it prints live; only the pps goes to stdout, which
  # the caller captures.
  printf "  %-8s delivered %d pkts in %ss  =>  %s pps\n" "$label" "$delta" "$DURATION" "$pps" >&2
  echo "$pps"
}

echo "══════════════════════════════════════════════════════"
echo " GTP-U XDP Router — Throughput Benchmark (native / generic / plain)"
echo "══════════════════════════════════════════════════════"
echo " Duration/mode : ${DURATION}s    packet size: ${PKT_SIZE}B"
echo " Measurement   : veth-core1 rx_packets delta (uniform across modes)"
echo

# --- craft the two frames once (MACs depend on the topology, so bring it up
#     first in native mode, then read the MACs). ---
echo "[bench] bringing up topology to read interface MACs..."
XDP_MODE=native TEID="$TEID" bash tools/setup_netns.sh --mode native >/dev/null 2>&1
attach_core_stub
GNB1_MAC=$(cat /sys/class/net/veth-gnb1/address)
GNB0_MAC=$(ip netns exec gnb cat /sys/class/net/veth-gnb0/address)

echo "[bench] crafting replay frames (scapy)..."
python3 - "$PCAP_GTP" "$PCAP_PLAIN" "$GNB0_MAC" "$GNB1_MAC" "$TEID" "$PKT_SIZE" <<'PYEOF'
import struct, sys
from scapy.all import Ether, IP, UDP, Raw, wrpcap
pcap_gtp, pcap_plain, smac, dmac, teid_s, size_s = sys.argv[1:7]
teid = int(teid_s, 0); size = int(size_s)
payload = bytes((i % 256 for i in range(size)))

# GTP-U uplink frame: Eth/IP/UDP(2152)/GTP-U(TEID)/inner-IP(10.1.0.1->10.1.0.2)
inner = bytes(IP(src="10.1.0.1", dst="10.1.0.2") / Raw(payload))
flags, mtype = 0x30, 0xFF                       # G-PDU, no optional header
gtp = struct.pack("!BBHI", flags, mtype, len(inner), teid)
gtp_frame = (Ether(src=smac, dst=dmac) / IP(src="10.0.0.1", dst="10.0.0.2")
             / UDP(sport=2152, dport=2152) / Raw(gtp + inner))
wrpcap(pcap_gtp, gtp_frame)

# Plain-forward frame: a bare IP packet the host will L3-forward gnb->core,
# 10.0.0.1 -> 10.0.1.2 (outer subnets already exist on the veths).
plain = (Ether(src=smac, dst=dmac) / IP(src="10.0.0.1", dst="10.0.1.2", ttl=64)
         / UDP(sport=4096, dport=9999) / Raw(payload))
wrpcap(pcap_plain, plain)
PYEOF
[[ -f "$PCAP_GTP" && -f "$PCAP_PLAIN" ]] || { echo "error: failed to craft pcaps" >&2; exit 1; }

# --- native ---------------------------------------------------------------
echo
echo "[native] GTP-U decap + redirect, native/driver XDP (pre-sk_buff)"
if ip link show veth-gnb1 | grep -q "xdpgeneric"; then
  echo "  error: veth-gnb1 attached as xdpgeneric, not native - native row would be invalid" >&2
  exit 1
fi
# The native row is only meaningful if the redirect target can actually receive
# the frames; without the stub they vanish and the number lies (bug G1/G3).
if ! core_has_xdp; then
  echo "  error: veth-core1 has no XDP program - native redirect frames would be dropped" >&2
  echo "         (attach_core_stub failed; is $PASS_OBJ built and does veth support xdpdrv?)" >&2
  exit 1
fi
PPS_NATIVE=$(measure "$PCAP_GTP" "native" | tail -1)

# --- generic --------------------------------------------------------------
echo
echo "[generic] GTP-U decap + redirect, generic/SKB XDP (post-sk_buff)"
XDP_MODE=generic TEID="$TEID" bash tools/setup_netns.sh --mode generic >/dev/null 2>&1
# Generic XDP redirect delivers to veth-core1 through the normal receive path, but
# keep the stub attached so the measurement point is identical across modes.
attach_core_stub
PPS_GENERIC=$(measure "$PCAP_GTP" "generic" | tail -1)

# --- plain (no XDP, kernel IP forwarding) ---------------------------------
echo
echo "[plain] kernel IP forwarding, no XDP (post-sk_buff baseline)"
"$GTP_CTRL" unload --iface veth-gnb1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.ip_forward=1 >/dev/null
# permit forwarding and relax rp_filter for the asymmetric synthetic path
iptables -C FORWARD -j ACCEPT 2>/dev/null || iptables -I FORWARD -j ACCEPT
for i in all default veth-gnb1 veth-core0; do sysctl -w "net.ipv4.conf.$i.rp_filter=0" >/dev/null 2>&1 || true; done
# The forwarded packet (src 10.0.0.1) is delivered locally on veth-core1 inside
# the core namespace, which has no route back to 10.0.0.1 - strict rp_filter there
# would drop it on input. Relax rp_filter in the core ns and add the return route
# so delivery (and the rx_packets count) actually happens (bug G2).
for i in all default veth-core1; do
  ip netns exec core sysctl -w "net.ipv4.conf.$i.rp_filter=0" >/dev/null 2>&1 || true
done
ip netns exec core ip route replace 10.0.0.0/24 via 10.0.1.1 2>/dev/null || true
# gnb needs a route to the core subnet via the host (dst MAC is hardcoded in the
# frame, but the host still routes on dst IP once it ingresses).
ip netns exec gnb ip route replace 10.0.1.0/24 via 10.0.0.2 2>/dev/null || true
# Re-craft the plain frame with the CURRENT veth MACs. Unlike XDP (which sees the
# frame before the L2 destination check and so ignores dst MAC), plain kernel
# forwarding drops any frame whose dst MAC isn't veth-gnb1's - and setup_netns.sh
# recreated the veths (with fresh MACs) for the generic run after the pcaps were
# first crafted, leaving the original dst MAC stale. Without this the plain row
# reads ~0 (bug G2).
GNB1_MAC=$(cat /sys/class/net/veth-gnb1/address)
GNB0_MAC=$(ip netns exec gnb cat /sys/class/net/veth-gnb0/address)
python3 - "$PCAP_PLAIN" "$GNB0_MAC" "$GNB1_MAC" "$PKT_SIZE" <<'PYEOF'
import sys
from scapy.all import Ether, IP, UDP, Raw, wrpcap
pcap_plain, smac, dmac, size_s = sys.argv[1:5]
size = int(size_s)
payload = bytes((i % 256 for i in range(size)))
plain = (Ether(src=smac, dst=dmac) / IP(src="10.0.0.1", dst="10.0.1.2", ttl=64)
         / UDP(sport=4096, dport=9999) / Raw(payload))
wrpcap(pcap_plain, plain)
PYEOF
PPS_PLAIN=$(measure "$PCAP_PLAIN" "plain" | tail -1)

# --- report ---------------------------------------------------------------
{
  echo "GTP-U XDP Router throughput benchmark  ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
  echo "kernel: $(uname -r)   duration/mode: ${DURATION}s   pkt-size: ${PKT_SIZE}B"
  echo "measurement: veth-core1 rx_packets delta / duration"
  echo
  printf "%-10s %-14s %s\n" "mode" "pps" "workload"
  printf "%-10s %-14s %s\n" "native"  "$PPS_NATIVE"  "GTP-U decap+redirect, pre-sk_buff (driver XDP)"
  printf "%-10s %-14s %s\n" "generic" "$PPS_GENERIC" "GTP-U decap+redirect, post-sk_buff (SKB XDP)"
  printf "%-10s %-14s %s\n" "plain"   "$PPS_PLAIN"   "kernel IP forward, post-sk_buff (no XDP)"
} | tee "$RESULTS"

echo
echo "results written to $RESULTS"

# Two distinct sanity checks (bug G3):
#
#  1. A zero/non-numeric row means a MEASUREMENT PATH IS BROKEN (e.g. the redirect
#     target lost its XDP stub, or the plain frame's dst MAC went stale) - the
#     number is meaningless, so hard-fail.
#
#  2. All rows non-zero but the expected ordering native>=generic>=plain does not
#     hold is NOT a broken measurement - on a veth/virtio topology it is the
#     honest result: veth is a software device, so "native" XDP has no driver
#     advantage and its redirect actually costs more than the kernel's optimised
#     veth forwarding path. The numbers are valid, just not evidence that native
#     is faster - so suppress the "paste into the README" invitation, print a
#     caveat, and exit 0. (Native's real advantage only shows on a hardware NIC
#     doing xdpdrv before skb allocation.)
broken=0
for v in "$PPS_NATIVE" "$PPS_GENERIC" "$PPS_PLAIN"; do
  [[ "$v" =~ ^[0-9]+$ ]] && (( v > 0 )) || broken=1
done
if (( broken )); then
  echo "sanity: FAIL - a measurement path is broken (a row is zero/non-numeric)." >&2
  echo "  native=$PPS_NATIVE generic=$PPS_GENERIC plain=$PPS_PLAIN pps" >&2
  echo "  Do NOT publish these numbers. Check that veth-core1 has an XDP stub" >&2
  echo "  (native/generic rows) and the core-ns route/rp_filter + fresh dst MAC" >&2
  echo "  (plain row)." >&2
  exit 1
fi

if awk -v n="$PPS_NATIVE" -v g="$PPS_GENERIC" -v p="$PPS_PLAIN" 'BEGIN{ exit !(n>=g && g>=p) }'; then
  echo "sanity: OK - native ($PPS_NATIVE) >= generic ($PPS_GENERIC) >= plain ($PPS_PLAIN) pps."
  echo "(paste these into the README Performance table.)"
else
  echo "sanity: all rows measured OK, but ordering native>=generic>=plain does NOT hold"
  echo "  native=$PPS_NATIVE generic=$PPS_GENERIC plain=$PPS_PLAIN pps"
  echo "  This is expected on a veth/virtio topology: all three paths are software"
  echo "  and land within measurement noise, so these numbers do NOT demonstrate a"
  echo "  native-XDP throughput advantage - do not paste them into the README as one."
  echo "  Re-run on a hardware NIC that supports xdpdrv to show native's real edge."
fi
