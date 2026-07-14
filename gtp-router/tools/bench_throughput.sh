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
  echo "  [WARN] veth-gnb1 attached as xdpgeneric, not native - native row may be invalid"
fi
PPS_NATIVE=$(measure "$PCAP_GTP" "native" | tail -1)

# --- generic --------------------------------------------------------------
echo
echo "[generic] GTP-U decap + redirect, generic/SKB XDP (post-sk_buff)"
XDP_MODE=generic TEID="$TEID" bash tools/setup_netns.sh --mode generic >/dev/null 2>&1
PPS_GENERIC=$(measure "$PCAP_GTP" "generic" | tail -1)

# --- plain (no XDP, kernel IP forwarding) ---------------------------------
echo
echo "[plain] kernel IP forwarding, no XDP (post-sk_buff baseline)"
"$GTP_CTRL" unload --iface veth-gnb1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.ip_forward=1 >/dev/null
# permit forwarding and relax rp_filter for the asymmetric synthetic path
iptables -C FORWARD -j ACCEPT 2>/dev/null || iptables -I FORWARD -j ACCEPT
for i in all veth-gnb1 veth-core0; do sysctl -w "net.ipv4.conf.$i.rp_filter=0" >/dev/null 2>&1 || true; done
# gnb needs a route to the core subnet via the host (dst MAC is hardcoded in the
# frame, but the host still routes on dst IP once it ingresses).
ip netns exec gnb ip route replace 10.0.1.0/24 via 10.0.0.2 2>/dev/null || true
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
echo "sanity: expect native >= generic, and native comfortably above plain."
echo "(paste these into the README Performance table.)"
