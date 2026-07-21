#!/usr/bin/env bash
# tools/bench_selectivity_scaling.sh  -  BENCH 3 of the suite.
#
# Part (a) SELECTIVITY - a capability a conventional router does not have:
#   per-subscriber in-tunnel policy. Several subscribers share one N3 GTP-U
#   tunnel (all outer UDP/2152); we rate-limit exactly ONE by its TEID and show
#   the others are untouched. A normal router sees only opaque UDP/2152 and could
#   cap the whole tunnel or nothing - it cannot single out one subscriber inside
#   it. This is a qualitative differentiator, reported as capability, not a race.
#
# Part (b) O(1) SCALING - per-packet cost vs number of installed rules. The XDP
#   router keys subscribers in a BPF hash map (O(1) lookup), so per-packet CPU is
#   flat as the rule set grows 1 -> 10000. For contrast we measure an equivalent
#   linear nftables ruleset (N per-source rules the packet is matched against),
#   whose per-packet cost rises with N. The chart-worthy result is the SHAPE:
#   XDP flat vs. stack-based linear rising. (Note: nft CAN be made O(1) with sets/
#   maps; we compare the naive per-rule form, and say so.)
#
# Held offered load (not max pps). Uniform /proc/stat CPU method (bench_common.sh).
# Self-contained; root required.
#   sudo bash tools/bench_selectivity_scaling.sh [--dur 6] [--reps 3]
set -uo pipefail
cd "$(dirname "$0")/.."
source tools/bench_common.sh

DUR=6; REPS=3
while [[ $# -gt 0 ]]; do case $1 in
  --dur) DUR="$2"; shift 2;; --reps) REPS="$2"; shift 2;;
  *) echo "unknown arg: $1" >&2; exit 1;; esac; done
[[ $EUID -eq 0 ]] || { echo "error: run as root" >&2; exit 1; }

GTP_CTRL=./build/gtp-ctrl
PASS_OBJ=build/xdp_pass.o
HELD=100000
RAW_SEL="$BENCH_OUT/bench3a_selectivity.tsv"
RAW_SCALE="$BENCH_OUT/bench3b_scaling.tsv"

native_topo() {
  XDP_MODE=native bash tools/setup_netns.sh --mode native >/dev/null 2>&1
  ip netns exec core ip link set dev veth-core1 xdpdrv obj "$PASS_OBJ" sec xdp 2>/dev/null || true
  GNB1=$(cat /sys/class/net/veth-gnb1/address)
  GNB0=$(ip netns exec gnb cat /sys/class/net/veth-gnb0/address)
  CORE0_MAC=$(cat /sys/class/net/veth-core0/address)
}

# ============================ PART (a) SELECTIVITY ============================
selectivity() {
  echo "================================================================="
  echo " BENCH 3a - per-subscriber selectivity inside one shared tunnel"
  echo "================================================================="
  native_topo
  local K=4 base=0x00003001
  # K subscribers, distinct TEIDs + distinct inner dst IPs, all decap+redirect.
  local teids=()
  for ((i=0;i<K;i++)); do
    local t; t=$(printf '0x%08x' $((base + i)))
    teids+=("$t")
    "$GTP_CTRL" add-teid --teid "$t" --action decap --out-iface veth-core0 \
      --dmac "$CORE0_MAC" --smac "$GNB1" >/dev/null 2>&1
  done
  # one pcap with K frames (distinct TEID + inner dst); tcpreplay round-robins,
  # so each subscriber gets ~HELD/K pps.
  local pcap=/tmp/b3a_$$.pcap
  python3 - "$pcap" "$GNB0" "$GNB1" "$K" "$base" <<'PY'
import struct,sys
from scapy.all import Ether,IP,UDP,Raw,wrpcap
pcap,smac,dmac,K,base=sys.argv[1],sys.argv[2],sys.argv[3],int(sys.argv[4]),int(sys.argv[5],0)
frames=[]
for i in range(K):
    payload=bytes((j%256 for j in range(64)))
    inner=bytes(IP(src="10.1.0.1",dst="10.2.0.%d"%(i+1))/Raw(payload))
    gtp=struct.pack("!BBHI",0x30,0xFF,len(inner),base+i)
    frames.append(Ether(src=smac,dst=dmac)/IP(src="10.0.0.1",dst="10.0.0.2")/UDP(sport=2152,dport=2152)/Raw(gtp+inner))
wrpcap(pcap,frames)
PY
  printf 'phase\tteid\tfwd_pkts\trate_drops\n' > "$RAW_SEL"
  fwd_of(){ "$GTP_CTRL" list 2>/dev/null | awk -v t="$1" 'tolower($1)==tolower(t){print $6}'; }
  drops_of(){ "$GTP_CTRL" list 2>/dev/null | awk -v t="$1" 'tolower($1)==tolower(t){print $9}'; }

  echo; echo " Phase 1: BASELINE - all $K subscribers uncapped, equal offered load"
  for t in "${teids[@]}"; do "$GTP_CTRL" add-teid --teid "$t" --action decap --out-iface veth-core0 --dmac "$CORE0_MAC" --smac "$GNB1" >/dev/null 2>&1; done
  declare -A base_f
  for t in "${teids[@]}"; do base_f[$t]=$(fwd_of "$t"); done
  run_load "$pcap" "$HELD" "$DUR" gnb veth-gnb0
  for t in "${teids[@]}"; do
    local f; f=$(( $(fwd_of "$t") - ${base_f[$t]} ))
    printf 'baseline\t%s\t%s\t0\n' "$t" "$f" >> "$RAW_SEL"
    printf '   %s : %8d pkts forwarded (%.0f pps)\n' "$t" "$f" "$(awk -v x=$f -v d=$DUR 'BEGIN{print x/d}')"
  done

  echo; echo " Phase 2: rate-limit ONLY ${teids[1]} to 5000 pps; re-drive same load"
  echo "          (col PACKETS = matched; forwarded = matched - rate-drops)"
  "$GTP_CTRL" add-teid --teid "${teids[1]}" --action decap --out-iface veth-core0 \
    --dmac "$CORE0_MAC" --smac "$GNB1" --rate-pps 5000 >/dev/null 2>&1
  declare -A p2f p2d
  for t in "${teids[@]}"; do p2f[$t]=$(fwd_of "$t"); p2d[$t]=$(drops_of "$t"); done
  run_load "$pcap" "$HELD" "$DUR" gnb veth-gnb0
  for t in "${teids[@]}"; do
    local m dr fwd; m=$(( $(fwd_of "$t") - ${p2f[$t]} )); dr=$(( $(drops_of "$t") - ${p2d[$t]} )); fwd=$(( m - dr ))
    local tag="uncapped"; [[ "$t" == "${teids[1]}" ]] && tag="** CAPPED **"
    printf 'capped_one\t%s\t%s\t%s\n' "$t" "$fwd" "$dr" >> "$RAW_SEL"
    printf '   %s : matched=%7d  forwarded=%7d (%5.0f pps)  rate-drops=%-8d  %s\n' \
      "$t" "$m" "$fwd" "$(awk -v x=$fwd -v d=$DUR 'BEGIN{print x/d}')" "$dr" "$tag"
  done
  rm -f "$pcap"
  echo
  echo " READ: only ${teids[1]} is throttled; the other 3 subscribers in the SAME"
  echo "       UDP/2152 tunnel are unaffected. A conventional router, seeing only"
  echo "       opaque outer UDP/2152, cannot do this - it is all-or-nothing."
}

# ============================ PART (b) SCALING ===============================
scaling_xdp() {
  echo; echo "================================================================="
  echo " BENCH 3b(i) - XDP router per-packet CPU vs teid_map size (expect FLAT)"
  echo "================================================================="
  native_topo
  local TARGET=0x0000dead
  local pcap=/tmp/b3b_$$.pcap
  python3 - "$pcap" "$GNB0" "$GNB1" "$TARGET" <<'PY'
import struct,sys
from scapy.all import Ether,IP,UDP,Raw,wrpcap
pcap,smac,dmac,teid=sys.argv[1],sys.argv[2],sys.argv[3],int(sys.argv[4],0)
payload=bytes((i%256 for i in range(64)))
inner=bytes(IP(src="10.1.0.1",dst="10.1.0.2")/Raw(payload))
gtp=struct.pack("!BBHI",0x30,0xFF,len(inner),teid)
wrpcap(pcap, Ether(src=smac,dst=dmac)/IP(src="10.0.0.1",dst="10.0.0.2")/UDP(sport=2152,dport=2152)/Raw(gtp+inner))
PY
  printf 'engine\tn_rules\trep\tdelivered\tcpu_s_all\tcpu_per_pkt_all\tpct_cpu\n' > "$RAW_SCALE"
  # the single target rule always present
  "$GTP_CTRL" add-teid --teid "$TARGET" --action decap --out-iface veth-core0 --dmac "$CORE0_MAC" --smac "$GNB1" >/dev/null 2>&1
  local have=1
  for N in 1 100 1000 10000; do
    # top up decoy rules to reach N total
    if (( N > have )); then
      for ((i=have;i<N;i++)); do
        "$GTP_CTRL" add-teid --teid "$(printf '0x%08x' $((0x00100000 + i)))" --action decap \
          --out-iface veth-core0 --dmac "$CORE0_MAC" --smac "$GNB1" >/dev/null 2>&1
      done
      have=$N
    fi
    for r in $(seq 1 "$REPS"); do
      b0=$(core_rx); cpu_snap /tmp/b3_before
      run_load "$pcap" "$HELD" "$DUR" gnb veth-gnb0
      cpu_snap /tmp/b3_after; sleep 0.2; b1=$(core_rx)
      local delivered=$(( b1 - b0 ))
      read cpu_all pct <<<"$(cpu_busy_seconds /tmp/b3_before /tmp/b3_after "$DUR")"
      local cpp; cpp=$(awk -v c="$cpu_all" -v d="$delivered" 'BEGIN{printf (d>0?"%.4e":"NA"),(d>0?c/d:0)}')
      printf 'xdp_hash\t%s\t%s\t%s\t%.4f\t%s\t%.2f\n' "$N" "$r" "$delivered" "$cpu_all" "$cpp" "$pct" >> "$RAW_SCALE"
      printf '  [xdp N=%-6s r%s] delivered=%8s  CPU/pkt=%s  %%CPU=%.1f\n' "$N" "$r" "$delivered" "$cpp" "$pct"
    done
  done
  rm -f "$pcap"
}

scaling_nft() {
  echo; echo "================================================================="
  echo " BENCH 3b(ii) - nftables linear per-source ruleset (expect RISING)"
  echo "================================================================="
  # plain-forward topology (no XDP); nft chain in the forward hook.
  XDP_MODE=generic bash tools/setup_netns.sh --mode generic >/dev/null 2>&1
  "$GTP_CTRL" unload --iface veth-gnb1 >/dev/null 2>&1 || true
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  for i in all default veth-gnb1 veth-core0; do sysctl -w "net.ipv4.conf.$i.rp_filter=0" >/dev/null 2>&1 || true; done
  for i in all default veth-core1; do ip netns exec core sysctl -w "net.ipv4.conf.$i.rp_filter=0" >/dev/null 2>&1 || true; done
  ip netns exec core ip route replace 10.0.0.0/24 via 10.0.1.1 2>/dev/null || true
  ip netns exec gnb  ip route replace 10.0.1.0/24 via 10.0.0.2 2>/dev/null || true
  local GNB0 GNB1; GNB1=$(cat /sys/class/net/veth-gnb1/address); GNB0=$(ip netns exec gnb cat /sys/class/net/veth-gnb0/address)
  local pcap=/tmp/b3nft_$$.pcap
  python3 - "$pcap" "$GNB0" "$GNB1" <<'PY'
import sys
from scapy.all import Ether,IP,UDP,Raw,wrpcap
pcap,smac,dmac=sys.argv[1],sys.argv[2],sys.argv[3]
wrpcap(pcap, Ether(src=smac,dst=dmac)/IP(src="10.0.0.1",dst="10.0.1.2",ttl=64)/UDP(sport=4096,dport=9999)/Raw(bytes((i%256 for i in range(64)))))
PY
  command -v nft >/dev/null || { echo "  [skip] nft not installed - cannot run the stack-based contrast"; rm -f "$pcap"; return; }
  for N in 1 100 1000 10000; do
    # build a chain with N non-matching saddr comparisons every fwd packet scans
    nft delete table ip bench 2>/dev/null || true
    { echo "table ip bench {"
      echo "  chain scan { type filter hook forward priority -150; policy accept;"
      for ((i=0;i<N;i++)); do printf '    ip saddr 172.%d.%d.%d counter\n' $(( (i>>16)&0xff )) $(( (i>>8)&0xff )) $(( i&0xff )); done
      echo "  }"
      echo "}"; } | nft -f - 2>/dev/null || { echo "  [warn] nft load failed at N=$N"; continue; }
    for r in $(seq 1 "$REPS"); do
      b0=$(core_rx); cpu_snap /tmp/b3_before
      run_load "$pcap" "$HELD" "$DUR" gnb veth-gnb0
      cpu_snap /tmp/b3_after; sleep 0.2; b1=$(core_rx)
      local delivered=$(( b1 - b0 ))
      read cpu_all pct <<<"$(cpu_busy_seconds /tmp/b3_before /tmp/b3_after "$DUR")"
      local cpp; cpp=$(awk -v c="$cpu_all" -v d="$delivered" 'BEGIN{printf (d>0?"%.4e":"NA"),(d>0?c/d:0)}')
      printf 'nft_linear\t%s\t%s\t%s\t%.4f\t%s\t%.2f\n' "$N" "$r" "$delivered" "$cpu_all" "$cpp" "$pct" >> "$RAW_SCALE"
      printf '  [nft N=%-6s r%s] delivered=%8s  CPU/pkt=%s  %%CPU=%.1f\n' "$N" "$r" "$delivered" "$cpp" "$pct"
    done
  done
  nft delete table ip bench 2>/dev/null || true
  rm -f "$pcap"
}

perf_available && true || true
echo " host: $(uname -r)  ncpu=$BENCH_NCPU  gen core $BENCH_GEN_CORE  held=${HELD}pps dur=${DUR}s reps=$REPS"
echo " raw -> $RAW_SEL , $RAW_SCALE"
selectivity
scaling_xdp
scaling_nft
"$GTP_CTRL" unload --iface veth-gnb1 >/dev/null 2>&1 || true
bash tools/teardown_netns.sh >/dev/null 2>&1 || true

echo; echo "==== SCALING SUMMARY (mean CPU-s/pkt +/- CV%, n=$REPS) ===="
python3 - "$RAW_SCALE" <<'PY'
import statistics as st, sys
rows=[l.rstrip().split('\t') for l in open(sys.argv[1])][1:]
for eng in ['xdp_hash','nft_linear']:
    ns=sorted({int(r[1]) for r in rows if r[0]==eng})
    if not ns: continue
    print(f"\n  {eng}:")
    for n in ns:
        v=[float(r[5]) for r in rows if r[0]==eng and int(r[1])==n and r[5]!='NA']
        if v:
            m=st.mean(v); cv=100*st.pstdev(v)/m if m else 0
            print(f"    N={n:>6}: {m:.3e} CPU-s/pkt  CV{cv:4.1f}%")
PY
