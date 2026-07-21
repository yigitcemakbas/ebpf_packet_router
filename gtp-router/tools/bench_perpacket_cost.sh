#!/usr/bin/env bash
# tools/bench_perpacket_cost.sh  -  BENCH 2 of the suite.
#
# Per-packet CPU cost of the three data planes at a HELD offered load (not the
# max-pps ceiling, which is generator-bound here). Same GTP-U decap+redirect job
# in native XDP (pre-sk_buff) and generic XDP (post-sk_buff, same program), and
# the kernel's plain IPv4 forward (no XDP) as the stack baseline.
#
# We deliberately do NOT report pps (generator-bound on veth). We report
# CPU-seconds-per-packet and %CPU at the held rate, computed identically for all
# three, plus cycles/packet if the VM exposes a PMU.
#
# Expectation: native <= generic <= plain in CPU/packet, because native skips the
# sk_buff allocation that generic and the stack pay. On a software veth rig the
# gap is small and can be noisy - we report mean+CV over >=3 reps and call it
# honestly if it doesn't separate.
#
# Self-contained: builds its own setup_netns.sh topology per mode. Root required.
#   sudo bash tools/bench_perpacket_cost.sh [--dur 6] [--reps 3]
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
TEID=0xDEAD
RATES=(100000 300000)
PCAP=/tmp/bench2_$$.pcap
RAW="$BENCH_OUT/bench2_perpacket.tsv"
printf 'mode\tpps_offered\trep\tdelivered\tdur\tcpu_s_all\tcpu_per_pkt_all\tpct_cpu_all\tcpu_s_fwd\tcpu_per_pkt_fwd\tcycles_per_pkt\n' > "$RAW"

craft_gtp() { # smac dmac
  python3 - "$PCAP" "$1" "$2" "$TEID" <<'PY'
import struct,sys
from scapy.all import Ether,IP,UDP,Raw,wrpcap
pcap,smac,dmac,teid=sys.argv[1],sys.argv[2],sys.argv[3],int(sys.argv[4],0)
payload=bytes((i%256 for i in range(64)))
inner=bytes(IP(src="10.1.0.1",dst="10.1.0.2")/Raw(payload))
gtp=struct.pack("!BBHI",0x30,0xFF,len(inner),teid)
wrpcap(pcap, Ether(src=smac,dst=dmac)/IP(src="10.0.0.1",dst="10.0.0.2")/UDP(sport=2152,dport=2152)/Raw(gtp+inner))
PY
}

setup_mode() { # native|generic|plain -> sets GNB0/GNB1, crafts pcap
  local m="$1"
  if [[ "$m" == plain ]]; then
    XDP_MODE=generic TEID="$TEID" bash tools/setup_netns.sh --mode generic >/dev/null 2>&1
    "$GTP_CTRL" unload --iface veth-gnb1 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    iptables -C FORWARD -j ACCEPT 2>/dev/null || iptables -I FORWARD -j ACCEPT
    for i in all default veth-gnb1 veth-core0; do sysctl -w "net.ipv4.conf.$i.rp_filter=0" >/dev/null 2>&1 || true; done
    for i in all default veth-core1; do ip netns exec core sysctl -w "net.ipv4.conf.$i.rp_filter=0" >/dev/null 2>&1 || true; done
    ip netns exec core ip route replace 10.0.0.0/24 via 10.0.1.1 2>/dev/null || true
    ip netns exec gnb  ip route replace 10.0.1.0/24 via 10.0.0.2 2>/dev/null || true
  else
    XDP_MODE="$m" TEID="$TEID" bash tools/setup_netns.sh --mode "$m" >/dev/null 2>&1
    ip netns exec core ip link set dev veth-core1 xdpdrv obj "$PASS_OBJ" sec xdp 2>/dev/null || true
  fi
  GNB1=$(cat /sys/class/net/veth-gnb1/address)
  GNB0=$(ip netns exec gnb cat /sys/class/net/veth-gnb0/address)
  if [[ "$m" == plain ]]; then
    python3 - "$PCAP" "$GNB0" "$GNB1" <<'PY'
import sys
from scapy.all import Ether,IP,UDP,Raw,wrpcap
pcap,smac,dmac=sys.argv[1],sys.argv[2],sys.argv[3]
wrpcap(pcap, Ether(src=smac,dst=dmac)/IP(src="10.0.0.1",dst="10.0.1.2",ttl=64)/UDP(sport=4096,dport=9999)/Raw(bytes((i%256 for i in range(64)))))
PY
  else
    craft_gtp "$GNB0" "$GNB1"
  fi
}

perf_available && PERF_OK=1 || PERF_OK=0
echo "=================================================================="
echo " BENCH 2 - per-packet CPU cost: native XDP vs generic XDP vs plain"
echo "=================================================================="
echo " host: $(uname -r)  ncpu=$BENCH_NCPU  generator pinned to core $BENCH_GEN_CORE"
echo " held rates: ${RATES[*]} pps   duration: ${DUR}s   reps: $REPS"
echo " PMU: $PERF_NOTE"
echo " raw rows -> $RAW"
echo

for mode in native generic plain; do
  setup_mode "$mode"
  for pps in "${RATES[@]}"; do
    for r in $(seq 1 "$REPS"); do
      b0=$(core_rx); cpu_snap /tmp/b2_before
      cyc=""
      if [[ "$PERF_OK" == 1 ]]; then
        cyc=$(perf stat -a -e cycles -- bash -c "timeout $DUR ip netns exec gnb taskset -c $BENCH_GEN_CORE tcpreplay --pps $pps --loop 0 -i veth-gnb0 $PCAP >/dev/null 2>&1 || true" 2>&1 | awk '/cycles/{gsub(/,/,"",$1); print $1; exit}')
      else
        run_load "$PCAP" "$pps" "$DUR" gnb veth-gnb0
      fi
      cpu_snap /tmp/b2_after; sleep 0.2; b1=$(core_rx)
      delivered=$(( b1 - b0 ))
      read cpu_all pct_all <<<"$(cpu_busy_seconds /tmp/b2_before /tmp/b2_after "$DUR")"
      read cpu_fwd pct_fwd <<<"$(cpu_busy_seconds /tmp/b2_before /tmp/b2_after "$DUR" "$BENCH_GEN_CORE")"
      cpp_all=$(awk -v c="$cpu_all" -v d="$delivered" 'BEGIN{printf (d>0?"%.4e":"NA"), (d>0?c/d:0)}')
      cpp_fwd=$(awk -v c="$cpu_fwd" -v d="$delivered" 'BEGIN{printf (d>0?"%.4e":"NA"), (d>0?c/d:0)}')
      cpk=$(awk -v cy="${cyc:-0}" -v d="$delivered" 'BEGIN{printf (d>0 && cy>0?"%.1f":"NA"), (d>0 && cy>0?cy/d:0)}')
      printf '%s\t%s\t%s\t%s\t%s\t%.4f\t%s\t%.2f\t%.4f\t%s\t%s\n' \
        "$mode" "$pps" "$r" "$delivered" "$DUR" "$cpu_all" "$cpp_all" "$pct_all" "$cpu_fwd" "$cpp_fwd" "$cpk" >> "$RAW"
      printf '  [%-7s @%6s pps r%s] delivered=%8s  CPU/pkt(all)=%s s  %%CPU=%5.1f  CPU/pkt(fwd-only)=%s  cyc/pkt=%s\n' \
        "$mode" "$pps" "$r" "$delivered" "$cpp_all" "$pct_all" "$cpp_fwd" "$cpk"
    done
  done
done
rm -f "$PCAP" /tmp/b2_before /tmp/b2_after
"$GTP_CTRL" unload --iface veth-gnb1 >/dev/null 2>&1 || true
bash tools/teardown_netns.sh >/dev/null 2>&1 || true

echo
echo "==== SUMMARY (mean CPU-seconds/packet +/- CV%, n=$REPS per cell) ===="
python3 - "$RAW" <<'PY'
import statistics as st
from collections import defaultdict
rows=[l.rstrip('\n').split('\t') for l in open(__import__('sys').argv[1])][1:]
modes=['native','generic','plain']; rates=sorted({r[1] for r in rows},key=int)
def cv(v): m=st.mean(v); return m, (100*st.pstdev(v)/m if m else 0)
for col,lbl in [(6,'CPU-s/pkt (all cores)'),(9,'CPU-s/pkt (fwd cores only)')]:
    print(f"\n{lbl}:")
    print(f"  {'rate':>8} | " + " | ".join(f"{m:>22}" for m in modes))
    for rate in rates:
        cells=[]
        for m in modes:
            v=[float(r[col]) for r in rows if r[0]==m and r[1]==rate and r[col]!='NA']
            if v: mm,c=cv(v); cells.append(f"{mm:.3e}  CV{c:4.1f}%")
            else: cells.append("NA")
        print(f"  {rate:>8} | " + " | ".join(f"{c:>22}" for c in cells))
PY
