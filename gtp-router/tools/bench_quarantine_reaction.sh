#!/usr/bin/env bash
# tools/bench_quarantine_reaction.sh  -  BENCH 4 of the suite.
#
# Autonomous in-kernel quarantine: closed-loop reaction with ZERO control-plane
# involvement. A rule carries --rate-pps + --quarantine-threshold + --quarantine-
# seconds. Under sustained over-cap traffic the XDP program itself (in the data
# path, per packet, using bpf_ktime) hard-blocks the subscriber after the
# threshold windows, and self-releases after the cooldown - no userspace poller,
# cron, or daemon acts in between.
#
# We measure two wall-clock latencies over >=3 reps (mean + CV):
#   * REACTION : first over-cap traffic -> subscriber hard-blocked (packets stop
#                reaching veth-core1). Bounded by the threshold windows.
#   * RELEASE  : quarantine cooldown deadline -> traffic flowing again (triggered
#                by the next packet in the XDP hook, not by any external timer).
#
# Self-contained; root required.
#   sudo bash tools/bench_quarantine_reaction.sh [--reps 3] [--rate 5000] [--threshold 3] [--seconds 8]
set -uo pipefail
cd "$(dirname "$0")/.."
source tools/bench_common.sh

REPS=3; RATE=5000; THR=3; SECS=8; HELD=100000
while [[ $# -gt 0 ]]; do case $1 in
  --reps) REPS="$2"; shift 2;; --rate) RATE="$2"; shift 2;;
  --threshold) THR="$2"; shift 2;; --seconds) SECS="$2"; shift 2;;
  *) echo "unknown arg: $1" >&2; exit 1;; esac; done
[[ $EUID -eq 0 ]] || { echo "error: run as root" >&2; exit 1; }

GTP_CTRL=./build/gtp-ctrl
PASS_OBJ=build/xdp_pass.o
TEID=0x0000cafe
RAW="$BENCH_OUT/bench4_quarantine.tsv"
printf 'rep\treaction_s\trelease_s\tquarantine_confirmed\tno_userspace_actor\n' > "$RAW"

XDP_MODE=native bash tools/setup_netns.sh --mode native >/dev/null 2>&1
ip netns exec core ip link set dev veth-core1 xdpdrv obj "$PASS_OBJ" sec xdp 2>/dev/null || true
GNB1=$(cat /sys/class/net/veth-gnb1/address); GNB0=$(ip netns exec gnb cat /sys/class/net/veth-gnb0/address)
CORE0_MAC=$(cat /sys/class/net/veth-core0/address)
PCAP=/tmp/b4_$$.pcap
python3 - "$PCAP" "$GNB0" "$GNB1" "$TEID" <<'PY'
import struct,sys
from scapy.all import Ether,IP,UDP,Raw,wrpcap
pcap,smac,dmac,teid=sys.argv[1],sys.argv[2],sys.argv[3],int(sys.argv[4],0)
inner=bytes(IP(src="10.1.0.1",dst="10.1.0.2")/Raw(bytes((i%256 for i in range(64)))))
gtp=struct.pack("!BBHI",0x30,0xFF,len(inner),teid)
wrpcap(pcap, Ether(src=smac,dst=dmac)/IP(src="10.0.0.1",dst="10.0.0.2")/UDP(sport=2152,dport=2152)/Raw(gtp+inner))
PY

qstate() { "$GTP_CTRL" list 2>/dev/null | awk -v t="$TEID" 'tolower($1)==tolower(t){print $10}'; }
now() { date +%s.%N; }

echo "=================================================================="
echo " BENCH 4 - autonomous in-kernel quarantine reaction time"
echo "=================================================================="
echo " cap=${RATE}pps  threshold=${THR} windows  cooldown=${SECS}s  drive=${HELD}pps"
echo " host: $(uname -r)   raw -> $RAW"
echo " (no cron/poller/daemon runs; the XDP hook decides per-packet)"
echo

# Confirm there is no userspace actor: nothing gtp/pfcp is polling the maps.
USERSPACE_ACTORS=$(pgrep -af 'pfcp-serve|gtp-ctrl (dashboard|stats)' | grep -v "$$" | wc -l)

for rep in $(seq 1 "$REPS"); do
  # fresh rule each rep -> resets counters + any prior quarantine state
  "$GTP_CTRL" del-teid --teid "$TEID" >/dev/null 2>&1 || true
  "$GTP_CTRL" add-teid --teid "$TEID" --action decap --out-iface veth-core0 \
    --dmac "$CORE0_MAC" --smac "$GNB1" \
    --rate-pps "$RATE" --quarantine-threshold "$THR" --quarantine-seconds "$SECS" >/dev/null 2>&1

  # start sustained over-cap traffic in the background for the whole rep
  ( timeout 40 ip netns exec gnb taskset -c "$BENCH_GEN_CORE" \
      tcpreplay --pps "$HELD" --loop 0 -i veth-gnb0 "$PCAP" >/dev/null 2>&1 ) &
  drv=$!
  t0=$(now)

  # --- detect hard-block: per-poll delivered delta collapses to ~0 ---
  reaction="NA"; qconf=0; prev=$(core_rx); zero=0
  for _ in $(seq 1 100); do          # up to ~20s
    sleep 0.2
    cur=$(core_rx); d=$(( cur - prev )); prev=$cur
    [[ "$(qstate)" == YES* ]] && qconf=1
    if (( qconf==1 && d < 50 )); then
      # confirm it stays blocked (two consecutive ~0 windows)
      zero=$((zero+1))
      if (( zero >= 2 )); then reaction=$(awk -v a="$t0" -v b="$(now)" 'BEGIN{printf "%.2f", b-a-0.4}'); break; fi
    else
      zero=0
    fi
  done

  # --- detect self-release: after the cooldown, delivered climbs again ---
  release="NA"
  if [[ "$reaction" != NA ]]; then
    tq=$(now)                         # ~moment of block; deadline ~ tq+SECS
    prev=$(core_rx)
    for _ in $(seq 1 $(( (SECS+8)*5 )) ); do
      sleep 0.2
      cur=$(core_rx); d=$(( cur - prev )); prev=$cur
      if (( d > 200 )); then          # traffic flowing again
        elapsed=$(awk -v a="$tq" -v b="$(now)" 'BEGIN{printf "%.2f", b-a}')
        # release latency = time past the cooldown deadline (elapsed - SECS)
        release=$(awk -v e="$elapsed" -v s="$SECS" 'BEGIN{r=e-s; printf "%.2f", (r>0?r:0)}')
        break
      fi
    done
  fi

  kill "$drv" 2>/dev/null; wait "$drv" 2>/dev/null
  no_actor=$([[ "$USERSPACE_ACTORS" -eq 0 ]] && echo yes || echo no)
  printf '%s\t%s\t%s\t%s\t%s\n' "$rep" "$reaction" "$release" "$([[ $qconf -eq 1 ]] && echo yes || echo no)" "$no_actor" >> "$RAW"
  printf '  rep %s: REACTION=%ss (block after ~%s windows)   RELEASE=+%ss past %ss cooldown   quarantine-column-confirmed=%s\n' \
    "$rep" "$reaction" "$THR" "$release" "$SECS" "$([[ $qconf -eq 1 ]] && echo YES || echo no)"
  sleep 1
done

rm -f "$PCAP"
"$GTP_CTRL" unload --iface veth-gnb1 >/dev/null 2>&1 || true
bash tools/teardown_netns.sh >/dev/null 2>&1 || true

echo
echo "==== SUMMARY (mean +/- CV, n=$REPS) ===="
python3 - "$RAW" <<'PY'
import statistics as st, sys
rows=[l.rstrip().split('\t') for l in open(sys.argv[1])][1:]
for col,lbl in [(1,'reaction (s)'),(2,'release past cooldown (s)')]:
    v=[float(r[col]) for r in rows if r[col] not in ('NA','')]
    if v:
        m=st.mean(v); cv=100*st.pstdev(v)/m if m else 0
        print(f"  {lbl:<28}: mean={m:.2f}  CV={cv:.1f}%  (n={len(v)})")
    else:
        print(f"  {lbl:<28}: no data")
print("  userspace actor during test: " + ("NONE (autonomous)" if all(r[4]=='yes' for r in rows) else "present"))
PY
