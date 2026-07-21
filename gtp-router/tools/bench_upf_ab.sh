#!/usr/bin/env bash
# tools/bench_upf_ab.sh  -  BENCH 1 (headline) of the suite.
#
# The comparison that matters: the SAME real GTP-U UPF job done by our in-kernel
# pre-sk_buff XDP data plane vs. Open5GS's own reference userspace UPF
# (open5gs-upfd). A clean A/B on the live lab, because our XDP program on
# veth-ran sees N3 packets BEFORE upfd's socket:
#   Config A (baseline): no teid_map rule for the UE -> the packet XDP_PASSes and
#                        open5gs-upfd (userspace) decaps/forwards it.
#   Config B (router)  : provision the decap+NAT rule -> our XDP router forwards
#                        it pre-stack; upfd never sees it.
# Same UE, same held offered load, only the rule differs. We report, for A and B:
#   * total-system CPU-seconds per forwarded packet (uniform /proc/stat method)
#   * end-to-end tail latency p50/p95/p99 from a real RTT probe (UE pings the peer
#     through the tunnel - the lab's full duplex path) UNDER the background load.
#
# This does NOT need the PFCP/F-TEID fix: the rule install/remove A/B works in the
# normal manual-provisioning lab, where upfd is running.
#
# LOAD NOTE: replayed (tcpreplay) GTP-U frames do NOT traverse upfd - it processes
# only live-session traffic and drops byte-identical replays (we verified upfd
# decapped 1 of ~38000 replayed frames). So the held load here is REAL UE traffic
# from a paced UDP sender bound to uesimtun0 (both configs forward it identically),
# at rates below the ~176k pps upfd ceiling. Generator pinned to its own core.
#
# PREREQUISITE: the manual lab must be up (sudo bash tools/lab.sh), UE attached,
# router loaded native on veth-ran + veth-inet0, open5gs-upfd running.
#   sudo bash tools/bench_upf_ab.sh [--dur 6] [--reps 3]
set -uo pipefail
cd "$(dirname "$0")/.."
source tools/bench_common.sh

DUR=6; REPS=3; RATES=(50000 100000)
while [[ $# -gt 0 ]]; do case $1 in
  --dur) DUR="$2"; shift 2;; --reps) REPS="$2"; shift 2;;
  *) echo "unknown arg: $1" >&2; exit 1;; esac; done
[[ $EUID -eq 0 ]] || { echo "error: run as root" >&2; exit 1; }
GTP_CTRL=./build/gtp-ctrl
PEER=10.99.0.2; STATE=/tmp/gtp-lab-ues.tsv

# --- prerequisites ---
ip netns list 2>/dev/null | grep -q '^ran' || { echo "error: netns 'ran' absent - bring up the lab: sudo bash tools/lab.sh" >&2; exit 1; }
UEIP=$(ip netns exec ran ip -4 -o addr show uesimtun0 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
[[ -n "$UEIP" ]] || { echo "error: uesimtun0 has no IP - is the UE attached?" >&2; exit 1; }
pgrep -f open5gs-upfd >/dev/null || { echo "error: open5gs-upfd not running - Config A needs the reference UPF" >&2; exit 1; }
ip link show veth-ran 2>/dev/null | grep -q 'xdp' || { echo "error: router not loaded on veth-ran" >&2; exit 1; }
[[ -f "$STATE" ]] || { echo "error: $STATE missing - run the lab's provisioning once" >&2; exit 1; }
read -r _ _ SUEIP ULTEID DLTEID NATIP < <(awk -F'\t' '$1==0{print}' "$STATE")
[[ "$SUEIP" == "$UEIP" ]] || echo "  note: state UEIP($SUEIP) != live($UEIP); using live rule params below"

# paced real-UE UDP sender, bound to uesimtun0 (SO_BINDTODEVICE) - generates real
# uplink traffic through the live gNB->N3 path (what upfd/router actually forward).
UE_SEND=/tmp/ue_send_$$.py
cat > "$UE_SEND" <<'PY'
import socket,sys,time
dur=float(sys.argv[1]); target=sys.argv[2]; pps=float(sys.argv[3]) if len(sys.argv)>3 and sys.argv[3]!='max' else 0
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,25,b"uesimtun0")
msg=bytes(64); end=time.time()+dur; n=0
interval=(1.0/pps) if pps>0 else 0; nxt=time.time()
while time.time()<end:
    try: s.sendto(msg,(target,9999)); n+=1
    except OSError: pass
    if interval:
        nxt+=interval; d=nxt-time.time()
        if d>0: time.sleep(d)
print(n)
PY

VINET0_MAC=$(cat /sys/class/net/veth-inet0/address); VINET1_MAC=$(ip netns exec inet cat /sys/class/net/veth-inet1/address)
VRAN_MAC=$(cat /sys/class/net/veth-ran/address);     VRANNS_MAC=$(ip netns exec ran cat /sys/class/net/veth-ran-ns/address)

config_A() { "$GTP_CTRL" del-teid --teid "$ULTEID" >/dev/null 2>&1 || true; "$GTP_CTRL" del-nat --nat-ip "$NATIP" >/dev/null 2>&1 || true; }
config_B() {
  "$GTP_CTRL" add-teid --teid "$ULTEID" --action decap --out-iface veth-inet0 --dmac "$VINET1_MAC" --smac "$VINET0_MAC" --nat-ip "$NATIP" >/dev/null 2>&1
  "$GTP_CTRL" add-nat --nat-ip "$NATIP" --ue-ip "$UEIP" --teid-out "$DLTEID" --src-ip 10.201.0.1 --dst-ip 10.201.0.2 --out-iface veth-ran --dmac "$VRANNS_MAC" --smac "$VRAN_MAC" >/dev/null 2>&1
}
vinet1_rx() { ip netns exec inet cat /sys/class/net/veth-inet1/statistics/rx_packets 2>/dev/null || echo 0; }

RAW="$BENCH_OUT/bench1_upf_ab.tsv"
printf 'config\tpps\trep\tdelivered\tcpu_s_all\tcpu_per_pkt\tpct_cpu\tlat_p50\tlat_p95\tlat_p99\tlat_max\n' > "$RAW"

echo "=================================================================="
echo " BENCH 1 (HEADLINE) - XDP router vs open5gs-upfd (reference UPF)"
echo "=================================================================="
echo " UE=$UEIP  uplinkTEID=$ULTEID  NAT=$NATIP  peer=$PEER"
echo " held rates: ${RATES[*]} pps (real UE traffic)  dur=${DUR}s  reps=$REPS"
echo " host: $(uname -r)  ncpu=$BENCH_NCPU  generator pinned to core $BENCH_GEN_CORE"
echo " raw -> $RAW"

run_cell() { # config_label pps rep
  local cfg="$1" pps="$2" rep="$3"
  local latfile=/tmp/b1_lat_$$.txt
  local b0 b1 delivered
  b0=$(vinet1_rx); cpu_snap /tmp/b1_before
  # background real-UE load, pinned to the generator core
  ip netns exec ran taskset -c "$BENCH_GEN_CORE" python3 $UE_SEND "$DUR" "$PEER" "$pps" >/dev/null 2>&1 &
  local gen=$!
  # concurrent latency probe: UE pings the peer through the tunnel (duplex path)
  ip netns exec ran ping -I uesimtun0 -c $(( DUR*50 )) -i 0.02 -W 1 "$PEER" > "$latfile" 2>/dev/null &
  local png=$!
  wait "$gen" 2>/dev/null
  cpu_snap /tmp/b1_after; b1=$(vinet1_rx); delivered=$(( b1 - b0 ))
  wait "$png" 2>/dev/null
  read cpu_all pct <<<"$(cpu_busy_seconds /tmp/b1_before /tmp/b1_after "$DUR")"
  local cpp; cpp=$(awk -v c="$cpu_all" -v d="$delivered" 'BEGIN{printf (d>0?"%.4e":"NA"),(d>0?c/d:0)}')
  # latency percentiles from the ping RTTs
  read p50 p95 p99 pmax <<<"$(grep -oE 'time=[0-9.]+' "$latfile" | cut -d= -f2 | python3 -c '
import sys
v=sorted(float(x) for x in sys.stdin)
def pc(p):
    if not v: return float("nan")
    import math; return v[min(len(v)-1, int(math.ceil(p/100*len(v)))-1)]
print("%.3f %.3f %.3f %.3f"%(pc(50),pc(95),pc(99),(v[-1] if v else float("nan"))) )')"
  printf '%s\t%s\t%s\t%s\t%.4f\t%s\t%.2f\t%s\t%s\t%s\t%s\n' "$cfg" "$pps" "$rep" "$delivered" "$cpu_all" "$cpp" "$pct" "$p50" "$p95" "$p99" "$pmax" >> "$RAW"
  printf '  [%s @%6s r%s] delivered=%7s CPU/pkt=%s %%CPU=%5.1f  lat p50/p95/p99=%s/%s/%s ms (max %s)\n' \
    "$cfg" "$pps" "$rep" "$delivered" "$cpp" "$pct" "$p50" "$p95" "$p99" "$pmax"
  rm -f "$latfile"
}

for pps in "${RATES[@]}"; do
  echo; echo "---- held offered load: $pps pps ----"
  for rep in $(seq 1 "$REPS"); do
    config_A; sleep 0.5; run_cell "A_upfd " "$pps" "$rep"
    config_B; sleep 0.5; run_cell "B_xdp  " "$pps" "$rep"
  done
done
config_B  # leave the lab in the router-provisioned state
rm -f /tmp/b1_before /tmp/b1_after "$UE_SEND"

echo
echo "==== SUMMARY (mean over $REPS reps) ===="
python3 - "$RAW" <<'PY'
import statistics as st, sys
rows=[l.rstrip().split('\t') for l in open(sys.argv[1])][1:]
rates=sorted({r[1] for r in rows},key=int)
def agg(cfg,rate,col):
    v=[float(r[col]) for r in rows if r[0].strip()==cfg and r[1]==rate and r[col] not in ('NA','nan','')]
    if not v: return None
    m=st.mean(v); cv=100*st.pstdev(v)/m if m else 0; return m,cv
for rate in rates:
    print(f"\n  @ {rate} pps:")
    print(f"    {'metric':<26} {'A (upfd)':>16} {'B (xdp)':>16}   ratio A/B")
    for col,lbl,unit in [(5,'CPU-s per packet','s'),(6,'%CPU (avg cores)','%'),(7,'latency p50','ms'),(8,'latency p95','ms'),(9,'latency p99','ms'),(10,'latency max','ms')]:
        a=agg('A_upfd',rate,col); b=agg('B_xdp',rate,col)
        if a and b:
            ratio = a[0]/b[0] if b[0] else float('inf')
            av = f"{a[0]:.3e}" if col==5 else f"{a[0]:.2f}"
            bv = f"{b[0]:.3e}" if col==5 else f"{b[0]:.2f}"
            print(f"    {lbl:<26} {av:>16} {bv:>16}   {ratio:>6.2f}x")
PY
