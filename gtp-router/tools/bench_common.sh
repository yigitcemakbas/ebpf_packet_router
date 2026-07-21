# tools/bench_common.sh
#
# Shared helpers for the benchmark suite (bench_upf_ab.sh, bench_perpacket_cost.sh,
# bench_selectivity_scaling.sh, bench_quarantine_reaction.sh). Sourced, not run.
#
# The whole suite follows ONE uniform CPU-cost method so every configuration's
# numbers are comparable:
#   * Offered load is HELD at a fixed rate BELOW the generator ceiling
#     (tcpreplay --pps), for a fixed duration - we measure cost at a held rate,
#     never the max-pps ceiling (which is generator-bound on this veth/VM rig
#     and cannot separate the modes).
#   * CPU is sampled from /proc/stat (summed over all cores) before/after each
#     run. CPU-busy-seconds = (1 - idle_delta/total_delta) * ncpu * dur. We then
#     report CPU-seconds-per-packet and %CPU. The SAME computation is used for
#     every configuration.
#   * The tcpreplay generator is pinned to its own core (taskset) so it does not
#     steal the forwarder's CPU. We also report a generator-core-excluded CPU
#     figure (all cores except the generator's) as a more sensitive view of the
#     forwarding cost alone - clearly labelled, secondary to the all-core metric.
#   * PMU: we try `perf stat -a` for cycles/packet; VMs frequently expose no PMU,
#     in which case perf reports <not supported> and we fall back to the
#     /proc/stat %CPU metric and say so in the output.

BENCH_NCPU="$(nproc)"
# Pin the generator to the last core; the forwarder/softirq work lands on the
# others. Reported in each script's header so the reader knows the layout.
BENCH_GEN_CORE="${BENCH_GEN_CORE:-$(( BENCH_NCPU - 1 ))}"
# Raw per-rep rows are written here for the user to re-aggregate/plot.
BENCH_OUT="${BENCH_OUT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scratchpad}"
mkdir -p "$BENCH_OUT" 2>/dev/null || true

# cpu_snap <file> - snapshot every /proc/stat cpu line (aggregate + per-core).
cpu_snap() { grep '^cpu' /proc/stat > "$1"; }

# cpu_busy_seconds <before> <after> <dur> [exclude_core] - CPU-busy-seconds over
# the interval. With no exclude_core, uses the aggregate "cpu" line (all cores,
# the primary metric). With exclude_core=N, sums per-core "cpuN" lines skipping
# core N (the generator's) - the forwarding-only view.
cpu_busy_seconds() {
  python3 - "$1" "$2" "$3" "${4:-}" "$BENCH_NCPU" <<'PY'
import sys
before,after,dur = sys.argv[1],sys.argv[2],float(sys.argv[3])
excl = sys.argv[4]; ncpu = int(sys.argv[5])
def load(fn):
    d={}
    for line in open(fn):
        f=line.split()
        if not f or not f[0].startswith('cpu'): continue
        vals=list(map(int,f[1:]))
        d[f[0]]=vals
    return d
b,a=load(before),load(after)
if excl == "":
    key='cpu'
    tot=sum(a[key])-sum(b[key])
    idle=(a[key][3]+a[key][4])-(b[key][3]+b[key][4])   # idle + iowait
    frac = 1 - idle/tot if tot else 0
    print("%.6f %.4f" % (frac*ncpu*dur, frac*100))
else:
    ex='cpu'+str(excl); tot=0; idle=0; keep=0
    for k in a:
        if k=='cpu' or k==ex: continue
        tot += sum(a[k])-sum(b[k]); idle += (a[k][3]+a[k][4])-(b[k][3]+b[k][4]); keep+=1
    frac = 1 - idle/tot if tot else 0
    # scale to keep cores worth of CPU-seconds
    print("%.6f %.4f" % (frac*keep*dur, frac*100))
PY
}

# mean_cv - reads one number per line on stdin, prints "mean cv%".
mean_cv() {
  awk '{v[NR]=$1; s+=$1} END{ if(NR==0){print "0 0"; exit} m=s/NR;
    for(i=1;i<=NR;i++){d=v[i]-m; ss+=d*d} sd=sqrt(ss/NR);
    printf "%.6g %.1f", m, (m!=0 ? 100*sd/m : 0) }'
}

# perf_available - 0 if `perf stat -a` yields real cycle counts, 1 otherwise.
# Sets PERF_NOTE describing what we found (printed once per script).
perf_available() {
  command -v perf >/dev/null 2>&1 || { PERF_NOTE="perf not installed"; return 1; }
  local out
  out=$(perf stat -a -e cycles -- sleep 0.2 2>&1)
  if echo "$out" | grep -qiE 'not supported|<not counted>|no permission|not allowed'; then
    PERF_NOTE="perf present but PMU unavailable on this VM ($(echo "$out" | grep -iE 'not supported|not counted|permission' | head -1 | tr -s ' ' | cut -c1-50)) - using /proc/stat %CPU"
    return 1
  fi
  if ! echo "$out" | grep -qE '[0-9,]+ +cycles'; then
    PERF_NOTE="perf produced no cycle count - using /proc/stat %CPU"
    return 1
  fi
  PERF_NOTE="perf PMU available (cycles counted)"
  return 0
}

# gtp counters at the uniform veth-core1 delivery point (synthetic rig).
core_rx() { ip netns exec core cat /sys/class/net/veth-core1/statistics/rx_packets 2>/dev/null || echo 0; }
iface_rx() { ip netns exec "$1" cat /sys/class/net/"$2"/statistics/rx_packets 2>/dev/null || echo 0; }

# run_load <pcap> <pps> <dur> <gen_netns> <gen_iface> - hold <pps> for <dur>s from
# <gen_netns>, generator pinned to BENCH_GEN_CORE.
run_load() {
  local pcap="$1" pps="$2" dur="$3" ns="$4" ifc="$5"
  timeout "$dur" ip netns exec "$ns" taskset -c "$BENCH_GEN_CORE" \
    tcpreplay --pps "$pps" --loop 0 -i "$ifc" "$pcap" >/dev/null 2>&1 || true
}
