# Runs a synthetic multi-subscriber concurrency stress test for the GTP-U
# XDP router.
#
#   1. Provisions NUM_SUBS independent DECAP_FWD rules in teid_map, one per
#      simulated subscriber (distinct TEID + distinct inner UE IP each)
#   2. Sends COUNT_PER_SUB packets for every subscriber, interleaved
#      round-robin (not one subscriber at a time) to approximate real
#      concurrent traffic, at an aggregate rate of SEND_PPS
#   3. Captures what actually arrives on veth-core1 and checks the total
#      is close to what was sent
#   4. Reads every subscriber's own rule counter (`gtp-ctrl list`) and
#      checks each one is isolated: > 0 (no subscriber silently starved
#      or lost) and <= COUNT_PER_SUB (no subscriber's counter inflated by
#      another subscriber's traffic, i.e. no cross-rule leakage). A small
#      per-rule undercount is tolerated and reported, not failed on: the
#      packet/byte counters are intentionally non-atomic (see bump_rule()
#      in ebpf/gtp_xdp.c) and may undercount slightly under concurrent
#      multi-CPU traffic to the SAME rule - this script's job is to prove
#      rules stay isolated from EACH OTHER, not to re-litigate that
#      documented, accepted counter behavior.
#   5. Prints PASS or FAIL with details
#
# Prerequisites:
#   - setup_netns.sh has been run (provides the gnb/core namespaces + XDP)
#   - scapy is installed (pip install scapy)
#   - tcpdump is installed
#   - gawk (strtonum) for the counter-parsing pass below
#
# Usage:
#   sudo bash tools/verify_concurrency.sh [--num-subs 100] [--count-per-sub 10] [--pps 500]

set -uo pipefail

NUM_SUBS="${NUM_SUBS:-100}"
COUNT_PER_SUB="${COUNT_PER_SUB:-10}"
SEND_PPS="${SEND_PPS:-500}"
TEID_BASE="${TEID_BASE:-0x1000}"
INNER_DST_BASE="${INNER_DST_BASE:-10.2.0.1}"
OUT_IFACE="${OUT_IFACE:-veth-core0}"
GTP_CTRL="${GTP_CTRL:-./build/gtp-ctrl}"
# Tolerance for the documented non-atomic per-rule undercount (see header
# comment above) - a rule is considered healthy at or above this fraction
# of what was actually sent to it, not necessarily 100%.
UNDERCOUNT_TOLERANCE="${UNDERCOUNT_TOLERANCE:-0.90}"
PASS=0
FAIL=0

# Parse flags
while [[ $# -gt 0 ]]; do
  case $1 in
    --num-subs)       NUM_SUBS="$2";       shift 2 ;;
    --count-per-sub)  COUNT_PER_SUB="$2";  shift 2 ;;
    --pps)            SEND_PPS="$2";       shift 2 ;;
    --teid-base)      TEID_BASE="$2";      shift 2 ;;
    *) echo "Unknown flag: $1"; exit 1 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "error: must be run as root" >&2
  exit 1
fi

# Helpers
ok()   { echo "  [PASS] $*"; ((PASS++)); }
fail() { echo "  [FAIL] $*"; ((FAIL++)); }
info() { echo "  [info] $*"; }

TOTAL_SENT=$(( NUM_SUBS * COUNT_PER_SUB ))

echo
echo "══════════════════════════════════════════════════════"
echo " GTP-U XDP Router — Multi-Subscriber Concurrency Verification"
echo "══════════════════════════════════════════════════════"
echo " Subscribers    : $NUM_SUBS"
echo " Packets/sub    : $COUNT_PER_SUB (total: $TOTAL_SENT)"
echo " Aggregate PPS  : $SEND_PPS"
echo " TEID range     : $TEID_BASE .. 0x$(printf '%X' $(( TEID_BASE + NUM_SUBS - 1 )))"
echo " Inner dst base : $INNER_DST_BASE"
echo

echo "[ Prerequisite checks ]"

if ip netns list | grep -q "^gnb"; then
  ok "namespace 'gnb' exists"
else
  fail "namespace 'gnb' not found. Run setup_netns.sh first"
  exit 1
fi

if ip netns list | grep -q "^core"; then
  ok "namespace 'core' exists"
else
  fail "namespace 'core' not found. Run setup_netns.sh first"
  exit 1
fi

if ip link show veth-gnb1 2>/dev/null | grep -q "xdp"; then
  ok "XDP is attached to veth-gnb1"
else
  fail "XDP is not attached to veth-gnb1 - run setup_netns.sh first"
  exit 1
fi

if command -v tcpdump &>/dev/null; then
  ok "tcpdump is available"
else
  fail "tcpdump not found — install it: apt install tcpdump"
  exit 1
fi

if ip netns exec gnb python3 -c "import scapy" 2>/dev/null; then
  ok "scapy is available"
else
  fail "scapy not found. Install it: pip install scapy"
  exit 1
fi

if command -v gawk &>/dev/null; then
  ok "gawk is available (needed for strtonum in the counter-parsing pass)"
else
  fail "gawk not found — install it: apt install gawk"
  exit 1
fi

echo

# Provision NUM_SUBS independent rules, one per simulated subscriber.
# Re-running is idempotent: add-teid replaces a rule in full, including its
# counters, so every run starts every subscriber's counter at zero.
echo "[ Provisioning $NUM_SUBS independent teid_map rules ]"
CORE0_MAC=$(cat /sys/class/net/$OUT_IFACE/address)
GNB1_MAC=$(cat /sys/class/net/veth-gnb1/address)

PROVISION_FAILS=0
for (( i=0; i<NUM_SUBS; i++ )); do
  teid=$(( TEID_BASE + i ))
  "$GTP_CTRL" add-teid \
    --teid "0x$(printf '%X' "$teid")" \
    --action decap \
    --out-iface "$OUT_IFACE" \
    --dmac "$CORE0_MAC" \
    --smac "$GNB1_MAC" >/dev/null 2>&1 || PROVISION_FAILS=$((PROVISION_FAILS+1))
done

if [[ "$PROVISION_FAILS" -eq 0 ]]; then
  ok "provisioned all $NUM_SUBS rules"
else
  fail "$PROVISION_FAILS of $NUM_SUBS rules failed to provision"
fi
echo

# Start capture on the egress side, scoped to the inner-dst /16 this run
# uses (10.2.0.0/16 by default) so it only counts this test's traffic, not
# whatever else may be flowing through the topology.
INNER_NET="$(echo "$INNER_DST_BASE" | cut -d. -f1-2).0.0/16"
echo "[ Starting packet capture on veth-core1 (net $INNER_NET) ]"
PCAP_FILE="/tmp/gtp_verify_concurrency_$$.pcap"
ip netns exec core tcpdump -i veth-core1 -nn -c "$TOTAL_SENT" -w "$PCAP_FILE" \
  "net $INNER_NET" &
TCPDUMP_PID=$!
sleep 0.5
info "tcpdump PID $TCPDUMP_PID — capturing up to $TOTAL_SENT packets"
echo

# Send interleaved traffic across all NUM_SUBS subscribers at once.
echo "[ Sending $COUNT_PER_SUB packets x $NUM_SUBS subscribers, interleaved, at ${SEND_PPS}pps aggregate ]"
ip netns exec gnb python3 tools/gen_gtp_traffic.py \
  --iface veth-gnb0 \
  --src-ip 10.0.0.1 --dst-ip 10.0.0.2 \
  --inner-src 10.1.0.1 \
  --num-subscribers "$NUM_SUBS" \
  --teid-base "0x$(printf '%X' "$TEID_BASE")" \
  --inner-dst-base "$INNER_DST_BASE" \
  --count "$COUNT_PER_SUB" \
  --pps "$SEND_PPS"
echo

info "Waiting for capture to complete..."
sleep 1.5
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
echo

# Analyse the wire-level capture: an aggregate sanity check independent of
# any per-rule counter, same spirit as verify.sh/verify_ratelimit.sh.
echo "[ Analysing capture ]"
DELIVERED=0
if [[ ! -f "$PCAP_FILE" ]]; then
  fail "Capture file not created"
else
  DELIVERED=$(tcpdump -r "$PCAP_FILE" -nn 2>/dev/null | wc -l)
  info "Packets delivered to veth-core1: $DELIVERED / $TOTAL_SENT sent"

  DELIVER_FLOOR=$(awk -v t="$TOTAL_SENT" -v tol="$UNDERCOUNT_TOLERANCE" 'BEGIN{printf "%d", t*tol}')
  if [[ "$DELIVERED" -ge "$DELIVER_FLOOR" ]]; then
    ok "delivered ($DELIVERED) is within tolerance of sent ($TOTAL_SENT, floor $DELIVER_FLOOR)"
  else
    fail "delivered ($DELIVERED) is below tolerance of sent ($TOTAL_SENT, floor $DELIVER_FLOOR)"
  fi

  rm -f "$PCAP_FILE"
fi
echo

# Analyse per-rule isolation: every subscriber's own counter, read once via
# a single `gtp-ctrl list` capture (not NUM_SUBS separate invocations - this
# needs to stay fast at a few hundred subscribers).
echo "[ Checking per-subscriber rule isolation ]"
sleep 0.3
RULES_LIST=$("$GTP_CTRL" list 2>/dev/null)

# Single gawk pass (needs strtonum, not available in plain/mawk awk): for
# every teid_map row whose TEID falls in [TEID_BASE, TEID_BASE+NUM_SUBS-1],
# classify it against COUNT_PER_SUB. Prints: seen zero exceeds sum min max
SUMMARY=$(echo "$RULES_LIST" | gawk -v base="$TEID_BASE" -v n="$NUM_SUBS" -v cap="$COUNT_PER_SUB" '
  BEGIN { seen=0; zero=0; exceeds=0; sum=0; min=-1; max=-1; base=strtonum(base) }
  /^0x/ {
    teid = strtonum($1)
    if (teid >= base && teid < base + n) {
      pkts = $6 + 0
      seen++
      sum += pkts
      if (pkts == 0) zero++
      if (pkts > cap) exceeds++
      if (min == -1 || pkts < min) min = pkts
      if (max == -1 || pkts > max) max = pkts
    }
  }
  END { print seen, zero, exceeds, sum, min, max }
')
read -r SEEN ZERO EXCEEDS SUM MIN MAX <<< "$SUMMARY"

info "Rules seen for this range : $SEEN / $NUM_SUBS"
info "Rules with 0 packets      : $ZERO"
info "Rules exceeding cap ($COUNT_PER_SUB)   : $EXCEEDS"
info "Per-rule packet count     : min=$MIN max=$MAX sum=$SUM (expected sum=$TOTAL_SENT)"

if [[ "$SEEN" -eq "$NUM_SUBS" ]]; then
  ok "every provisioned rule ($NUM_SUBS) is present in teid_map"
else
  fail "only $SEEN of $NUM_SUBS provisioned rules found in teid_map"
fi

if [[ "$ZERO" -eq 0 ]]; then
  ok "no subscriber's rule was starved (0 rules stuck at zero packets)"
else
  fail "$ZERO subscriber(s) received zero packets - possible starvation or lookup miss"
fi

if [[ "$EXCEEDS" -eq 0 ]]; then
  ok "no subscriber's rule exceeded its own expected count ($COUNT_PER_SUB) - no cross-rule leakage"
else
  fail "$EXCEEDS subscriber(s) exceeded their own expected count - traffic leaked across rules"
fi

SUM_FLOOR=$(awk -v t="$TOTAL_SENT" -v tol="$UNDERCOUNT_TOLERANCE" 'BEGIN{printf "%d", t*tol}')
if [[ "$SUM" -ge "$SUM_FLOOR" ]]; then
  ok "aggregate rule counters ($SUM) are within tolerance of total sent ($TOTAL_SENT, floor $SUM_FLOOR)"
else
  fail "aggregate rule counters ($SUM) are below tolerance of total sent ($TOTAL_SENT, floor $SUM_FLOOR)"
fi

# Summary
echo
echo "══════════════════════════════════════════════════════"
TOTAL=$(( PASS + FAIL ))
if [[ $FAIL -eq 0 ]]; then
  echo " RESULT: PASS ($PASS/$TOTAL checks passed)"
else
  echo " RESULT: FAIL ($PASS/$TOTAL checks passed, $FAIL failed)"
fi
echo "══════════════════════════════════════════════════════"
echo

[[ $FAIL -eq 0 ]]
