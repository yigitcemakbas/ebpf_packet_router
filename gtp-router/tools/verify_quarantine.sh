# Runs the end-to-end autonomous quarantine test for the GTP-U XDP router.
#
#   1. Provisions a DECAP_FWD rule with --rate-pps, --quarantine-threshold,
#      and --quarantine-seconds (idempotent)
#   2. Floods it above the rate cap for long enough to accumulate
#      quarantine-threshold consecutive violated 1s windows
#   3. Checks `gtp-ctrl list`'s QUARANTINE column shows the rule as
#      quarantined
#   4. Sends a short probe burst well *below* the rate cap while still
#      quarantined and checks it is completely dropped - proving quarantine
#      is an absolute hard block, not just continued rate limiting
#   5. Waits for the quarantine to expire, sends one more packet (the event
#      that triggers self-release - there is no external poller), and
#      checks the rule is no longer quarantined
#   6. Prints PASS or FAIL with details
#
# Prerequisites:
#   - setup_netns.sh has been run (provides the gnb/core namespaces + XDP)
#   - scapy is installed (pip install scapy)
#   - tcpdump is installed
#
# Usage:
#   sudo bash tools/verify_quarantine.sh [--teid 0xBAD0] [--rate-pps 5] [--threshold 2] [--seconds 15]
#
# --seconds needs enough margin to outlast the flood + probe phases' own
# wall-clock overhead (~7-8s combined) - too short and the quarantine can
# expire mid-probe, which looks like a leak but is actually correct
# self-release timing colliding with the test's own slowness.

set -uo pipefail

TEID="${TEID:-0xBAD0}"
RATE_PPS="${RATE_PPS:-5}"
Q_THRESHOLD="${Q_THRESHOLD:-2}"
Q_SECONDS="${Q_SECONDS:-15}"
INNER_SRC="${INNER_SRC:-10.1.0.1}"
INNER_DST="${INNER_DST:-10.1.0.2}"
OUT_IFACE="${OUT_IFACE:-veth-core0}"
GTP_CTRL="${GTP_CTRL:-./build/gtp-ctrl}"
PASS=0
FAIL=0

# Parse flags
while [[ $# -gt 0 ]]; do
  case $1 in
    --teid)      TEID="$2";       shift 2 ;;
    --rate-pps)  RATE_PPS="$2";   shift 2 ;;
    --threshold) Q_THRESHOLD="$2";shift 2 ;;
    --seconds)   Q_SECONDS="$2";  shift 2 ;;
    *) echo "Unknown flag: $1"; exit 1 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "error: must be run as root" >&2
  exit 1
fi

# `gtp-ctrl list` always prints TEID zero-padded to 8 hex digits (0x%08X).
TEID_HEX=$(printf "0x%08X" "$((TEID))")

# Helpers
ok()   { echo "  [PASS] $*"; ((PASS++)); }
fail() { echo "  [FAIL] $*"; ((FAIL++)); }
info() { echo "  [info] $*"; }

# Returns the gtp-ctrl list row for $TEID_HEX, or empty if not found.
rule_row() { "$GTP_CTRL" list 2>/dev/null | grep "^$TEID_HEX"; }

# Sends $1 packets at $2 pps and returns how many were actually delivered to
# veth-core1 (captures for up to 2s past when sending should finish).
send_and_count() {
  local count="$1" pps="$2"
  local pcap="/tmp/gtp_verify_quarantine_$$.pcap"
  ip netns exec core tcpdump -i veth-core1 -nn -c "$count" -w "$pcap" \
    "ip src $INNER_SRC and ip dst $INNER_DST" &>/dev/null &
  local tdpid=$!
  sleep 0.3
  ip netns exec gnb python3 tools/gen_gtp_traffic.py \
    --iface veth-gnb0 --teid "$TEID" \
    --src-ip 10.0.0.1 --dst-ip 10.0.0.2 \
    --inner-src "$INNER_SRC" --inner-dst "$INNER_DST" \
    --count "$count" --pps "$pps" &>/dev/null
  sleep 1
  kill "$tdpid" 2>/dev/null || true
  wait "$tdpid" 2>/dev/null || true
  local delivered=0
  if [[ -f "$pcap" ]]; then
    delivered=$(tcpdump -r "$pcap" -nn 2>/dev/null | wc -l)
    rm -f "$pcap"
  fi
  echo "$delivered"
}

echo
echo "══════════════════════════════════════════════════════"
echo " GTP-U XDP Router — Autonomous Quarantine Verification"
echo "══════════════════════════════════════════════════════"
echo " TEID                 : $TEID"
echo " Rate cap              : $RATE_PPS pkt/s"
echo " Quarantine threshold  : $Q_THRESHOLD consecutive violated windows"
echo " Quarantine duration   : ${Q_SECONDS}s"
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

echo

# Provision (idempotent — re-running overwrites it, which also resets
# violation_streak/quarantine_until_ns for a clean run)
echo "[ Provisioning rule with auto-quarantine for TEID $TEID ]"
CORE0_MAC=$(cat /sys/class/net/$OUT_IFACE/address)
GNB1_MAC=$(cat /sys/class/net/veth-gnb1/address)

"$GTP_CTRL" add-teid \
  --teid "$TEID" \
  --action decap \
  --out-iface "$OUT_IFACE" \
  --dmac "$CORE0_MAC" \
  --smac "$GNB1_MAC" \
  --rate-pps "$RATE_PPS" \
  --quarantine-threshold "$Q_THRESHOLD" \
  --quarantine-seconds "$Q_SECONDS" || { fail "add-teid failed"; exit 1; }
echo

# Flood well above the cap for long enough to accumulate Q_THRESHOLD
# consecutive violated 1-second windows and trigger quarantine.
FLOOD_SECONDS=$(( Q_THRESHOLD + 1 ))
FLOOD_COUNT=$(( FLOOD_SECONDS * 20 ))
echo "[ Flooding at 20pps for ${FLOOD_SECONDS}s (cap is ${RATE_PPS}pps, threshold is $Q_THRESHOLD windows) ]"
FLOOD_DELIVERED=$(send_and_count "$FLOOD_COUNT" 20)
info "Delivered during flood: $FLOOD_DELIVERED / $FLOOD_COUNT sent"
echo

echo "[ Checking quarantine activated ]"
ROW=$(rule_row)
info "Rule row: $ROW"
if echo "$ROW" | grep -q "YES"; then
  ok "Rule is quarantined after sustained rate-limit violations"
else
  fail "Rule is not quarantined - expected QUARANTINE column to show YES"
fi
echo

# Probe well *below* the rate cap (1pps, easily within a 5pps cap) - if
# quarantine is a real hard block, this should be entirely dropped anyway.
echo "[ Probing at 1pps (well under the ${RATE_PPS}pps cap) while quarantined ]"
PROBE_DELIVERED=$(send_and_count 3 1)
info "Delivered during probe: $PROBE_DELIVERED / 3 sent"
if [[ "$PROBE_DELIVERED" -eq 0 ]]; then
  ok "Probe traffic was fully blocked despite being under the rate cap (quarantine is absolute)"
else
  fail "$PROBE_DELIVERED/3 probe packets got through - quarantine did not block traffic under the rate cap"
fi
echo

# Wait out the quarantine, then send one packet - the very next packet after
# the deadline is what triggers self-release; there is no external poller.
echo "[ Waiting ${Q_SECONDS}s for quarantine to expire, then sending one packet to trigger release ]"
sleep "$Q_SECONDS"
sleep 0.5
ip netns exec gnb python3 tools/gen_gtp_traffic.py \
  --iface veth-gnb0 --teid "$TEID" \
  --src-ip 10.0.0.1 --dst-ip 10.0.0.2 \
  --inner-src "$INNER_SRC" --inner-dst "$INNER_DST" \
  --count 1 --pps 1 &>/dev/null
sleep 0.3

ROW_AFTER=$(rule_row)
info "Rule row after release packet: $ROW_AFTER"
if echo "$ROW_AFTER" | grep -q "YES"; then
  fail "Rule is still showing as quarantined after the cooldown elapsed"
else
  ok "Rule self-released after the cooldown - no manual intervention needed"
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
