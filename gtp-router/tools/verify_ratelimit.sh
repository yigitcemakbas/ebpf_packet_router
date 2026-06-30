# Runs the end-to-end per-subscriber rate-limiting test for the GTP-U XDP
# router.
#
#   1. Provisions a DECAP_FWD rule in teid_map with --rate-pps set well below
#      the rate traffic will be sent at (idempotent)
#   2. Sends N GTP-U packets from the gnb namespace at a pps well above the
#      cap
#   3. Captures what actually arrives on veth-core1 - this should be fewer
#      packets than were sent, proving the cap is enforced in the XDP hook
#      itself, not just counted
#   4. Checks that the rule's RATE-DROPS counter (from `gtp-ctrl list`)
#      increased
#   5. Prints PASS or FAIL with details
#
# Prerequisites:
#   - setup_netns.sh has been run (provides the gnb/core namespaces + XDP)
#   - scapy is installed (pip install scapy)
#   - tcpdump is installed
#
# Usage:
#   sudo bash tools/verify_ratelimit.sh [--teid 0xCAFE] [--rate-pps 5] [--count 30] [--pps 20]

set -uo pipefail

TEID="${TEID:-0xCAFE}"
RATE_PPS="${RATE_PPS:-5}"
COUNT="${COUNT:-30}"
SEND_PPS="${SEND_PPS:-20}"
INNER_SRC="${INNER_SRC:-10.1.0.1}"
INNER_DST="${INNER_DST:-10.1.0.2}"
OUT_IFACE="${OUT_IFACE:-veth-core0}"
GTP_CTRL="${GTP_CTRL:-./build/gtp-ctrl}"
PASS=0
FAIL=0

# Parse flags
while [[ $# -gt 0 ]]; do
  case $1 in
    --teid)     TEID="$2";      shift 2 ;;
    --rate-pps) RATE_PPS="$2";  shift 2 ;;
    --count)    COUNT="$2";     shift 2 ;;
    --pps)      SEND_PPS="$2";  shift 2 ;;
    *) echo "Unknown flag: $1"; exit 1 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "error: must be run as root" >&2
  exit 1
fi

# `gtp-ctrl list` always prints TEID zero-padded to 8 hex digits (0x%08X),
# so normalize for awk comparisons below regardless of how --teid was given.
TEID_HEX=$(printf "0x%08X" "$((TEID))")

# Helpers
ok()   { echo "  [PASS] $*"; ((PASS++)); }
fail() { echo "  [FAIL] $*"; ((FAIL++)); }
info() { echo "  [info] $*"; }

# Looks up a named column's value from `gtp-ctrl list`'s table for the row
# whose first column equals $1, by header name rather than a fixed position.
# This script has been broken twice by position-based parsing (BYTES'
# "5.18 KB" used to shift later columns; then a new QUARANTINE column was
# appended after RATE-DROPS) - looking up by header name survives both
# kinds of change, as long as every column stays a single whitespace-free
# token (a project convention now, see control/maps/types.go's FormatBytes).
list_column() {
  local key="$1" col="$2"
  "$GTP_CTRL" list 2>/dev/null | awk -v key="$key" -v col="$col" '
    $1 == "TEID" || $1 == "UE-IP" {
      idx = 0
      for (i = 1; i <= NF; i++) if ($i == col) idx = i
      next
    }
    idx > 0 && $1 == key { print $idx }
  '
}

echo
echo "══════════════════════════════════════════════════════"
echo " GTP-U XDP Router — Per-Subscriber Rate Limit Verification"
echo "══════════════════════════════════════════════════════"
echo " TEID      : $TEID"
echo " Rate cap  : $RATE_PPS pkt/s"
echo " Send rate : $SEND_PPS pkt/s ($COUNT packets)"
echo " Inner     : $INNER_SRC -> $INNER_DST"
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

# Provision a rate-limited DECAP_FWD rule (idempotent — re-running overwrites it,
# which also resets window_count/rate_drop_count for a clean run)
echo "[ Provisioning rate-limited rule for TEID $TEID ]"
CORE0_MAC=$(cat /sys/class/net/$OUT_IFACE/address)
GNB1_MAC=$(cat /sys/class/net/veth-gnb1/address)

"$GTP_CTRL" add-teid \
  --teid "$TEID" \
  --action decap \
  --out-iface "$OUT_IFACE" \
  --dmac "$CORE0_MAC" \
  --smac "$GNB1_MAC" \
  --rate-pps "$RATE_PPS" || { fail "add-teid failed"; exit 1; }
echo

# Read baseline RATE-DROPS for this TEID.
DROPS_BEFORE=$(list_column "$TEID_HEX" "RATE-DROPS")
DROPS_BEFORE=${DROPS_BEFORE:-0}
info "RATE-DROPS before: $DROPS_BEFORE"
echo

# Start capture on the egress side - this counts packets that actually got
# through the cap, not just what was sent
echo "[ Starting packet capture on veth-core1 ]"
PCAP_FILE="/tmp/gtp_verify_ratelimit_$$.pcap"
ip netns exec core tcpdump -i veth-core1 -nn -c "$COUNT" -w "$PCAP_FILE" \
  "ip src $INNER_SRC and ip dst $INNER_DST" &
TCPDUMP_PID=$!
sleep 0.5   # give tcpdump time to start listening
info "tcpdump PID $TCPDUMP_PID — capturing up to $COUNT packets"
echo

# Send GTP-U traffic well above the configured cap
echo "[ Sending $COUNT GTP-U packets at ${SEND_PPS}pps (cap is ${RATE_PPS}pps) ]"
ip netns exec gnb python3 tools/gen_gtp_traffic.py \
  --iface     veth-gnb0 \
  --teid      "$TEID" \
  --src-ip    10.0.0.1 \
  --dst-ip    10.0.0.2 \
  --inner-src "$INNER_SRC" \
  --inner-dst "$INNER_DST" \
  --count     "$COUNT" \
  --pps       "$SEND_PPS"
echo

info "Waiting for capture to complete..."
sleep 1.5
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
echo

# Analyse capture
echo "[ Analysing capture ]"

DELIVERED=0
if [[ ! -f "$PCAP_FILE" ]]; then
  fail "Capture file not created"
else
  DELIVERED=$(tcpdump -r "$PCAP_FILE" -nn 2>/dev/null | wc -l)
  info "Packets delivered to veth-core1: $DELIVERED / $COUNT sent"

  if [[ "$DELIVERED" -lt "$COUNT" ]]; then
    ok "Fewer packets were delivered ($DELIVERED) than sent ($COUNT) — the cap dropped excess traffic"
  else
    fail "All $COUNT sent packets were delivered — rate cap had no effect"
  fi

  rm -f "$PCAP_FILE"
fi

# Check the rule's RATE-DROPS counter
echo
echo "[ Checking RATE-DROPS counter ]"
sleep 0.3
DROPS_AFTER=$(list_column "$TEID_HEX" "RATE-DROPS")
DROPS_AFTER=${DROPS_AFTER:-0}
DROPS_DELTA=$(( DROPS_AFTER - DROPS_BEFORE ))

info "RATE-DROPS after : $DROPS_AFTER"
info "RATE-DROPS delta : $DROPS_DELTA"

if [[ "$DROPS_DELTA" -gt 0 ]]; then
  ok "RATE-DROPS increased by $DROPS_DELTA"
else
  fail "RATE-DROPS did not increase (delta=$DROPS_DELTA)"
fi

# Cross-check: delivered + dropped should roughly equal sent (allowing for
# background noise / minor timing slack, not an exact match)
echo
TOTAL_ACCOUNTED=$(( DELIVERED + DROPS_DELTA ))
info "Delivered ($DELIVERED) + dropped ($DROPS_DELTA) = $TOTAL_ACCOUNTED (sent: $COUNT)"

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
