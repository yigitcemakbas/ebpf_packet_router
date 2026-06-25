# Runs the end-to-end test for the GTP-U XDP router.
#
#   1. Sends N GTP-U packets from the gnb namespace into veth-gnb0
#   2. Captures what arrives on veth-core1 (inside the core namespace)
#   3. Checks that the captured packets are bare inner IP packets (no GTP-U)
#   4. Checks that the XDP REDIRECT counter incremented correctly
#   5. Prints PASS or FAIL with details

# Prerequisites:
#   - setup_netns.sh has been run
#   - scapy is installed (pip install scapy)
#   - tcpdump is installed
#
# Usage:
#   sudo bash tools/verify.sh [--teid 0xDEAD] [--count 20]

set -uo pipefail

TEID="${TEID:-0xDEAD}"
COUNT="${COUNT:-20}"
INNER_SRC="${INNER_SRC:-10.1.0.1}"
INNER_DST="${INNER_DST:-10.1.0.2}"
GTP_CTRL="${GTP_CTRL:-./build/gtp-ctrl}"
PASS=0
FAIL=0

# Parse flags
while [[ $# -gt 0 ]]; do
  case $1 in
    --teid)   TEID="$2";  shift 2 ;;
    --count)  COUNT="$2"; shift 2 ;;
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

echo
echo "══════════════════════════════════════════════════════"
echo " GTP-U XDP Router — End-to-End Verification"
echo "══════════════════════════════════════════════════════"
echo " TEID : $TEID"
echo " Count: $COUNT packets"
echo " Inner: $INNER_SRC → $INNER_DST"
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

if "$GTP_CTRL" list 2>/dev/null | grep -q "DECAP_FWD"; then
  ok "DECAP_FWD rule is present in teid_map"
else
  fail "No DECAP_FWD rule found. Run setup_netns.sh first"
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

# Read baseline stats 
echo "[ Reading baseline counters ]"
STATS_BEFORE=$("$GTP_CTRL" stats 2>/dev/null)
REDIRECT_BEFORE=$(echo "$STATS_BEFORE" | awk '/REDIRECT/{print $2}')
REDIRECT_BEFORE=${REDIRECT_BEFORE:-0}
info "REDIRECT counter before: $REDIRECT_BEFORE"
echo

# Start capture 
echo "[ Starting packet capture on veth-core1 ]"
PCAP_FILE="/tmp/gtp_verify_$$.pcap"
ip netns exec core tcpdump -i veth-core1 -nn -c "$COUNT" -w "$PCAP_FILE" \
  "ip src $INNER_SRC and ip dst $INNER_DST" &
TCPDUMP_PID=$!
sleep 0.5   # give tcpdump time to start listening
info "tcpdump PID $TCPDUMP_PID — capturing up to $COUNT packets"
echo

# Send GTP-U traffic 
echo "[ Sending $COUNT GTP-U packets from gnb namespace ]"
ip netns exec gnb python3 tools/gen_gtp_traffic.py \
  --iface   veth-gnb0 \
  --teid    "$TEID" \
  --src-ip  10.0.0.1 \
  --dst-ip  10.0.0.2 \
  --inner-src "$INNER_SRC" \
  --inner-dst "$INNER_DST" \
  --count   "$COUNT" \
  --pps     50
echo

info "Waiting for capture to complete..."
sleep 1
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
echo

# Analyse capture 
echo "[ Analysing capture ]"

if [[ ! -f "$PCAP_FILE" ]]; then
  fail "Capture file not created"
else
  CAPTURED=$(tcpdump -r "$PCAP_FILE" -nn 2>/dev/null | wc -l)
  info "Packets captured on veth-core1: $CAPTURED"

  if [[ "$CAPTURED" -gt 0 ]]; then
    ok "$CAPTURED inner IP packets arrived on veth-core1 (GTP-U decapsulated)"
  else
    fail "No packets captured on veth-core1 — decapsulation may not be working"
  fi

  # Check there is no GTP-U port in the captured traffic (i.e. it is decapsulated)
  GTP_PKTS=$(tcpdump -r "$PCAP_FILE" -nn "udp port 2152" 2>/dev/null | wc -l)
  if [[ "$GTP_PKTS" -eq 0 ]]; then
    ok "Captured packets contain no GTP-U encapsulation (port 2152 absent)"
  else
    fail "$GTP_PKTS captured packets still have GTP-U encapsulation"
  fi

  # Check captured packets are IPv4 with correct addresses
  CORRECT=$(tcpdump -r "$PCAP_FILE" -nn "ip src $INNER_SRC and ip dst $INNER_DST" 2>/dev/null | wc -l)
  if [[ "$CORRECT" -gt 0 ]]; then
    ok "Captured packets have correct inner addresses ($INNER_SRC → $INNER_DST)"
  else
    fail "Captured packets do not have expected inner addresses"
  fi

  rm -f "$PCAP_FILE"
fi

# Check stats counter 
echo
echo "[ Checking XDP stats ]"
sleep 0.3
STATS_AFTER=$("$GTP_CTRL" stats 2>/dev/null)
REDIRECT_AFTER=$(echo "$STATS_AFTER" | awk '/REDIRECT/{print $2}')
REDIRECT_AFTER=${REDIRECT_AFTER:-0}
REDIRECT_DELTA=$(( REDIRECT_AFTER - REDIRECT_BEFORE ))

info "REDIRECT counter after : $REDIRECT_AFTER"
info "REDIRECT counter delta : $REDIRECT_DELTA"

if [[ "$REDIRECT_DELTA" -gt 0 ]]; then
  ok "REDIRECT counter incremented by $REDIRECT_DELTA"
else
  fail "REDIRECT counter did not increment (delta=$REDIRECT_DELTA)"
fi

# Check per-rule counter
RULE_PKTS=$("$GTP_CTRL" list 2>/dev/null | awk '/DECAP_FWD/{print $6}' | head -1)
if [[ -n "$RULE_PKTS" && "$RULE_PKTS" -gt 0 ]]; then
  ok "Per-rule packet counter is $RULE_PKTS"
else
  fail "Per-rule packet counter is zero or unreadable"
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