# Runs the end-to-end downlink (ENCAP_FWD) test for the GTP-U XDP router.
#
#   1. Provisions an ENCAP_FWD rule in ueip_map for a UE IP (idempotent)
#   2. Sends N bare IP packets from the gnb namespace, destined to that UE IP
#   3. Captures what arrives on veth-core1 (inside the core namespace)
#   4. Checks that the captured packets are GTP-U encapsulated (outer IP/UDP
#      2152 + a GTP-U header carrying the expected TEID) wrapping the
#      original inner packet unchanged
#   5. Checks that the per-rule packet counter on the ueip_map entry
#      incremented correctly
#   6. Prints PASS or FAIL with details
#
# Prerequisites:
#   - setup_netns.sh has been run (provides the gnb/core namespaces + XDP)
#   - scapy is installed (pip install scapy)
#   - tcpdump is installed
#
# Usage:
#   sudo bash tools/verify_encap.sh [--ue-ip 10.1.0.2] [--teid-out 0xBEEF] [--count 20]

set -uo pipefail

UE_IP="${UE_IP:-10.1.0.2}"
TEID_OUT="${TEID_OUT:-0xBEEF}"
OUTER_SRC="${OUTER_SRC:-10.0.0.2}"
OUTER_DST="${OUTER_DST:-10.0.0.1}"
DL_SRC="${DL_SRC:-10.0.0.1}"
COUNT="${COUNT:-20}"
OUT_IFACE="${OUT_IFACE:-veth-core0}"
GTP_CTRL="${GTP_CTRL:-./build/gtp-ctrl}"
PASS=0
FAIL=0

# Parse flags
while [[ $# -gt 0 ]]; do
  case $1 in
    --ue-ip)    UE_IP="$2";     shift 2 ;;
    --teid-out) TEID_OUT="$2";  shift 2 ;;
    --count)    COUNT="$2";     shift 2 ;;
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
echo " GTP-U XDP Router — Downlink (ENCAP_FWD) Verification"
echo "══════════════════════════════════════════════════════"
echo " UE IP     : $UE_IP"
echo " TEID out  : $TEID_OUT"
echo " Outer     : $OUTER_SRC -> $OUTER_DST"
echo " Count     : $COUNT packets"
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

# Provision the ENCAP_FWD rule (idempotent — re-running just overwrites it)
echo "[ Provisioning ENCAP_FWD rule for $UE_IP ]"
CORE0_MAC=$(cat /sys/class/net/$OUT_IFACE/address)
GNB1_MAC=$(cat /sys/class/net/veth-gnb1/address)

"$GTP_CTRL" add-ueip \
  --ip "$UE_IP" \
  --action encap \
  --teid-out "$TEID_OUT" \
  --src-ip "$OUTER_SRC" \
  --dst-ip "$OUTER_DST" \
  --out-iface "$OUT_IFACE" \
  --dmac "$CORE0_MAC" \
  --smac "$GNB1_MAC" || { fail "add-ueip failed"; exit 1; }
echo

# Read baseline per-rule counter for this UE IP
RULE_BEFORE=$("$GTP_CTRL" list 2>/dev/null | awk -v ip="$UE_IP" '$1==ip{print $6}')
RULE_BEFORE=${RULE_BEFORE:-0}
info "Per-rule packet counter before: $RULE_BEFORE"
echo

# Start capture
echo "[ Starting packet capture on veth-core1 ]"
PCAP_FILE="/tmp/gtp_verify_encap_$$.pcap"
ip netns exec core tcpdump -i veth-core1 -nn -c "$COUNT" -w "$PCAP_FILE" \
  "ip src $OUTER_SRC and ip dst $OUTER_DST" &
TCPDUMP_PID=$!
sleep 0.5   # give tcpdump time to start listening
info "tcpdump PID $TCPDUMP_PID — capturing up to $COUNT packets"
echo

# Send downlink (bare IP) traffic toward the UE
echo "[ Sending $COUNT downlink packets from gnb namespace ]"
ip netns exec gnb python3 tools/gen_gtp_traffic.py \
  --iface     veth-gnb0 \
  --mode      downlink \
  --inner-src "$DL_SRC" \
  --inner-dst "$UE_IP" \
  --count     "$COUNT" \
  --pps       50
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
    ok "$CAPTURED packets arrived on veth-core1 (GTP-U encapsulated)"
  else
    fail "No packets captured on veth-core1 — encapsulation may not be working"
  fi

  # Check the encapsulated packets are UDP/2152 (the GTP-U envelope)
  GTP_PKTS=$(tcpdump -r "$PCAP_FILE" -nn "udp port 2152" 2>/dev/null | wc -l)
  if [[ "$GTP_PKTS" -eq "$CAPTURED" && "$CAPTURED" -gt 0 ]]; then
    ok "All captured packets carry a GTP-U envelope (UDP port 2152)"
  else
    fail "$GTP_PKTS/$CAPTURED captured packets carry a GTP-U envelope"
  fi

  rm -f "$PCAP_FILE"
fi

# Check per-rule counter
echo
echo "[ Checking per-rule counter ]"
sleep 0.3
RULE_AFTER=$("$GTP_CTRL" list 2>/dev/null | awk -v ip="$UE_IP" '$1==ip{print $6}')
RULE_AFTER=${RULE_AFTER:-0}
RULE_DELTA=$(( RULE_AFTER - RULE_BEFORE ))

info "Per-rule packet counter after : $RULE_AFTER"
info "Per-rule packet counter delta : $RULE_DELTA"

if [[ "$RULE_DELTA" -eq "$COUNT" ]]; then
  ok "Per-rule packet counter incremented by $RULE_DELTA"
else
  fail "Per-rule packet counter delta is $RULE_DELTA (expected $COUNT)"
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
