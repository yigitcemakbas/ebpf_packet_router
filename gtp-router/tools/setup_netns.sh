#!/usr/bin/env bash
# tools/setup_netns.sh
#
# Creates a two-namespace test topology and attaches the XDP router.


#   gNB side sends GTP-U to 10.0.0.2 (veth-gnb1 = the XDP interface).
#   XDP decapsulates and bpf_redirects the inner IP packet to veth-core0.
#   The inner packet exits on veth-core1 inside the 'core' namespace.

# Usage:
#   sudo bash tools/setup_netns.sh [--teid 0xDEAD] [--inner-dst 10.1.0.2]


# Defaults:
#   TEID      = 0xDEAD
#   inner dst = 10.1.0.2  (the UE IP the rule will match on)
#   inner src = 10.1.0.1

set -euo pipefail

TEID="${TEID:-0xDEAD}"
INNER_SRC="${INNER_SRC:-10.1.0.1}"
INNER_DST="${INNER_DST:-10.1.0.2}"
XDP_MODE="${XDP_MODE:-generic}"
GTP_CTRL="${GTP_CTRL:-./build/gtp-ctrl}"

# Parse flags
while [[ $# -gt 0 ]]; do
  case $1 in
    --teid)       TEID="$2";       shift 2 ;;
    --inner-dst)  INNER_DST="$2"; shift 2 ;;
    --inner-src)  INNER_SRC="$2"; shift 2 ;;
    --mode)       XDP_MODE="$2";  shift 2 ;;
    *) echo "Unknown flag: $1"; exit 1 ;;
  esac
done

# Require root 
if [[ $EUID -ne 0 ]]; then
  echo "error: must be run as root" >&2
  exit 1
fi

# Require the binary 
if [[ ! -x "$GTP_CTRL" ]]; then
  echo "error: $GTP_CTRL not found — run 'make' first" >&2
  exit 1
fi

echo "[setup] Kernel: $(uname -r)"
echo "[setup] TEID: $TEID  inner: $INNER_SRC -> $INNER_DST  mode: $XDP_MODE"
echo

# Tear down any previous run 
echo "[1/7] Cleaning up any previous state..."
ip netns del gnb  2>/dev/null || true
ip netns del core 2>/dev/null || true
ip link del veth-gnb0  2>/dev/null || true
ip link del veth-core0 2>/dev/null || true
"$GTP_CTRL" unload --iface veth-gnb1 2>/dev/null || true
sleep 0.3

echo "[2/7] Creating network namespaces (gnb, core)..."
ip netns add gnb
ip netns add core

echo "[3/7] Creating veth pairs..."
ip link add veth-gnb0 type veth peer name veth-gnb1
ip link set veth-gnb0 netns gnb

# Core side: veth-core0 
ip link add veth-core0 type veth peer name veth-core1
ip link set veth-core1 netns core

# Assign addresses and bring interfaces up 
echo "[4/7] Configuring addresses..."

# gnb namespace
ip netns exec gnb ip addr add 10.0.0.1/24 dev veth-gnb0
ip netns exec gnb ip link set veth-gnb0 up
ip netns exec gnb ip link set lo up

# default namespace
ip addr add 10.0.0.2/24 dev veth-gnb1
ip addr add 10.0.1.1/24 dev veth-core0
ip link set veth-gnb1 up
ip link set veth-core0 up

# core namespace
ip netns exec core ip addr add 10.0.1.2/24 dev veth-core1
ip netns exec core ip link set veth-core1 up
ip netns exec core ip link set lo up

# Disable checksum and TX offloads on veth interfaces 
# veth drivers in generic XDP mode need offloads disabled to avoid
# checksum issues with crafted packets from Scapy.
echo "[5/7] Disabling offloads..."
for iface in veth-gnb0 veth-gnb1 veth-core0 veth-core1; do
  ethtool -K "$iface" tx off rx off gso off gro off 2>/dev/null || true
done
ip netns exec gnb  ethtool -K veth-gnb0  tx off rx off gso off gro off 2>/dev/null || true
ip netns exec core ethtool -K veth-core1 tx off rx off gso off gro off 2>/dev/null || true

# Load the XDP program 
echo "[6/7] Loading XDP program on veth-gnb1..."
"$GTP_CTRL" load --iface veth-gnb1 --mode "$XDP_MODE"

echo "[7/7] Inserting DECAP_FWD rule..."

# Get the MAC addresses of the next-hop interfaces
CORE0_MAC=$(cat /sys/class/net/veth-core0/address)
GNB1_MAC=$(cat /sys/class/net/veth-gnb1/address)

"$GTP_CTRL" add-teid \
  --teid   "$TEID" \
  --action decap \
  --out-iface veth-core0 \
  --dmac   "$CORE0_MAC" \
  --smac   "$GNB1_MAC"

echo
echo "══════════════════════════════════════════════════════"
echo " Test environment ready"
echo "══════════════════════════════════════════════════════"
echo
echo " XDP attached to : veth-gnb1 (10.0.0.2)"
echo " Egress interface: veth-core0 -> veth-core1 (10.0.1.2)"
echo " Rule TEID       : $TEID"
echo " Inner traffic   : $INNER_SRC -> $INNER_DST"
echo
echo " Active rules:"
"$GTP_CTRL" list
echo
echo " To send test traffic (in a new terminal):"
echo
echo "   sudo ip netns exec gnb python3 tools/gen_gtp_traffic.py \\"
echo "     --iface veth-gnb0 \\"
echo "     --teid $TEID \\"
echo "     --src-ip 10.0.0.1 \\"
echo "     --dst-ip 10.0.0.2 \\"
echo "     --inner-src $INNER_SRC \\"
echo "     --inner-dst $INNER_DST \\"
echo "     --count 20 --pps 5"
echo
echo " To capture on the egress side:"
echo "   sudo ip netns exec core tcpdump -i veth-core1 -nn"
echo
echo " To watch counters:"
echo "   sudo ./build/gtp-ctrl stats --watch"
echo
echo " To tear down:"
echo "   sudo bash tools/teardown_netns.sh"
echo "══════════════════════════════════════════════════════"