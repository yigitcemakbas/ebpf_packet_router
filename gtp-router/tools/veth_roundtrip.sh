#!/usr/bin/env bash
# tools/veth_roundtrip.sh
#
# Full-duplex, fully-native (pre-sk_buff) XDP round trip using ONLY veth
# interfaces - no eth0, no internet. This exists because native XDP on this
# VM's virtio-net egress is impossible (VirtualBox does not negotiate
# VIRTIO_NET_F_CTRL_GUEST_OFFLOADS, so rx-gro-hw/rx-checksumming are [fixed] on
# and the kernel refuses XDP), whereas veth's native XDP is pure in-kernel
# functionality and works. It proves the router's data path end to end in
# driver-mode XDP.
#
# Topology:
#   netns ran:  uesimtun0 (UE) --- gNB --- veth-ran-ns  <--veth-->  veth-ran (host)
#   host:       veth-ran (XDP native, uplink ingress + downlink egress)
#   host:       veth-inet0 (XDP native, downlink ingress + uplink egress),
#               10.99.0.1/24 + NAT secondary 10.99.0.10/32
#   netns inet: veth-inet1 (10.99.0.2) = the "internet host" that replies
#
# Data path (all inside the XDP hook, driver mode, bpf_redirect_map/devmap):
#   uplink:   GTP-U in on veth-ran -> decap + NAT src(UE->10.99.0.10)
#             -> redirect out veth-inet0 -> veth-inet1 replies
#   downlink: reply dst==10.99.0.10 in on veth-inet0 -> NAT dst(->UE) + GTP-U
#             encap -> redirect out veth-ran -> gNB -> UE
#
# The two RECEIVING veth peers (veth-inet1, veth-ran-ns) carry the xdp_pass
# stub: a veth only accepts redirected (ndo_xdp_xmit) frames when its peer has
# an XDP program loaded, otherwise they are silently dropped.
#
# Usage (core + veth-ran must already be up, e.g. via tools/setup_ran.sh):
#   sudo bash tools/veth_roundtrip.sh          # setup + run the round-trip test
#   sudo bash tools/veth_roundtrip.sh --down   # tear down the veth-inet leg
set -u

REPO="${REPO:-/home/$(logname 2>/dev/null || echo flower)/ebpf_packet_router/gtp-router}"
UERANSIM="${UERANSIM:-/home/$(logname 2>/dev/null || echo flower)/UERANSIM}"
CTRL="$REPO/build/gtp-ctrl"
PASS_OBJ="$REPO/build/xdp_pass.o"

RAN=ran;        VRAN=veth-ran;      VRANNS=veth-ran-ns
INET=inet;      VINET0=veth-inet0;  VINET1=veth-inet1
HOST_N3=10.201.0.1; RAN_N3=10.201.0.2
INET_SUBNET=10.99.0; VINET0_IP=10.99.0.1; PEER=10.99.0.2; NAT_IP=10.99.0.10

log(){ echo "[veth-rt $(date +%H:%M:%S)] $*"; }
die(){ echo "ERROR: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "must run as root"

if [[ "${1:-}" == "--down" ]]; then
  pkill -f nr-ue 2>/dev/null; pkill -f nr-gnb 2>/dev/null
  "$CTRL" unload --iface "$VRAN" 2>/dev/null
  ip netns del "$INET" 2>/dev/null
  ip link del "$VINET0" 2>/dev/null
  log "veth-inet leg torn down"
  exit 0
fi

[[ -x "$CTRL" ]]      || die "$CTRL missing - run 'make all'"
[[ -f "$PASS_OBJ" ]]  || die "$PASS_OBJ missing - run 'make ebpf'"
ip link show "$VRAN" >/dev/null 2>&1 || die "$VRAN missing - run tools/setup_ran.sh first"

# --- 1. idempotent veth-inet leg -------------------------------------------
log "creating veth-inet leg ($INET_SUBNET.0/24)..."
ip netns del "$INET" 2>/dev/null; ip link del "$VINET0" 2>/dev/null
ip netns add "$INET"
ip link add "$VINET0" type veth peer name "$VINET1"
ip link set "$VINET1" netns "$INET"
ip addr add "$VINET0_IP/24" dev "$VINET0"
ip addr add "$NAT_IP/32"    dev "$VINET0"     # host answers ARP for the NAT IP
ip link set "$VINET0" up
ip netns exec "$INET" ip addr add "$PEER/24" dev "$VINET1"
ip netns exec "$INET" ip link set "$VINET1" up
ip netns exec "$INET" ip link set lo up

# --- 2. attach router native on both host legs -----------------------------
log "attaching router (native) on $VRAN + $VINET0..."
rm -rf /sys/fs/bpf/gtp_router
"$CTRL" load --iface "$VRAN" --mode native --dl-iface "$VINET0" --dl-mode native \
  || die "router native attach failed"

# --- 3. attach xdp_pass native on the two RECEIVING peers ------------------
log "attaching xdp_pass (native) on receiving peers $VINET1 + $VRANNS..."
ip netns exec "$INET" ip link set dev "$VINET1" xdp off 2>/dev/null || true
ip netns exec "$RAN"  ip link set dev "$VRANNS" xdp off 2>/dev/null || true
ip netns exec "$INET" ip link set dev "$VINET1"  xdpdrv obj "$PASS_OBJ" sec xdp \
  || die "xdp_pass attach on $VINET1 failed"
ip netns exec "$RAN"  ip link set dev "$VRANNS"  xdpdrv obj "$PASS_OBJ" sec xdp \
  || die "xdp_pass attach on $VRANNS failed"

# --- 4. assert NATIVE (xdp, never xdpgeneric) on every data-path iface ------
assert_native(){ # <iface> [netns]
  local iface="$1" ns="${2:-}" out mode
  if [[ -n "$ns" ]]; then out=$(ip netns exec "$ns" ip link show "$iface"); else out=$(ip link show "$iface"); fi
  case "$out" in
    *xdpgeneric*) die "$iface is xdpgeneric (post-sk_buff) - requirement is native/xdp" ;;
    *xdp*)        mode=xdp ;;
    *)            die "$iface has NO xdp program attached" ;;
  esac
  printf "  %-12s %s\n" "$iface" "$mode"
}
log "verifying native mode on all data-path interfaces:"
assert_native "$VRAN"
assert_native "$VINET0"
assert_native "$VINET1" "$INET"
assert_native "$VRANNS" "$RAN"

# --- 5. gNB + UE (self-managed children) -----------------------------------
cleanup(){ pkill -f nr-ue 2>/dev/null; pkill -f nr-gnb 2>/dev/null; pkill -f 'ping -O' 2>/dev/null; }
trap cleanup EXIT

VINET0_MAC=$(cat /sys/class/net/$VINET0/address)
VINET1_MAC=$(ip netns exec "$INET" cat /sys/class/net/$VINET1/address)
VRAN_MAC=$(cat /sys/class/net/$VRAN/address)
VRANNS_MAC=$(ip netns exec "$RAN" cat /sys/class/net/$VRANNS/address)

: > /tmp/gnb.log
ip netns exec "$RAN" "$UERANSIM/build/nr-gnb" -c "$UERANSIM/config/open5gs-gnb.yaml" >/tmp/gnb.log 2>&1 &
log "gNB starting..."
for i in $(seq 1 30); do ip netns exec "$RAN" ss -uln 2>/dev/null | grep -q ':4997' && break; sleep 1; done

: > /tmp/ue.log
ip netns exec "$RAN" "$UERANSIM/build/nr-ue" -c "$UERANSIM/config/open5gs-ue.yaml" >/tmp/ue.log 2>&1 &
log "UE starting..."
UEIP=""
for i in $(seq 1 40); do
  UEIP=$(ip netns exec "$RAN" ip -4 -o addr show uesimtun0 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
  [[ -n "$UEIP" ]] && break; sleep 1
done
[[ -n "$UEIP" ]] || die "UE never attached"
log "UE attached: uesimtun0 = $UEIP"

# --- 6. capture live TEIDs -------------------------------------------------
# downlink TEID: ping the UE from the host (via ogstun) so the UPF emits a
# downlink G-PDU; uplink TEID: from the UE's own ping to the peer.
( for k in 1 2 3; do ping -c1 -W1 "$UEIP" >/dev/null 2>&1; sleep 0.5; done ) &
DT=$(timeout 6 tcpdump -i "$VRAN" -nn -x "udp port 2152 and src $HOST_N3 and dst $RAN_N3" -c1 2>/dev/null \
     | grep '0x0020' | awk '{print "0x"$2$3}')
ip netns exec "$RAN" ping -O -i 1 -I uesimtun0 "$PEER" >/tmp/ueping.log 2>&1 &
T=$(timeout 6 tcpdump -i "$VRAN" -nn -x "udp port 2152 and src $RAN_N3 and dst $HOST_N3" -c1 2>/dev/null \
     | grep '0x0020' | awk '{print "0x"$2$3}')
[[ -n "$T"  ]] || die "no uplink TEID captured"
[[ -n "$DT" ]] || die "no downlink TEID captured"
log "TEIDs: uplink=$T downlink=$DT"

# --- 7. provision rules ----------------------------------------------------
"$CTRL" add-teid --teid "$T" --action decap \
  --out-iface "$VINET0" --dmac "$VINET1_MAC" --smac "$VINET0_MAC" --nat-ip "$NAT_IP"
"$CTRL" add-nat --nat-ip "$NAT_IP" --ue-ip "$UEIP" --teid-out "$DT" \
  --src-ip "$HOST_N3" --dst-ip "$RAN_N3" \
  --out-iface "$VRAN" --dmac "$VRANNS_MAC" --smac "$VRAN_MAC"

# --- 8. round-trip test ----------------------------------------------------
pkill -f 'ping -O' 2>/dev/null; sleep 1
echo "=== ROUND-TRIP: ip netns exec $RAN ping -c 6 -i 1 -I uesimtun0 $PEER ==="
ip netns exec "$RAN" ping -c 6 -i 1 -W 2 -I uesimtun0 "$PEER" 2>&1 | tee /tmp/ueping.log
LOSS=$(grep -oE '[0-9]+% packet loss' /tmp/ueping.log | head -1)

echo "=== counters ==="
"$CTRL" list 2>/dev/null | grep -E '^0x|^10\.99'
UL=$("$CTRL" list 2>/dev/null | awk -v t="$T" 'toupper($1)==toupper(t){print $6}')
DL=$("$CTRL" list 2>/dev/null | awk '/^10\.99\.0\.10/{print $7}')

echo "===================== RESULT ====================="
echo "  UE ping loss                         : ${LOSS:-unknown}"
echo "  uplink   decap+NAT teid_map[$T] pkts : ${UL:-0}"
echo "  downlink NAT+encap nat_map[$NAT_IP] pkts : ${DL:-0}"
echo "=================================================="
log "done (gNB/UE stop on exit; veth-inet leg + XDP stay attached)"
