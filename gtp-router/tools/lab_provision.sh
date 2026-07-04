#!/usr/bin/env bash
# tools/lab_provision.sh - runs in the lab's 'provision' tmux window.
#
# Waits for the live UE to attach, then provisions the REAL round-trip rules
# against the veth-inet standin egress (no fake dashboard test rules). This is
# the piece that makes the dashboard actually useful: once these rules are in,
# every tunnel ping the UE sends matches teid_map (uplink) and nat_map
# (downlink), so the per-rule counters climb 0 -> N live on screen.
#
# Data path provisioned (all inside the XDP hook, native/pre-sk_buff):
#   uplink:   GTP-U in on veth-ran  -> decap + NAT src(UE->NAT_IP)
#                                    -> redirect out veth-inet0
#   downlink: reply dst==NAT_IP in on veth-inet0 -> NAT dst(->UE) + GTP-U encap
#                                    -> redirect out veth-ran -> gNB -> UE
#
# It also installs a /32 route for the peer via uesimtun0 so the dashboard's
# plain `ping <peer>` (no -I) is forced through the GTP tunnel rather than out
# the namespace's default route.
#
# Sourced knobs come from the environment (exported by tools/lab.sh); sensible
# defaults match the veth standin topology.
set -u

REPO="${REPO:-/home/$(logname 2>/dev/null || echo flower)/ebpf_packet_router/gtp-router}"
CTRL="$REPO/build/gtp-ctrl"

RAN="${NETNS:-ran}";           VRAN="${VETH:-veth-ran}";     VRANNS="${VRANNS:-veth-ran-ns}"
INET="${INET_NS:-inet}";       VINET0="${VINET0:-veth-inet0}"; VINET1="${VINET1:-veth-inet1}"
HOST_N3="${HOST_N3:-10.201.0.1}"; RAN_N3="${RAN_N3:-10.201.0.2}"
PEER="${PEER_IP:-10.99.0.2}";  NAT_IP="${NAT_IP:-10.99.0.10}"

log(){ echo "[provision $(date +%H:%M:%S)] $*"; }
die(){ echo "PROVISION ERROR: $*" >&2; exec bash; }   # keep the pane open on failure

[[ $EUID -eq 0 ]] || { echo "re-exec under sudo..."; exec sudo -E bash "$0" "$@"; }

# --- 1. wait for the UE tunnel -------------------------------------------
log "waiting for uesimtun0 in netns $RAN (gNB+UE are starting in their panes)..."
UEIP=""
for i in $(seq 1 90); do
  UEIP=$(ip netns exec "$RAN" ip -4 -o addr show uesimtun0 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
  [[ -n "$UEIP" ]] && break
  sleep 1
done
[[ -n "$UEIP" ]] || die "UE never attached (check the 'ue' pane / /tmp/ue.log)"
log "UE attached: uesimtun0 = $UEIP"

# --- 2. force the peer through the tunnel --------------------------------
# A plain `ping $PEER` in netns ran would otherwise follow the default route
# (via $HOST_N3 on veth-ran-ns), bypassing the UE's PDU session entirely.
ip netns exec "$RAN" ip route replace "$PEER/32" dev uesimtun0 2>/dev/null \
  && log "route $PEER/32 -> uesimtun0 installed (tunnel-forces the dashboard ping)"

# --- 3. capture the live TEIDs -------------------------------------------
# downlink TEID: ping the UE from the host (via ogstun) so the UPF emits a
# downlink G-PDU on veth-ran; uplink TEID: from the UE's own tunnel ping.
log "capturing live TEIDs off $VRAN..."
( for k in 1 2 3 4; do ping -c1 -W1 "$UEIP" >/dev/null 2>&1; sleep 0.5; done ) &
DT=$(timeout 7 tcpdump -i "$VRAN" -nn -x "udp port 2152 and src $HOST_N3 and dst $RAN_N3" -c1 2>/dev/null \
     | grep '0x0020' | awk '{print "0x"$2$3}')
ip netns exec "$RAN" ping -i 0.5 -I uesimtun0 "$PEER" >/dev/null 2>&1 &
ULPING=$!
T=$(timeout 7 tcpdump -i "$VRAN" -nn -x "udp port 2152 and src $RAN_N3 and dst $HOST_N3" -c1 2>/dev/null \
     | grep '0x0020' | awk '{print "0x"$2$3}')
kill "$ULPING" 2>/dev/null
[[ -n "$T"  ]] || die "no uplink TEID captured (is the UE passing traffic?)"
[[ -n "$DT" ]] || die "no downlink TEID captured (did the UPF emit a downlink G-PDU?)"
log "TEIDs: uplink=$T downlink=$DT"

# --- 4. MACs for the two egress legs -------------------------------------
VINET0_MAC=$(cat /sys/class/net/"$VINET0"/address)
VINET1_MAC=$(ip netns exec "$INET" cat /sys/class/net/"$VINET1"/address)
VRAN_MAC=$(cat /sys/class/net/"$VRAN"/address)
VRANNS_MAC=$(ip netns exec "$RAN" cat /sys/class/net/"$VRANNS"/address)

# --- 5. provision the REAL round-trip rules ------------------------------
"$CTRL" add-teid --teid "$T" --action decap \
  --out-iface "$VINET0" --dmac "$VINET1_MAC" --smac "$VINET0_MAC" --nat-ip "$NAT_IP" \
  || die "add-teid failed"
"$CTRL" add-nat --nat-ip "$NAT_IP" --ue-ip "$UEIP" --teid-out "$DT" \
  --src-ip "$HOST_N3" --dst-ip "$RAN_N3" \
  --out-iface "$VRAN" --dmac "$VRANNS_MAC" --smac "$VRAN_MAC" \
  || die "add-nat failed"

cat <<EOF

==================================================================
 REAL rules provisioned against the live session:

   uplink   teid_map[$T]  DECAP + NAT ($UEIP -> $NAT_IP) -> out $VINET0
   downlink nat_map[$NAT_IP]  NAT ($NAT_IP -> $UEIP) + GTP-U encap
            (teid=$DT) -> out $VRAN

 Now switch to the 'control' window and press  p  in the dashboard.
 The UE will ping $PEER through the tunnel and you will watch these
 two rules' packet counters climb 0 -> N live (not the global PASS
 counter - the actual per-rule matches).

 Re-run this provisioning any time (the TEID rotates ~every 72s under
 load) with:   sudo -E bash tools/lab_provision.sh
==================================================================
EOF
exec bash
