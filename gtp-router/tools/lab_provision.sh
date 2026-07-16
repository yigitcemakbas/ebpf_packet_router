#!/usr/bin/env bash
# tools/lab_provision.sh - runs in the lab's 'provision' tmux window.
#
# Waits for the live UE(s) to attach, then provisions the REAL round-trip rules
# against the veth-inet standin egress (no fake dashboard test rules). This is
# the piece that makes the dashboard actually useful: once these rules are in,
# every tunnel ping a UE sends matches teid_map (uplink) and nat_map (downlink),
# so the per-rule counters climb 0 -> N live on screen.
#
# Data path provisioned per UE (all inside the XDP hook, native/pre-sk_buff):
#   uplink:   GTP-U in on veth-ran  -> decap + NAT src(UE->NAT_i)
#                                    -> redirect out veth-inet0
#   downlink: reply dst==NAT_i in on veth-inet0 -> NAT dst(->UE) + GTP-U encap
#                                    -> redirect out veth-ran -> gNB -> UE
#
# For NUM_UES>1, one nr-ue process brings up N UEs as uesimtun0..uesimtun(N-1),
# each with a distinct UE IP; this script provisions an independent rule pair
# per UE, giving each its own static-NAT egress address NAT_i = NAT_IP_BASE + i.
# Because every UE shares the same outer N3 tunnel (RAN_N3<->HOST_N3), a UE's
# live TEID can only be told apart by driving that one UE's traffic during its
# own capture window (ping -I uesimtunN for uplink, ping <UE-IP> for downlink) -
# which is exactly what the per-UE loop below does, one UE at a time.
#
# It also installs a /32 route for the peer via uesimtun0 so the dashboard's
# plain `ping <peer>` (no -I) is forced through UE 0's GTP tunnel rather than
# out the namespace's default route. (UEs 1..N-1 are driven with explicit
# `-I uesimtunN` by the lab_helpers verbs, so they need no such route.)
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
NAT_IP_BASE="${NAT_IP_BASE:-$NAT_IP}"
NUM_UES="${NUM_UES:-1}"
# Per-UE mapping persisted here the moment each UE's TEIDs are still visible on
# the wire (before any decap rule exists to hide the traffic from the tap).
# lab_helpers.sh reads this file by UE index so its verbs resolve the RIGHT UE
# in steady state instead of re-sniffing - which native XDP redirect makes
# impossible once a rule is installed. Columns (tab-separated):
#   index  uesimtunN  UEIP  uplinkTEID  downlinkTEID  NATIP
LAB_UESTATE="${LAB_UESTATE:-/tmp/gtp-lab-ues.tsv}"

nat_ip_for() { echo "${NAT_IP_BASE%.*}.$(( ${NAT_IP_BASE##*.} + $1 ))"; }

log(){ echo "[provision $(date +%H:%M:%S)] $*"; }
die(){ echo "PROVISION ERROR: $*" >&2; exec bash; }   # keep the pane open on failure

[[ $EUID -eq 0 ]] || { echo "re-exec under sudo..."; exec sudo -E bash "$0" "$@"; }

# ue_ip_of <index> - the IPv4 on uesimtun<index> in netns ran, or empty.
ue_ip_of() {
  ip netns exec "$RAN" ip -4 -o addr show "uesimtun$1" 2>/dev/null \
    | awk '{print $4}' | cut -d/ -f1
}

# --- 1. wait for the UE tunnel(s) ----------------------------------------
log "waiting for uesimtun0 in netns $RAN (gNB+UE are starting in their panes)..."
UEIP0=""
for i in $(seq 1 90); do
  UEIP0=$(ue_ip_of 0)
  [[ -n "$UEIP0" ]] && break
  sleep 1
done
[[ -n "$UEIP0" ]] || die "UE never attached (check the 'ue' pane / /tmp/ue.log)"
log "UE 0 attached: uesimtun0 = $UEIP0"

# For multi-UE, give the remaining tunnels a chance to come up too (they attach
# sequentially as each UE completes its PDU session).
if (( NUM_UES > 1 )); then
  log "waiting for up to $NUM_UES UE tunnels to attach..."
  for i in $(seq 1 60); do
    up=0
    for (( u=0; u<NUM_UES; u++ )); do [[ -n "$(ue_ip_of "$u")" ]] && up=$((up+1)); done
    [[ "$up" -ge "$NUM_UES" ]] && break
    sleep 1
  done
fi

# --- 2. force the peer through UE 0's tunnel (for the dashboard ping) -----
# A plain `ping $PEER` in netns ran would otherwise follow the default route
# (via $HOST_N3 on veth-ran-ns), bypassing the UE's PDU session entirely.
ip netns exec "$RAN" ip route replace "$PEER/32" dev uesimtun0 2>/dev/null \
  && log "route $PEER/32 -> uesimtun0 installed (tunnel-forces the dashboard ping)"

# --- 3. MACs for the two egress legs (shared across all UEs) --------------
VINET0_MAC=$(cat /sys/class/net/"$VINET0"/address)
VINET1_MAC=$(ip netns exec "$INET" cat /sys/class/net/"$VINET1"/address)
VRAN_MAC=$(cat /sys/class/net/"$VRAN"/address)
VRANNS_MAC=$(ip netns exec "$RAN" cat /sys/class/net/"$VRANNS"/address)

# capture_teids <uesimtun-index> <ue-ip>  -> echoes "UPLINK_TEID DOWNLINK_TEID"
# Drives only this one UE during each capture so the TEID on the wire is
# unambiguously this UE's, then returns both directions' TEIDs.
capture_teids() {
  local idx="$1" ueip="$2" T DT
  # downlink: ping this UE's IP from the host (via ogstun); the UPF emits a
  # downlink G-PDU on veth-ran carrying this UE's downlink TEID.
  ( for k in 1 2 3 4; do ping -c1 -W1 "$ueip" >/dev/null 2>&1; sleep 0.5; done ) &
  local dpid=$!
  DT=$(timeout 7 tcpdump -i "$VRAN" -nn -x "udp port 2152 and src $HOST_N3 and dst $RAN_N3" -c1 2>/dev/null \
       | grep '0x0020' | awk '{print "0x"$2$3}')
  kill "$dpid" 2>/dev/null
  # uplink: this UE pings the peer through its own tunnel interface.
  ip netns exec "$RAN" ping -i 0.5 -I "uesimtun$idx" "$PEER" >/dev/null 2>&1 &
  local upid=$!
  T=$(timeout 7 tcpdump -i "$VRAN" -nn -x "udp port 2152 and src $RAN_N3 and dst $HOST_N3" -c1 2>/dev/null \
       | grep '0x0020' | awk '{print "0x"$2$3}')
  kill "$upid" 2>/dev/null
  echo "$T $DT"
}

# --- 4. per-UE: capture live TEIDs + provision the rule pair --------------
declare -a SUMMARY
provisioned=0
# Start the state file fresh; each UE appends its row after it provisions OK.
: > "$LAB_UESTATE" 2>/dev/null || log "  (warning: cannot write $LAB_UESTATE - helper verbs will fall back to sniffing)"
for (( u=0; u<NUM_UES; u++ )); do
  ueip=$(ue_ip_of "$u")
  if [[ -z "$ueip" ]]; then
    if (( u == 0 )); then die "UE 0 has no IP - cannot provision anything"; fi
    log "  UE $u (uesimtun$u) never attached - skipping"
    continue
  fi
  nat_u=$(nat_ip_for "$u")
  log "capturing live TEIDs for UE $u (uesimtun$u = $ueip, NAT $nat_u)..."
  read -r T DT <<< "$(capture_teids "$u" "$ueip")"
  if [[ -z "$T" || -z "$DT" ]]; then
    if (( u == 0 )); then die "UE 0: missing TEID (uplink='$T' downlink='$DT') - is traffic flowing?"; fi
    log "  UE $u: missing TEID (uplink='$T' downlink='$DT') - skipping"
    continue
  fi
  log "  UE $u TEIDs: uplink=$T downlink=$DT"

  "$CTRL" add-teid --teid "$T" --action decap \
    --out-iface "$VINET0" --dmac "$VINET1_MAC" --smac "$VINET0_MAC" --nat-ip "$nat_u" \
    || { (( u == 0 )) && die "UE 0: add-teid failed"; log "  UE $u: add-teid failed - skipping"; continue; }
  "$CTRL" add-nat --nat-ip "$nat_u" --ue-ip "$ueip" --teid-out "$DT" \
    --src-ip "$HOST_N3" --dst-ip "$RAN_N3" \
    --out-iface "$VRAN" --dmac "$VRANNS_MAC" --smac "$VRAN_MAC" \
    || { (( u == 0 )) && die "UE 0: add-nat failed"; log "  UE $u: add-nat failed - skipping"; continue; }

  SUMMARY+=("   UE $u  uesimtun$u=$ueip  teid_map[$T] DECAP+NAT->$nat_u  nat_map[$nat_u] NAT->$ueip encap(teid=$DT) out $VRAN")
  provisioned=$((provisioned+1))
  # Persist this UE's freshly-captured mapping so lab_helpers.sh can resolve it
  # by index later, when the tap can no longer see the (now-redirected) traffic.
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$u" "uesimtun$u" "$ueip" "$T" "$DT" "$nat_u" \
    >> "$LAB_UESTATE" 2>/dev/null || true
done

[[ "$provisioned" -gt 0 ]] || die "no UEs provisioned"

cat <<EOF

==================================================================
 REAL rules provisioned against the live session ($provisioned/$NUM_UES UE(s)):

$(printf '%s\n' "${SUMMARY[@]}")

 Now switch to the 'control' window and press  p  in the dashboard.
 UE 0 will ping $PEER through its tunnel; watch that UE's teid_map /
 nat_map packet counters climb 0 -> N live (the actual per-rule
 matches, not the global PASS counter).
EOF

if (( NUM_UES > 1 )); then
cat <<EOF

 Multi-UE: the dashboard ping drives UE 0 only. To drive another UE's
 tunnel and watch its own rule counters move, use the control verbs
 with a UE selector, e.g.:   showteid all   |   pingue 3
EOF
fi

cat <<EOF

 Re-run this provisioning any time (TEIDs rotate ~every 72s under
 load) with:   sudo -E bash tools/lab_provision.sh
==================================================================
EOF
exec bash
