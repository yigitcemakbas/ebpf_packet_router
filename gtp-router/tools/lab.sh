#!/usr/bin/env bash
# tools/lab.sh
#
# One command to stand up the whole live 5G lab as a tmux "control room":
# infra + Open5GS core + gNB + UE + the router + dashboard + traffic, fully
# auto-started. You land in a tmux session; you mostly watch the dashboard and
# type verbs (from tools/lab_helpers.sh) in the control pane.
#
# EGRESS = a veth "internet" standin (veth-inet0), NOT eth0. On this VirtualBox
# VM eth0's virtio_net refuses native XDP (VIRTIO_NET_F_CTRL_GUEST_OFFLOADS is
# not negotiated, so rx-gro-hw/rx-checksumming are [fixed] on), and the very
# act of toggling those offloads to retry wedges the TX ring and reboots the
# NIC. A veth pair does native XDP purely in-kernel, so the router runs native
# (pre-sk_buff) on BOTH legs and the dashboard shows real per-rule matches
# instead of eth0's ambient background PASS traffic. See tools/veth_roundtrip.sh
# for the standalone proof of this exact data path.
#
# Topology (all native XDP / pre-sk_buff):
#   netns ran:  uesimtun0 (UE) - gNB - veth-ran-ns <-veth-> veth-ran (host)
#   host:       veth-ran   (router native: uplink ingress + downlink egress)
#   host:       veth-inet0 (router native: downlink ingress + uplink egress),
#               10.99.0.1/24 + NAT secondary 10.99.0.10/32
#   netns inet: veth-inet1 (10.99.0.2) = the "internet host" that replies
#   xdp_pass stub on the two RECEIVING peers (veth-inet1, veth-ran-ns) so the
#   native redirect is actually delivered across each veth pair.
#
# Two provisioning modes, both first-class:
#   (default)  the router's rules are installed directly (add-teid/add-nat) from
#              the live TEIDs by tools/lab_provision.sh, and you drive policy
#              from the dashboard / control verbs. The dashboard's "t" key
#              re-provisions from the live session after the TEID rotates.
#   --pfcp     the router acts as the UPF over a REAL N4/PFCP session: Open5GS's
#              own SMF establishes/modifies/deletes GTP-U sessions on the router
#              via PFCP (gtp-ctrl pfcp-serve), which installs the same
#              teid_map/nat_map rules automatically. open5gs-upfd is not used -
#              the router is the UPF.
#
# Usage:
#   sudo bash tools/lab.sh          # bring the lab up (direct provisioning)
#   sudo bash tools/lab.sh --pfcp   # bring the lab up with the router as PFCP UPF
#   sudo bash tools/lab.sh --down   # tear it all down (either mode)
#
# Knobs live in tools/ran.conf. Override paths if yours differ:
#   sudo OPEN5GS=/path UERANSIM=/path REPO=/path bash tools/lab.sh

set -euo pipefail

USER_HOME="/home/${SUDO_USER:-$(logname 2>/dev/null || echo root)}"
export OPEN5GS="${OPEN5GS:-$USER_HOME/open5gs}"
export UERANSIM="${UERANSIM:-$USER_HOME/UERANSIM}"
export REPO="${REPO:-$USER_HOME/ebpf_packet_router/gtp-router}"

SESSION="gtplab"
export NETNS="ran"
export VETH="veth-ran"
export VRANNS="veth-ran-ns"
TOOLS="$REPO/tools"
SMF_YAML="$OPEN5GS/install/etc/open5gs/smf.yaml"
SMF_BAK="$SMF_YAML.labbak"   # backup so --pfcp's smf.yaml edit is reversible

# --- mode / arg parsing ----------------------------------------------------
MODE="manual"; DOWN=0
for a in "$@"; do
  case "$a" in
    --pfcp) MODE="pfcp" ;;
    --down) DOWN=1 ;;
    *) echo "error: unknown argument '$a' (use --pfcp and/or --down)" >&2; exit 1 ;;
  esac
done

# --- veth "internet" standin egress (single source of truth) ---------------
export INET_NS="inet"
export VINET0="veth-inet0"      # host egress leg - router native here
export VINET1="veth-inet1"      # peer in netns inet - carries xdp_pass stub
VINET0_IP="10.99.0.1"
export PEER_IP="10.99.0.2"      # the "internet host" the UE pings

# --- multi-UE knobs (NUM_UES=1 is the original single-UE golden path) --------
# Honored from the environment; defaults match tools/ran.conf. Not sourced from
# ran.conf wholesale, because ran.conf's autodetected EGRESS_IFACE/NAT_IP are
# for a real NIC and would clobber this lab's veth-standin values.
export NUM_UES="${NUM_UES:-1}"
export NAT_IP_BASE="${NAT_IP_BASE:-10.99.0.10}"  # UE i is NATed to base + i
# NAT_IP stays the single base address for the N=1 golden path and for the
# control verbs / dashboard, which operate on the first UE by default.
export NAT_IP="$NAT_IP_BASE"    # in-XDP static 1:1 NAT address (in veth subnet)
export HOST_N3="10.201.0.1"
export RAN_N3="10.201.0.2"
PASS_OBJ="$REPO/build/xdp_pass.o"

# nat_ip_for <i> - the /32 egress NAT address for UE index i, incrementing the
# last octet of NAT_IP_BASE. Lab-scoped: assumes all N stay inside the egress
# /24 (guarded below).
nat_ip_for() { echo "${NAT_IP_BASE%.*}.$(( ${NAT_IP_BASE##*.} + $1 ))"; }

# EGRESS_IFACE is what the interactive control verbs (decap/redirect/...) use;
# on this lab it is the veth standin, and LAB_DMAC pins the peer's MAC so those
# verbs don't try to arping a nonexistent LAN gateway.
export EGRESS_IFACE="$VINET0"

# dashboard traffic ping: the UE pings the peer THROUGH the tunnel (the
# provision step installs a /32 route for it via uesimtun0). Local veth target,
# never an internet host - keep the rate gentle regardless.
PING_TARGET="$PEER_IP"; PING_INTERVAL=1; PING_SIZE=64

if [[ $EUID -ne 0 ]]; then
  echo "error: must be run as root" >&2
  exit 1
fi

teardown_veth_inet() {
  "$REPO/build/gtp-ctrl" unload --iface "$VINET0" 2>/dev/null || true
  ip netns del "$INET_NS" 2>/dev/null || true
  ip link del "$VINET0" 2>/dev/null || true
}

if [[ "$DOWN" == 1 ]]; then
  tmux kill-session -t "$SESSION" 2>/dev/null || true
  pkill -f 'gtp-ctrl pfcp-serve' 2>/dev/null || true
  # restore smf.yaml if a --pfcp run swapped in our PFCP address, so the next
  # direct-provisioning run works with open5gs-upfd again.
  if [[ -f "$SMF_BAK" ]]; then mv -f "$SMF_BAK" "$SMF_YAML"; echo "[lab] restored smf.yaml"; fi
  teardown_veth_inet
  bash "$TOOLS/setup_ran.sh" --down
  echo "[lab] down. (core still running - 'sudo bash tools/stop_5gc.sh' to stop it)"
  exit 0
fi

# --- preflight ---
command -v tmux >/dev/null || { echo "error: tmux not installed (apt install tmux)" >&2; exit 1; }
[[ -x "$REPO/build/gtp-ctrl" ]] || { echo "error: $REPO/build/gtp-ctrl missing - run 'make all' first" >&2; exit 1; }
[[ -f "$PASS_OBJ" ]] || { echo "error: $PASS_OBJ missing - run 'make ebpf' first" >&2; exit 1; }
# shellcheck source=tools/native_check.sh
source "$TOOLS/native_check.sh"

# multi-UE sanity: N >= 1, and all N NAT /32s must fit in the egress /24.
[[ "$NUM_UES" =~ ^[0-9]+$ && "$NUM_UES" -ge 1 ]] || { echo "error: NUM_UES must be a positive integer (got '$NUM_UES')" >&2; exit 1; }
if (( ${NAT_IP_BASE##*.} + NUM_UES - 1 > 254 )); then
  echo "error: NUM_UES=$NUM_UES overflows the egress /24 from NAT_IP_BASE=$NAT_IP_BASE" >&2
  exit 1
fi

# --- infra: namespace, veth-ran, core (NGAP/N3 on the veth), ogstun/NAT ------
bash "$TOOLS/setup_ran.sh"

# --- multi-UE: register N subscribers in Mongo (N=1 keeps the manual golden ---
# path untouched; the single subscriber is assumed already registered per the
# README). For N>1, register all N sequential IMSIs UERANSIM's -n flag will use.
if (( NUM_UES > 1 )); then
  echo "[lab] registering $NUM_UES subscribers for multi-UE run..."
  OPEN5GS="$OPEN5GS" UERANSIM="$UERANSIM" REPO="$REPO" NUM_UES="$NUM_UES" \
    bash "$TOOLS/register_subscribers.sh" "$NUM_UES" \
    || { echo "error: subscriber registration failed" >&2; exit 1; }
fi

# --- veth "internet" standin leg (idempotent) ------------------------------
echo "[lab] creating veth-inet standin egress (10.99.0.0/24)..."
teardown_veth_inet
ip netns add "$INET_NS"
ip link add "$VINET0" type veth peer name "$VINET1"
ip link set "$VINET1" netns "$INET_NS"
ip addr add "$VINET0_IP/24" dev "$VINET0"
# One /32 static-NAT egress address per UE, so the host answers ARP for each.
for (( u=0; u<NUM_UES; u++ )); do
  ip addr add "$(nat_ip_for "$u")/32" dev "$VINET0"
done
ip link set "$VINET0" up
ip netns exec "$INET_NS" ip addr add "$PEER_IP/24" dev "$VINET1"
ip netns exec "$INET_NS" ip link set "$VINET1" up
ip netns exec "$INET_NS" ip link set lo up

# --- attach the router: NATIVE on both veth legs (no eth0, no fallback) ------
# The whole point of this router is pre-stack processing (before sk_buff
# allocation), so native (xdpdrv) is mandatory. veth does native purely
# in-kernel, so unlike eth0 there is no offload dance and no generic fallback:
# if native fails here it is a real bug, and we stop rather than silently
# degrade to post-sk_buff generic mode.
echo "[lab] attaching router NATIVE on $VETH + $VINET0..."
rm -rf /sys/fs/bpf/gtp_router
"$REPO/build/gtp-ctrl" load --iface "$VETH" --mode native \
  --dl-iface "$VINET0" --dl-mode native \
  || { echo "error: native router attach failed on $VETH/$VINET0" >&2; exit 1; }

# xdp_pass stub on the two RECEIVING peers: a veth only accepts redirected
# (ndo_xdp_xmit) frames when its peer has an XDP program loaded.
echo "[lab] attaching xdp_pass (native) on receiving peers $VINET1 + $VRANNS..."
ip netns exec "$INET_NS" ip link set dev "$VINET1" xdp off 2>/dev/null || true
ip netns exec "$NETNS"   ip link set dev "$VRANNS" xdp off 2>/dev/null || true
ip netns exec "$INET_NS" ip link set dev "$VINET1" xdpdrv obj "$PASS_OBJ" sec xdp \
  || { echo "error: xdp_pass native attach failed on $VINET1" >&2; exit 1; }
ip netns exec "$NETNS"   ip link set dev "$VRANNS" xdpdrv obj "$PASS_OBJ" sec xdp \
  || { echo "error: xdp_pass native attach failed on $VRANNS" >&2; exit 1; }

# --- assert NATIVE (xdp, never xdpgeneric) on every data-path iface ----------
# assert_native / assert_native_all come from tools/native_check.sh. The
# XDP-bearing set is fixed at these four legs regardless of NUM_UES (per-UE
# uesimtunN devices carry no XDP program).
echo "[lab] verifying native mode on all data-path interfaces:"
assert_native_all "$VETH" "$VINET0" "$VINET1" "$INET_NS" "$VRANNS" "$NETNS" \
  || { echo "error: not all data-path interfaces are native/xdp" >&2; exit 1; }

# LAB_DMAC pins the uplink egress next-hop MAC (the peer veth) for the control
# verbs, so decap/redirect/ratelimit resolve it without an ARP to a LAN gateway
# that does not exist on the veth subnet.
export LAB_DMAC="$(ip netns exec "$INET_NS" cat /sys/class/net/"$VINET1"/address)"

# --- optional launch-time policy ---
if [[ "${DEFAULT_RATE_PPS:-0}" != "0" ]]; then
  echo "[lab] note: DEFAULT_RATE_PPS=$DEFAULT_RATE_PPS will apply once traffic is flowing;"
  echo "      the control pane can run 'ratelimit $DEFAULT_RATE_PPS' / 'quarantine ...' any time."
fi

# nr-ue flag shared by both modes: one process runs all N UEs via -n (IMSI
# incremented per UE, one uesimtunN each); omitted for the N=1 golden path.
UE_NFLAG=""; (( NUM_UES > 1 )) && UE_NFLAG="-n $NUM_UES"

tmux kill-session -t "$SESSION" 2>/dev/null || true

if [[ "$MODE" == "pfcp" ]]; then
  # ===================== PFCP mode: the router IS the UPF =====================
  # Point Open5GS's SMF at our PFCP/N4 listener and take open5gs-upfd out of the
  # path. The SMF then establishes/modifies/deletes GTP-U sessions on the router
  # over real PFCP, and gtp-ctrl pfcp-serve installs the teid_map/nat_map rules.
  # The exact smf.yaml key varies by Open5GS version; this repoints the default
  # UPF PFCP address (127.0.0.7) at us and is reverted on --down (smf.yaml.labbak).
  echo "[lab] --pfcp: repointing SMF PFCP client 127.0.0.7 -> $HOST_N3 in smf.yaml..."
  if [[ -f "$SMF_YAML" ]]; then
    [[ -f "$SMF_BAK" ]] || cp "$SMF_YAML" "$SMF_BAK"
    sed -i "s/127\.0\.0\.7/$HOST_N3/g" "$SMF_YAML" || true
    grep -q "$HOST_N3" "$SMF_YAML" || echo "  [WARN] could not confirm $HOST_N3 in smf.yaml - set smf.pfcp.client.upf address by hand"
  else
    echo "  [WARN] $SMF_YAML not found - point the SMF's UPF PFCP address at $HOST_N3 manually"
  fi
  echo "[lab] --pfcp: stopping open5gs-upfd (the router is the UPF), restarting SMF..."
  pkill -f open5gs-upfd 2>/dev/null || true
  pkill -f open5gs-smfd 2>/dev/null || true
  sleep 1
  ( cd "$OPEN5GS" && ./install/bin/open5gs-smfd -c "$SMF_YAML" >/tmp/open5gs/smf.log 2>&1 & ) || true

  # MACs for the two egress legs (PFCP conveys no L2 addressing).
  VINET0_MAC=$(cat /sys/class/net/"$VINET0"/address)
  VINET1_MAC=$(ip netns exec "$INET_NS" cat /sys/class/net/"$VINET1"/address)
  VRAN_MAC=$(cat /sys/class/net/"$VETH"/address)
  VRANNS_MAC=$(ip netns exec "$NETNS" cat /sys/class/net/"$VRANNS"/address)

  tmux new-session -d -s "$SESSION" -n pfcp -x 220 -y 50
  tmux set-option -t "$SESSION" -g mouse on

  # window 0 'pfcp' - the N4 server the SMF drives.
  tmux send-keys -t "$SESSION:pfcp" \
    "cd $REPO && sudo ./build/gtp-ctrl pfcp-serve \
      --listen $HOST_N3:8805 --n3-addr $HOST_N3 \
      --ul-iface $VINET0 --ul-dmac $VINET1_MAC --ul-smac $VINET0_MAC \
      --dl-iface $VETH --dl-dmac $VRANNS_MAC --dl-smac $VRAN_MAC \
      --nat-base $NAT_IP_BASE" C-m

  tmux new-window -t "$SESSION" -n gnb \
    "cd $UERANSIM && sudo ip netns exec $NETNS ./build/nr-gnb -c config/open5gs-gnb.yaml 2>&1 | tee /tmp/gnb.log"
  tmux new-window -t "$SESSION" -n ue \
    "cd $UERANSIM && until sudo ip netns exec $NETNS ss -uln 2>/dev/null | grep -q ':4997'; do sleep 1; done; sudo ip netns exec $NETNS ./build/nr-ue -c config/open5gs-ue.yaml $UE_NFLAG 2>&1 | tee /tmp/ue.log"
  # window 3 'rules' - watch the SMF's PFCP sessions materialize as rules live.
  tmux new-window -t "$SESSION" -n rules \
    "watch -n1 'sudo $REPO/build/gtp-ctrl list'"
  tmux select-window -t "$SESSION:pfcp"

  cat <<EOF

==================================================================
 Lab is up in PFCP mode: the router is the UPF, driven by Open5GS's
 own SMF over a real N4/PFCP session (native / pre-sk_buff data path).

   Windows: 0 pfcp (the N4 server)  1 gnb  2 ue  3 rules (live rules)

 EXPECTED FLOW:
   1. 'pfcp' logs "association setup" once the SMF associates with us.
   2. When the UE attaches, 'pfcp' logs "session established" and a
      teid_map rule appears in 'rules'; a Session Modification then adds
      the matching nat_map rule.
   3. UE traffic flows through the router's XDP hook, native, with the
      rules the SMF installed over PFCP.

 If no association appears, the SMF is not reaching our listener - check
 smf.yaml's UPF PFCP address ($HOST_N3) and /tmp/open5gs/smf.log.

 Tear down:  sudo bash tools/lab.sh --down
==================================================================
EOF

else
  # ===================== direct-provisioning mode (default) ==================
  tmux new-session -d -s "$SESSION" -n control -x 220 -y 50
  tmux set-option -t "$SESSION" -g mouse on

  PING_LOG=/tmp/gtp-lab-ping.log
  : > "$PING_LOG"

  # window 0 'control': control shell (left) + dashboard (right, larger).
  # The dashboard owns the traffic ping (started/stopped with "p"); it pings the
  # veth peer, which the provision step routes through uesimtun0 (the tunnel).
  tmux send-keys -t "$SESSION:control" \
    "cd $REPO && EGRESS_IFACE=$EGRESS_IFACE NAT_IP=$NAT_IP NAT_IP_BASE=$NAT_IP_BASE NUM_UES=$NUM_UES LAB_DMAC=$LAB_DMAC LAB_PEER=$PEER_IP source tools/lab_helpers.sh" C-m
  # The dashboard's "t" key re-provisions the REAL round-trip rules from the live
  # session, so it gets the full topology env (same vars tools/lab_provision.sh
  # reads) in addition to the ping config.
  tmux split-window -h -p 65 -t "$SESSION:control" \
    "cd $REPO && sudo PING_TARGET=$PING_TARGET PING_INTERVAL=$PING_INTERVAL PING_SIZE=$PING_SIZE PING_NETNS=$NETNS \
       NETNS=$NETNS VETH=$VETH VRANNS=$VRANNS INET_NS=$INET_NS VINET0=$VINET0 VINET1=$VINET1 \
       HOST_N3=$HOST_N3 RAN_N3=$RAN_N3 PEER_IP=$PEER_IP EGRESS_IFACE=$EGRESS_IFACE NAT_IP=$NAT_IP \
       NAT_IP_BASE=$NAT_IP_BASE NUM_UES=$NUM_UES ./build/gtp-ctrl dashboard"

  # window 1 'gnb'
  tmux new-window -t "$SESSION" -n gnb \
    "cd $UERANSIM && sudo ip netns exec $NETNS ./build/nr-gnb -c config/open5gs-gnb.yaml 2>&1 | tee /tmp/gnb.log"

  # window 2 'ue' - waits for the gNB's RLS socket before attaching.
  tmux new-window -t "$SESSION" -n ue \
    "cd $UERANSIM && until sudo ip netns exec $NETNS ss -uln 2>/dev/null | grep -q ':4997'; do sleep 1; done; sudo ip netns exec $NETNS ./build/nr-ue -c config/open5gs-ue.yaml $UE_NFLAG 2>&1 | tee /tmp/ue.log"

  # window 3 'provision' - waits for the UE(s), then installs the REAL round-trip
  # rules from the LIVE TEID(s) for every UE (this is what makes rule counters
  # climb). The dashboard's "t" key re-provisions the same way after a rotation.
  tmux new-window -t "$SESSION" -n provision \
    "cd $REPO && REPO=$REPO NETNS=$NETNS VETH=$VETH VRANNS=$VRANNS INET_NS=$INET_NS VINET0=$VINET0 VINET1=$VINET1 HOST_N3=$HOST_N3 RAN_N3=$RAN_N3 PEER_IP=$PEER_IP NAT_IP=$NAT_IP NAT_IP_BASE=$NAT_IP_BASE NUM_UES=$NUM_UES sudo -E bash tools/lab_provision.sh"

  # window 4 'traffic' - tails the dashboard-managed ping log (start it with "p")
  tmux new-window -t "$SESSION" -n traffic \
    "echo '[traffic] press p in the control window to start/stop the tunnel ping'; tail -F $PING_LOG"

  tmux select-window -t "$SESSION:control"

  cat <<EOF

==================================================================
 Lab is up (fully NATIVE / pre-sk_buff on all four data-path legs).
 Attaching to tmux session '$SESSION'.

   Windows (mouse is on - click the names in the status bar, or
   Ctrl-b then 0/1/2/3/4):
     0 control    - dashboard (right) + your command shell (left)
     1 gnb        - gNB log
     2 ue         - UE log (auto-starts after the gNB)
     3 provision  - waits for the UE, provisions the REAL rules automatically
                    (the dashboard "t" key re-provisions after a TEID rotation)
     4 traffic    - the UE's tunnel ping output (start it with "p")

 DEMO FLOW:
   1. Wait for the 'provision' window to say "REAL rules provisioned".
   2. Switch to 'control' and press  p  in the dashboard.
   3. Watch teid_map / nat_map per-rule counters climb 0 -> N live -
      those are real GTP-U matches through the tunnel, native XDP.

 Dashboard keys:  t re-provision  p ping   a add  e edit  d delete   c snapshot   q quit
 Control verbs:   showteid | decap | drop | redirect | ratelimit [pps]
                  quarantine [pps] [thr] [secs] | clearrule

 Tear down:  sudo bash tools/lab.sh --down
==================================================================
EOF
fi

if [[ -t 1 ]]; then
  exec tmux attach -t "$SESSION"
else
  echo "[lab] non-interactive shell: session '$SESSION' is running detached."
  echo "[lab] attach with:  tmux attach -t $SESSION"
fi
