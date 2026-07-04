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
# Usage:
#   sudo bash tools/lab.sh          # bring the whole lab up and attach
#   sudo bash tools/lab.sh --down   # tear it all down
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

# --- veth "internet" standin egress (single source of truth) ---------------
export INET_NS="inet"
export VINET0="veth-inet0"      # host egress leg - router native here
export VINET1="veth-inet1"      # peer in netns inet - carries xdp_pass stub
VINET0_IP="10.99.0.1"
export PEER_IP="10.99.0.2"      # the "internet host" the UE pings
export NAT_IP="10.99.0.10"      # in-XDP static 1:1 NAT address (in veth subnet)
export HOST_N3="10.201.0.1"
export RAN_N3="10.201.0.2"
PASS_OBJ="$REPO/build/xdp_pass.o"

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

if [[ "${1:-}" == "--down" ]]; then
  tmux kill-session -t "$SESSION" 2>/dev/null || true
  teardown_veth_inet
  bash "$TOOLS/setup_ran.sh" --down
  echo "[lab] down. (core still running - 'sudo bash tools/stop_5gc.sh' to stop it)"
  exit 0
fi

# --- preflight ---
command -v tmux >/dev/null || { echo "error: tmux not installed (apt install tmux)" >&2; exit 1; }
[[ -x "$REPO/build/gtp-ctrl" ]] || { echo "error: $REPO/build/gtp-ctrl missing - run 'make all' first" >&2; exit 1; }
[[ -f "$PASS_OBJ" ]] || { echo "error: $PASS_OBJ missing - run 'make ebpf' first" >&2; exit 1; }

# --- infra: namespace, veth-ran, core (NGAP/N3 on the veth), ogstun/NAT ------
bash "$TOOLS/setup_ran.sh"

# --- veth "internet" standin leg (idempotent) ------------------------------
echo "[lab] creating veth-inet standin egress (10.99.0.0/24)..."
teardown_veth_inet
ip netns add "$INET_NS"
ip link add "$VINET0" type veth peer name "$VINET1"
ip link set "$VINET1" netns "$INET_NS"
ip addr add "$VINET0_IP/24" dev "$VINET0"
ip addr add "$NAT_IP/32"    dev "$VINET0"        # host answers ARP for the NAT IP
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
assert_native() { # <iface> [netns]
  local iface="$1" ns="${2:-}" out
  if [[ -n "$ns" ]]; then out=$(ip netns exec "$ns" ip link show "$iface"); else out=$(ip link show "$iface"); fi
  case "$out" in
    *xdpgeneric*) echo "error: $iface is xdpgeneric (post-sk_buff) - requirement is native/xdp" >&2; exit 1 ;;
    *xdp*)        printf "  %-12s %s\n" "$iface" "xdp (native)" ;;
    *)            echo "error: $iface has NO xdp program attached" >&2; exit 1 ;;
  esac
}
echo "[lab] verifying native mode on all data-path interfaces:"
assert_native "$VETH"
assert_native "$VINET0"
assert_native "$VINET1" "$INET_NS"
assert_native "$VRANNS" "$NETNS"

# LAB_DMAC pins the uplink egress next-hop MAC (the peer veth) for the control
# verbs, so decap/redirect/ratelimit resolve it without an ARP to a LAN gateway
# that does not exist on the veth subnet.
export LAB_DMAC="$(ip netns exec "$INET_NS" cat /sys/class/net/"$VINET1"/address)"

# --- optional launch-time policy ---
if [[ "${DEFAULT_RATE_PPS:-0}" != "0" ]]; then
  echo "[lab] note: DEFAULT_RATE_PPS=$DEFAULT_RATE_PPS will apply once traffic is flowing;"
  echo "      the control pane can run 'ratelimit $DEFAULT_RATE_PPS' / 'quarantine ...' any time."
fi

# --- build the tmux control room -------------------------------------------
tmux kill-session -t "$SESSION" 2>/dev/null || true
tmux new-session -d -s "$SESSION" -n control -x 220 -y 50
tmux set-option -t "$SESSION" -g mouse on

PING_LOG=/tmp/gtp-lab-ping.log
: > "$PING_LOG"

# window 0 'control': control shell (left) + dashboard (right, larger).
# The dashboard owns the traffic ping (started/stopped with "p"); it pings the
# veth peer, which the provision step routes through uesimtun0 (the tunnel).
tmux send-keys -t "$SESSION:control" \
  "cd $REPO && EGRESS_IFACE=$EGRESS_IFACE NAT_IP=$NAT_IP LAB_DMAC=$LAB_DMAC LAB_PEER=$PEER_IP source tools/lab_helpers.sh" C-m
tmux split-window -h -p 65 -t "$SESSION:control" \
  "cd $REPO && sudo PING_TARGET=$PING_TARGET PING_INTERVAL=$PING_INTERVAL PING_SIZE=$PING_SIZE PING_NETNS=$NETNS EGRESS_IFACE=$EGRESS_IFACE NAT_IP=$NAT_IP ./build/gtp-ctrl dashboard"

# window 1 'gnb'
tmux new-window -t "$SESSION" -n gnb \
  "cd $UERANSIM && sudo ip netns exec $NETNS ./build/nr-gnb -c config/open5gs-gnb.yaml 2>&1 | tee /tmp/gnb.log"

# window 2 'ue' - waits for the gNB's RLS socket before attaching
tmux new-window -t "$SESSION" -n ue \
  "cd $UERANSIM && until sudo ip netns exec $NETNS ss -uln 2>/dev/null | grep -q ':4997'; do sleep 1; done; sudo ip netns exec $NETNS ./build/nr-ue -c config/open5gs-ue.yaml 2>&1 | tee /tmp/ue.log"

# window 3 'provision' - waits for the UE, then installs the REAL round-trip
# rules from the LIVE TEID (this is what makes rule counters actually climb).
tmux new-window -t "$SESSION" -n provision \
  "cd $REPO && REPO=$REPO NETNS=$NETNS VETH=$VETH VRANNS=$VRANNS INET_NS=$INET_NS VINET0=$VINET0 VINET1=$VINET1 HOST_N3=$HOST_N3 RAN_N3=$RAN_N3 PEER_IP=$PEER_IP NAT_IP=$NAT_IP sudo -E bash tools/lab_provision.sh"

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
     3 provision  - waits for the UE, provisions the REAL rules, then
                    tells you to press 'p'. Watch this one first.
     4 traffic    - the UE's tunnel ping output (start it with "p")

 DEMO FLOW:
   1. Wait for the 'provision' window to say "REAL rules provisioned".
   2. Switch to 'control' and press  p  in the dashboard.
   3. Watch teid_map / nat_map per-rule counters climb 0 -> N live -
      those are real GTP-U matches through the tunnel, native XDP.

 Dashboard keys:  p ping   a add  e edit  d delete   c snapshot   q quit
 Control verbs:   showteid | decap | drop | redirect | ratelimit [pps]
                  quarantine [pps] [thr] [secs] | clearrule

 Tear down:  sudo bash tools/lab.sh --down
==================================================================
EOF

if [[ -t 1 ]]; then
  exec tmux attach -t "$SESSION"
else
  echo "[lab] non-interactive shell: session '$SESSION' is running detached."
  echo "[lab] attach with:  tmux attach -t $SESSION"
fi
