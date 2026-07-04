#!/usr/bin/env bash
# tools/lab.sh
#
# One command to stand up the whole live 5G lab as a tmux "control room":
# infra + Open5GS core + gNB + UE + the router + dashboard + traffic, fully
# auto-started. You land in a tmux session; you mostly watch the dashboard and
# type verbs (from tools/lab_helpers.sh) in the control pane.
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
NETNS="ran"
VETH="veth-ran"
TOOLS="$REPO/tools"

if [[ $EUID -ne 0 ]]; then
  echo "error: must be run as root" >&2
  exit 1
fi

if [[ "${1:-}" == "--down" ]]; then
  tmux kill-session -t "$SESSION" 2>/dev/null || true
  bash "$TOOLS/setup_ran.sh" --down
  echo "[lab] down. (core still running - 'sudo bash tools/stop_5gc.sh' to stop it)"
  exit 0
fi

# --- preflight ---
command -v tmux >/dev/null || { echo "error: tmux not installed (apt install tmux)" >&2; exit 1; }
[[ -x "$REPO/build/gtp-ctrl" ]] || { echo "error: $REPO/build/gtp-ctrl missing - run 'make all' first" >&2; exit 1; }

# --- knobs (EGRESS_IFACE/NAT_IP are resolved in ran.conf - single source) ---
# Fallbacks only (ran.conf overrides): never an internet ping target, and a
# gentle 1 pkt/s - this LAN drops the VM's WiFi on ICMP bursts to the internet.
PING_TARGET=127.0.0.1; PING_INTERVAL=1; PING_SIZE=64
DEFAULT_RATE_PPS=0; DEFAULT_Q_THRESHOLD=0; DEFAULT_Q_SECONDS=30
[[ -f "$TOOLS/ran.conf" ]] && source "$TOOLS/ran.conf"
[[ -n "${EGRESS_IFACE:-}" ]] || { echo "error: could not detect egress interface (no default route?); set EGRESS_IFACE in tools/ran.conf" >&2; exit 1; }
echo "[lab] egress: $EGRESS_IFACE  NAT IP: ${NAT_IP:-<unset>}"

# --- infra: namespace, veth, core (NGAP/N3 on the veth), ogstun/NAT/forwarding ---
bash "$TOOLS/setup_ran.sh"

# xdp_mode_of <iface>: what `ip link show` actually reports after attach.
# Native shows a bare "xdp", generic shows "xdpgeneric" - we assert on this
# rather than trusting the attach call, so a silent mode downgrade is caught.
xdp_mode_of() {
  local out; out=$(ip link show dev "$1" 2>/dev/null)
  case "$out" in
    *xdpgeneric*) echo generic ;;
    *xdpoffload*) echo offload ;;
    *xdp*)        echo native ;;
    *)            echo none ;;
  esac
}

egress_driver() {
  basename "$(readlink -f "/sys/class/net/$EGRESS_IFACE/device/driver" 2>/dev/null)" 2>/dev/null || echo unknown
}

# --- attach the router: NATIVE on both sides, honest fallback if unsupported ---
# The whole point of this router is pre-stack processing (before sk_buff
# allocation), so native (xdpdrv) is mandatory wherever the driver allows it.
# Fallback to generic is a loud exception - never the default - and it is
# all-or-nothing: bpf_redirect from a NATIVE program requires ndo_xdp_xmit on
# the TARGET interface, so "native veth + generic egress" silently drops every
# uplink packet (proven against e1000). If the egress can't do native, the
# veth must degrade with it.
load_router() {
  local ctrl="$REPO/build/gtp-ctrl"
  echo "[lab] attaching XDP native on $VETH + $EGRESS_IFACE..."
  "$ctrl" load --iface "$VETH" --mode native --dl-iface "$EGRESS_IFACE" --dl-mode native && return 0

  # virtio_net refuses native XDP while guest offloads are active
  # ("Can't set XDP while host is implementing GRO_HW/CSUM" in the kernel
  # extack). Disable every offload the guest is allowed to touch and retry.
  # NOTE: if the hypervisor did not negotiate VIRTIO_NET_F_CTRL_GUEST_OFFLOADS,
  # rx-gro-hw / rx-checksumming are [fixed] and this retry CANNOT succeed -
  # the fix is hypervisor-side (disable guest TSO/csum offload in the VM's
  # NIC config), not in the guest.
  echo "[lab] native attach failed - disabling offloads on $EGRESS_IFACE (virtio_net XDP requirement) and retrying..."
  ethtool -K "$EGRESS_IFACE" gro off lro off tso off rx-gro-hw off rx off 2>/dev/null || true
  "$ctrl" load --iface "$VETH" --mode native --dl-iface "$EGRESS_IFACE" --dl-mode native && return 0

  echo "[lab] WARNING: driver '$(egress_driver)' on $EGRESS_IFACE refuses native XDP (see 'sudo dmesg | tail')."
  echo "[lab] WARNING: pre-stack acceleration is UNAVAILABLE - falling back to GENERIC on BOTH interfaces"
  echo "[lab] WARNING: (both, not just $EGRESS_IFACE: native-veth redirect into a non-XDP NIC silently drops)."
  "$ctrl" load --iface "$VETH" --mode generic --dl-iface "$EGRESS_IFACE" --dl-mode generic
}
load_router

# --- verify the modes we actually got (not the ones we asked for) ---
for _if in "$VETH" "$EGRESS_IFACE"; do
  _mode=$(xdp_mode_of "$_if")
  echo "[lab] $_if XDP mode: $_mode"
  if [[ "$_mode" == "none" ]]; then
    echo "error: no XDP program attached on $_if" >&2; exit 1
  elif [[ "$_mode" != "native" ]]; then
    echo "[lab] WARNING: $_if is NOT native ($_mode) - packets there traverse sk_buff allocation first."
  fi
done

# --- optional launch-time policy ---
if [[ "${DEFAULT_RATE_PPS:-0}" != "0" ]]; then
  echo "[lab] note: DEFAULT_RATE_PPS=$DEFAULT_RATE_PPS will apply once traffic is flowing;"
  echo "      the control pane can run 'ratelimit $DEFAULT_RATE_PPS' / 'quarantine ...' any time."
fi

# --- build the tmux control room ---
tmux kill-session -t "$SESSION" 2>/dev/null || true
tmux new-session -d -s "$SESSION" -n control -x 220 -y 50
tmux set-option -t "$SESSION" -g mouse on

PING_LOG=/tmp/gtp-lab-ping.log
: > "$PING_LOG"

# window 0 'control': control shell (left) + dashboard (right, larger).
# The dashboard owns the traffic ping (started/stopped with "p"); it gets the
# ping knobs via env so "p" pings the right target at the configured rate.
tmux send-keys -t "$SESSION:control" "cd $REPO && EGRESS_IFACE=$EGRESS_IFACE NAT_IP=$NAT_IP source tools/lab_helpers.sh" C-m
tmux split-window -h -p 65 -t "$SESSION:control" \
  "cd $REPO && sudo PING_TARGET=$PING_TARGET PING_INTERVAL=$PING_INTERVAL PING_SIZE=$PING_SIZE PING_NETNS=$NETNS EGRESS_IFACE=$EGRESS_IFACE NAT_IP=$NAT_IP ./build/gtp-ctrl dashboard"

# window 1 'gnb'
tmux new-window -t "$SESSION" -n gnb \
  "cd $UERANSIM && sudo ip netns exec $NETNS ./build/nr-gnb -c config/open5gs-gnb.yaml"

# window 2 'ue' - waits for the gNB's RLS socket before attaching
tmux new-window -t "$SESSION" -n ue \
  "cd $UERANSIM && until sudo ip netns exec $NETNS ss -uln 2>/dev/null | grep -q ':4997'; do sleep 1; done; sudo ip netns exec $NETNS ./build/nr-ue -c config/open5gs-ue.yaml"

# window 3 'traffic' - tails the dashboard-managed ping log (start it with "p")
tmux new-window -t "$SESSION" -n traffic \
  "echo '[traffic] press p in the control window to start/stop the ping'; tail -F $PING_LOG"

tmux select-window -t "$SESSION:control"

cat <<EOF

==================================================================
 Lab is up. Attaching to tmux session '$SESSION'.

   Windows (mouse is on - click the names in the status bar, or
   Ctrl-b then 0/1/2/3):
     0 control  - dashboard (right) + your command shell (left)
     1 gnb      - gNB log
     2 ue       - UE log (auto-starts after the gNB)
     3 traffic  - the UE's ping output (start it with "p"; rate in ran.conf)

 In the dashboard pane:  p start/stop ping   t add test rules   ? manual
                         a add  e edit  d delete   c snapshot   q quit
 In the control shell, drive the router with:
   showteid | decap | drop | redirect | ratelimit [pps]
   quarantine [pps] [thr] [secs] | clearrule

 Tear down:  sudo bash tools/lab.sh --down
==================================================================
EOF

exec tmux attach -t "$SESSION"
