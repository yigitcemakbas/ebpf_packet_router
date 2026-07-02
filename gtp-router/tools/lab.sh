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

# --- knobs ---
PING_TARGET=8.8.8.8; PING_INTERVAL=0.05; PING_SIZE=64
EGRESS_IFACE=eth0; DEFAULT_RATE_PPS=0; DEFAULT_Q_THRESHOLD=0; DEFAULT_Q_SECONDS=30
[[ -f "$TOOLS/ran.conf" ]] && source "$TOOLS/ran.conf"

# --- infra: namespace, veth, core (NGAP/N3 on the veth), ogstun/NAT/forwarding ---
bash "$TOOLS/setup_ran.sh"

# --- attach the router to the real N3 wire ---
"$REPO/build/gtp-ctrl" load --iface "$VETH" --mode generic

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
tmux send-keys -t "$SESSION:control" "cd $REPO && EGRESS_IFACE=$EGRESS_IFACE source tools/lab_helpers.sh" C-m
tmux split-window -h -p 65 -t "$SESSION:control" \
  "cd $REPO && sudo PING_TARGET=$PING_TARGET PING_INTERVAL=$PING_INTERVAL PING_SIZE=$PING_SIZE PING_NETNS=$NETNS ./build/gtp-ctrl dashboard"

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
