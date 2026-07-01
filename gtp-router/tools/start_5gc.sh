#!/usr/bin/env bash
# tools/start_5gc.sh
#
# Starts all Open5GS 5G SA network functions in the correct order,
# waits for each one to confirm it is listening before starting the next,
# and tails all logs into a single tmux session with one named window per NF.
#
# Usage:
#   sudo bash tools/start_5gc.sh [--open5gs ~/open5gs]
#
# Prerequisites:
#   - Open5GS built and installed (see SETUP_5GC.md)
#   - MongoDB running: sudo systemctl start mongodb
#   - tmux installed: apt install tmux

set -euo pipefail

OPEN5GS="${OPEN5GS:-$HOME/open5gs}"
SESSION="5gc"

while [[ $# -gt 0 ]]; do
  case $1 in
    --open5gs) OPEN5GS="$2"; shift 2 ;;
    *) echo "Unknown flag: $1"; exit 1 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "error: must be run as root" >&2
  exit 1
fi

BIN="$OPEN5GS/install/bin"
export LD_LIBRARY_PATH="$OPEN5GS/install/lib/aarch64-linux-gnu:${LD_LIBRARY_PATH:-}"

if [[ ! -x "$BIN/open5gs-nrfd" ]]; then
  echo "error: Open5GS not found at $OPEN5GS - pass --open5gs <path>" >&2
  exit 1
fi

if ! systemctl is-active --quiet mongodb 2>/dev/null && \
   ! systemctl is-active --quiet mongod  2>/dev/null; then
  echo "error: MongoDB is not running. Start it first:"
  echo "  sudo systemctl start mongodb"
  exit 1
fi

if tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "Session '$SESSION' already exists. Attaching..."
  exec tmux attach -t "$SESSION"
fi

# wait_port <ip> <port> <label> <timeout_secs>
wait_port() {
  local ip="$1" port="$2" label="$3" timeout="${4:-10}"
  local i=0
  while ! ss -tlnp 2>/dev/null | grep -q "${ip}:${port}"; do
    sleep 0.5
    i=$(( i + 1 ))
    if [[ $i -ge $(( timeout * 2 )) ]]; then
      echo "  [WARN] $label did not bind ${ip}:${port} within ${timeout}s - check the '$label' window"
      return
    fi
  done
  echo "  [ok]   $label listening on ${ip}:${port}"
}

echo
echo "Starting Open5GS 5G SA core..."
echo "  Install path : $BIN"
echo "  tmux session : $SESSION"
echo

# Start each NF in a named tmux window. The NRF must be first; everything
# else registers with it on startup. Port numbers match Open5GS defaults
# for a single-host loopback deployment.
start_nf() {
  local name="$1" bin="$2"
  if tmux has-session -t "$SESSION" 2>/dev/null; then
    tmux new-window -t "$SESSION" -n "$name" "export LD_LIBRARY_PATH='$OPEN5GS/install/lib/aarch64-linux-gnu:${LD_LIBRARY_PATH}'; exec sudo -E $BIN/$bin"
  else
    tmux new-session -d -s "$SESSION" -n "$name" "export LD_LIBRARY_PATH='$OPEN5GS/install/lib/aarch64-linux-gnu:${LD_LIBRARY_PATH}'; exec sudo -E $BIN/$bin"
  fi
}

# NRF - service registry, everything else depends on it
start_nf "nrf"  "open5gs-nrfd"
wait_port 127.0.0.10 7777 "nrf" 10

# SCP - service communication proxy
start_nf "scp"  "open5gs-scpd"
wait_port 127.0.1.10 7777 "scp" 8

# Core control plane
start_nf "ausf" "open5gs-ausfd"
start_nf "udm"  "open5gs-udmd"
start_nf "udr"  "open5gs-udrd"
start_nf "pcf"  "open5gs-pcfd"
start_nf "nssf" "open5gs-nssfd"
start_nf "bsf"  "open5gs-bsfd"
sleep 2

# SMF and UPF (PFCP peers - SMF must start before UPF connects)
start_nf "smf"  "open5gs-smfd"
wait_port 127.0.0.4 8805 "smf" 10

start_nf "upf"  "open5gs-upfd"
wait_port 127.0.0.7 2152 "upf" 10

# AMF - last, depends on AUSF/UDM/PCF/NSSF all being registered
start_nf "amf"  "open5gs-amfd"
wait_port 127.0.0.5 38412 "amf" 15

echo
echo "All network functions started."
echo
echo "Next step - add a test subscriber (if not already done):"
echo
echo "  sudo $OPEN5GS/install/bin/open5gs-dbctl add \\"
echo "    999700000000001 \\"
echo "    465B5CE8B199B49FAA5F0A2EE238A6BC \\"
echo "    E8ED289DEBA952E4283B54E88E6183CA"
echo
echo "tmux controls:"
echo "  Ctrl-b w       list windows (one per NF)"
echo "  Ctrl-b <n>     switch to window number n"
echo "  Ctrl-b d       detach (leaves everything running)"
echo "  tmux attach -t $SESSION   reattach later"
echo
echo "To stop everything:  sudo bash tools/stop_5gc.sh"
echo

exec tmux attach -t "$SESSION"
