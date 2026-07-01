#!/usr/bin/env bash
# tools/start_5gc.sh
#
# Starts all Open5GS 5G SA network functions in the correct order.
# Each NF runs in the background and logs to /tmp/open5gs/<nf>.log.
#
# Usage:
#   sudo bash tools/start_5gc.sh [--open5gs /home/youruser/open5gs]
#
# View all logs live:
#   sudo bash tools/start_5gc.sh --logs
#
# Check status:
#   sudo bash tools/start_5gc.sh --status
#
# Stop everything:
#   sudo bash tools/stop_5gc.sh

set -euo pipefail

OPEN5GS="${OPEN5GS:-/home/$(logname)/open5gs}"
LOGDIR="/tmp/open5gs"
MODE="start"

while [[ $# -gt 0 ]]; do
  case $1 in
    --open5gs) OPEN5GS="$2"; shift 2 ;;
    --logs)    MODE="logs" ;;
    --status)  MODE="status" ;;
    *) echo "Unknown flag: $1"; exit 1 ;;
  esac
done

if [[ "$MODE" == "logs" ]]; then
  exec tail -f "$LOGDIR"/*.log
fi

if [[ "$MODE" == "status" ]]; then
  echo
  printf "  %-8s  %-6s  %s\n" "NF" "PID" "STATUS"
  printf "  %-8s  %-6s  %s\n" "--------" "------" "------"
  for nf in nrf scp ausf udm udr pcf nssf bsf smf upf amf; do
    pid=$(pgrep -f "open5gs-${nf}d" 2>/dev/null || true)
    if [[ -n "$pid" ]]; then
      printf "  %-8s  %-6s  running\n" "$nf" "$pid"
    else
      printf "  %-8s  %-6s  STOPPED\n" "$nf" "-"
    fi
  done
  echo
  exit 0
fi

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
  echo "error: MongoDB is not running. Run: sudo systemctl start mongodb" >&2
  exit 1
fi

mkdir -p "$LOGDIR"

# wait_port <ip> <port> <label>
wait_port() {
  local ip="$1" port="$2" label="$3"
  local i=0
  printf "  starting %-8s ... " "$label"
  while ! ss -tlnp 2>/dev/null | grep -q "${ip}:${port}"; do
    sleep 0.5
    i=$(( i + 1 ))
    if [[ $i -ge 30 ]]; then
      echo "WARN (did not bind ${ip}:${port} within 15s - see $LOGDIR/${label}.log)"
      return
    fi
  done
  echo "ok  (${ip}:${port})"
}

start_nf() {
  local label="$1" bin="$2"
  "$BIN/$bin" >> "$LOGDIR/$label.log" 2>&1 &
}

echo
echo "Open5GS install : $BIN"
echo "Logs            : $LOGDIR/<nf>.log"
echo

start_nf nrf  open5gs-nrfd
wait_port 127.0.0.10 7777 nrf

start_nf scp  open5gs-scpd
wait_port 127.0.1.10 7777 scp

start_nf ausf open5gs-ausfd
start_nf udm  open5gs-udmd
start_nf udr  open5gs-udrd
start_nf pcf  open5gs-pcfd
start_nf nssf open5gs-nssfd
start_nf bsf  open5gs-bsfd
sleep 2

start_nf smf  open5gs-smfd
wait_port 127.0.0.4 8805 smf

start_nf upf  open5gs-upfd
wait_port 127.0.0.7 2152 upf

start_nf amf  open5gs-amfd
wait_port 127.0.0.5 38412 amf

echo
echo "All network functions started."
echo
echo "Add test subscriber (run once):"
echo
echo "  sudo $BIN/open5gs-dbctl add 999700000000001 465B5CE8B199B49FAA5F0A2EE238A6BC E8ED289DEBA952E4283B54E88E6183CA"
echo
echo "View all logs live:"
echo "  sudo bash tools/start_5gc.sh --logs"
echo
echo "Check status:"
echo "  sudo bash tools/start_5gc.sh --status"
echo
echo "Stop everything:"
echo "  sudo bash tools/stop_5gc.sh"
echo
