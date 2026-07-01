#!/usr/bin/env bash
# tools/stop_5gc.sh
#
# Kills all running Open5GS processes and closes the tmux session.
#
# Usage:
#   sudo bash tools/stop_5gc.sh

SESSION="5gc"

pkill -f "open5gs-nrfd"  2>/dev/null || true
pkill -f "open5gs-scpd"  2>/dev/null || true
pkill -f "open5gs-amfd"  2>/dev/null || true
pkill -f "open5gs-smfd"  2>/dev/null || true
pkill -f "open5gs-ausfd" 2>/dev/null || true
pkill -f "open5gs-udmd"  2>/dev/null || true
pkill -f "open5gs-udrd"  2>/dev/null || true
pkill -f "open5gs-pcfd"  2>/dev/null || true
pkill -f "open5gs-nssfd" 2>/dev/null || true
pkill -f "open5gs-bsfd"  2>/dev/null || true
pkill -f "open5gs-upfd"  2>/dev/null || true

tmux kill-session -t "$SESSION" 2>/dev/null || true

echo "Open5GS stopped."
