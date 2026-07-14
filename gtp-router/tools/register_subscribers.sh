#!/usr/bin/env bash
# tools/register_subscribers.sh
#
# Idempotently register N sequential test subscribers in Open5GS's MongoDB, so
# UERANSIM's `nr-ue -n N` (which increments the IMSI per simulated UE) has a
# provisioned subscriber for every UE it brings up.
#
# The base IMSI, key and OPc are read from UERANSIM's own UE config
# (open5gs-ue.yaml) so this always matches whatever the UE will actually
# present, falling back to the well-known UERANSIM test values if the file
# cannot be parsed. All N subscribers share the same key/OPc and differ only in
# IMSI, exactly as UERANSIM's `-n` flag does.
#
# Usage:
#   sudo OPEN5GS=/path UERANSIM=/path bash tools/register_subscribers.sh [count]
#
# count defaults to $NUM_UES (from tools/ran.conf) or 1.

set -uo pipefail

USER_HOME="/home/${SUDO_USER:-$(logname 2>/dev/null || echo root)}"
OPEN5GS="${OPEN5GS:-$USER_HOME/open5gs}"
UERANSIM="${UERANSIM:-$USER_HOME/UERANSIM}"
REPO="${REPO:-$USER_HOME/ebpf_packet_router/gtp-router}"

[[ -f "$REPO/tools/ran.conf" ]] && source "$REPO/tools/ran.conf"

COUNT="${1:-${NUM_UES:-1}}"
DBCTL="$OPEN5GS/misc/db/open5gs-dbctl"
UE_YAML="$UERANSIM/config/open5gs-ue.yaml"

# Well-known UERANSIM defaults, used only if the YAML cannot be parsed.
DEF_IMSI="999700000000001"
DEF_KEY="465B5CE8B199B49FAA5F0A2EE238A6BC"
DEF_OPC="E8ED289DEBA952E4283B54E88E6183CA"

if [[ $EUID -ne 0 ]]; then
  echo "error: must be run as root" >&2
  exit 1
fi
[[ -x "$DBCTL" ]] || { echo "error: open5gs-dbctl not found at $DBCTL (set OPEN5GS)" >&2; exit 1; }

# Parse base IMSI / key / OPc from the UE YAML. UERANSIM's format:
#   supi: 'imsi-999700000000001'
#   key: '465B...'
#   op: 'E8ED...'        # this is the OPc when opType is OPC (UERANSIM default)
if [[ -f "$UE_YAML" ]]; then
  BASE_IMSI=$(grep -E "^\s*supi:" "$UE_YAML" | head -1 | grep -oE '[0-9]{15}' | head -1)
  KEY=$(grep -E "^\s*key:" "$UE_YAML" | head -1 | grep -oiE '[0-9A-F]{32}' | head -1)
  OPC=$(grep -E "^\s*op:" "$UE_YAML" | head -1 | grep -oiE '[0-9A-F]{32}' | head -1)
fi
BASE_IMSI="${BASE_IMSI:-$DEF_IMSI}"
KEY="${KEY:-$DEF_KEY}"
OPC="${OPC:-$DEF_OPC}"

echo "[register] base IMSI $BASE_IMSI, key ${KEY:0:8}..., OPc ${OPC:0:8}..., count $COUNT"

# IMSIs are 15-digit decimal; increment the numeric value and re-pad to 15.
strip_zeros() { echo "$1" | sed 's/^0*//'; }   # for safe base-10 arithmetic
BASE_NUM=$(strip_zeros "$BASE_IMSI")

registered=0
for (( i=0; i<COUNT; i++ )); do
  imsi=$(printf "%015d" $(( BASE_NUM + i )))
  # Idempotent: remove any existing row for this IMSI first (ignore failure on
  # a fresh DB), then add. open5gs-dbctl's `add` errors on a duplicate.
  "$DBCTL" remove "$imsi" >/dev/null 2>&1 || true
  if "$DBCTL" add "$imsi" "$KEY" "$OPC" >/dev/null 2>&1; then
    registered=$((registered+1))
  else
    echo "  [WARN] failed to register $imsi" >&2
  fi
done

echo "[register] $registered/$COUNT subscribers registered (IMSI $BASE_IMSI .. $(printf "%015d" $(( BASE_NUM + COUNT - 1 ))))"
[[ "$registered" -eq "$COUNT" ]]
