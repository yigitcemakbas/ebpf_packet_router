#!/usr/bin/env bash
# tools/setup_ran.sh
#
# One-command bring-up (and teardown) of the live Open5GS + UERANSIM topology
# used to feed REAL 5G GTP-U traffic to the XDP router.
#
# Everything this creates is NON-PERSISTENT and wiped by a reboot: the 'ran'
# network namespace, its veth, the ogstun address, NAT, and IP forwarding. The
# one-time YAML edits (AMF NGAP + UPF N3 rebound onto the veth so the gNB in the
# namespace can reach them, and so the router's XDP hook on the veth can see N3
# traffic) persist on disk; this script re-applies them idempotently anyway.
#
# It does NOT start the gNB/UE - those are foreground processes you run in their
# own terminals so you can watch their logs. The commands are printed at the end.
#
# Usage:
#   sudo bash tools/setup_ran.sh          # bring everything up
#   sudo bash tools/setup_ran.sh --down   # tear the RAN topology down
#
# Override paths if yours differ:
#   sudo OPEN5GS=/path UERANSIM=/path REPO=/path bash tools/setup_ran.sh

set -euo pipefail

USER_HOME="/home/${SUDO_USER:-$(logname 2>/dev/null || echo root)}"
OPEN5GS="${OPEN5GS:-$USER_HOME/open5gs}"
UERANSIM="${UERANSIM:-$USER_HOME/UERANSIM}"
REPO="${REPO:-$USER_HOME/ebpf_packet_router/gtp-router}"

NETNS="ran"
VETH_H="veth-ran"
VETH_N="veth-ran-ns"
HOST_N3="10.201.0.1"
RAN_N3="10.201.0.2"
OGSTUN_ADDR="10.45.0.1/16"
UE_SUBNET="10.45.0.0/16"

AMF_YAML="$OPEN5GS/install/etc/open5gs/amf.yaml"
UPF_YAML="$OPEN5GS/install/etc/open5gs/upf.yaml"
GNB_YAML="$UERANSIM/config/open5gs-gnb.yaml"
UE_YAML="$UERANSIM/config/open5gs-ue.yaml"

if [[ $EUID -ne 0 ]]; then
  echo "error: must be run as root" >&2
  exit 1
fi

teardown() {
  echo "[setup_ran] tearing down RAN topology..."
  pkill -9 -f nr-gnb 2>/dev/null || true
  pkill -9 -f nr-ue  2>/dev/null || true
  ip netns del "$NETNS" 2>/dev/null || true
  ip link del "$VETH_H" 2>/dev/null || true
  echo "[setup_ran] done (core left running - use tools/stop_5gc.sh to stop it)."
}

if [[ "${1:-}" == "--down" ]]; then
  teardown
  exit 0
fi

# --- sanity: required files/dirs ---
for f in "$AMF_YAML" "$UPF_YAML" "$GNB_YAML" "$UE_YAML"; do
  [[ -f "$f" ]] || { echo "error: config not found: $f (set OPEN5GS/UERANSIM)" >&2; exit 1; }
done
[[ -x "$REPO/build/gtp-ctrl" ]] || echo "[setup_ran] note: $REPO/build/gtp-ctrl not built yet (run 'make all')"

echo "[setup_ran] 1/5 applying one-time config edits (idempotent)..."
sed -i '/^  ngap:/,/^  [a-z]/ s/127\.0\.0\.5/10.201.0.1/' "$AMF_YAML"
sed -i '/^  gtpu:/,/^  [a-z]/ s/127\.0\.0\.7/10.201.0.1/' "$UPF_YAML"
sed -i 's/^linkIp:.*/linkIp: 127.0.0.1/'  "$GNB_YAML"
sed -i 's/^ngapIp:.*/ngapIp: 10.201.0.2/' "$GNB_YAML"
sed -i 's/^gtpIp:.*/gtpIp: 10.201.0.2/'   "$GNB_YAML"
sed -i '/^amfConfigs:/,/port:/ s/- address:.*/- address: 10.201.0.1/' "$GNB_YAML"
sed -i '/^gnbSearchList:/,/^[^ ]/ s/^  - .*/  - 127.0.0.1/' "$UE_YAML"

grep -A2 '^  ngap:' "$AMF_YAML" | grep -q "$HOST_N3" || { echo "error: AMF NGAP rebind to $HOST_N3 failed in $AMF_YAML" >&2; exit 1; }
grep -A2 '^  gtpu:' "$UPF_YAML" | grep -q "$HOST_N3" || { echo "error: UPF N3 rebind to $HOST_N3 failed in $UPF_YAML" >&2; exit 1; }

echo "[setup_ran] 2/5 (re)creating '$NETNS' namespace + veth..."
ip netns del "$NETNS" 2>/dev/null || true
ip link del "$VETH_H" 2>/dev/null || true
ip netns add "$NETNS"
ip link add "$VETH_H" type veth peer name "$VETH_N"
ip link set "$VETH_N" netns "$NETNS"
ip addr add "$HOST_N3/24" dev "$VETH_H"
ip link set "$VETH_H" up
ip netns exec "$NETNS" ip addr add "$RAN_N3/24" dev "$VETH_N"
ip netns exec "$NETNS" ip link set "$VETH_N" up
ip netns exec "$NETNS" ip link set lo up
ip netns exec "$NETNS" ip route add default via "$HOST_N3"

echo "[setup_ran] 3/5 starting MongoDB + Open5GS core (NGAP/N3 bind on $HOST_N3)..."
systemctl start mongodb 2>/dev/null || systemctl start mongod 2>/dev/null || true
bash "$REPO/tools/stop_5gc.sh" >/dev/null 2>&1 || true
bash "$REPO/tools/start_5gc.sh" --open5gs "$OPEN5GS"

echo "[setup_ran] 4/5 re-asserting host data-plane (ogstun / NAT / forwarding)..."
for i in $(seq 1 10); do ip link show ogstun >/dev/null 2>&1 && break; sleep 0.5; done
ip addr add "$OGSTUN_ADDR" dev ogstun 2>/dev/null || true
ip link set ogstun up
sysctl -w net.ipv4.ip_forward=1 >/dev/null
iptables -t nat -C POSTROUTING -s "$UE_SUBNET" ! -o ogstun -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s "$UE_SUBNET" ! -o ogstun -j MASQUERADE
iptables -C FORWARD -j ACCEPT 2>/dev/null || iptables -I FORWARD -j ACCEPT

echo "[setup_ran] 5/5 verifying core binds on the veth..."
if ss -lnp 2>/dev/null | grep -q "${HOST_N3}:2152";  then echo "  [ok]   UPF N3   -> ${HOST_N3}:2152"; else echo "  [WARN] UPF not bound on ${HOST_N3}:2152 - see /tmp/open5gs/upf.log"; fi
if ss -lnp 2>/dev/null | grep -q "${HOST_N3}:38412"; then echo "  [ok]   AMF NGAP -> ${HOST_N3}:38412"; else echo "  [WARN] AMF not bound on ${HOST_N3}:38412 - see /tmp/open5gs/amf.log"; fi

cat <<EOF

==================================================================
 RAN topology ready. Start the radio in its own terminals:

   # Terminal - gNB
   cd $UERANSIM && sudo ip netns exec $NETNS ./build/nr-gnb -c config/open5gs-gnb.yaml

   # Terminal - UE (after gNB shows 'NG Setup procedure is successful')
   cd $UERANSIM && sudo ip netns exec $NETNS ./build/nr-ue -c config/open5gs-ue.yaml

 Then verify internet through the tunnel:
   sudo ip netns exec $NETNS ping -I uesimtun0 -c 5 8.8.8.8

 Attach the router to the real N3 wire:
   cd $REPO && sudo ./build/gtp-ctrl load --iface $VETH_H --mode generic

 Tear down later:
   sudo bash tools/setup_ran.sh --down
==================================================================
EOF
