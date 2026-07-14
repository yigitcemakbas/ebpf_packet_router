# tools/lab_helpers.sh - sourced into the lab's control pane by tools/lab.sh.
#
# Short verbs for driving the router against the live 5G session. Each set-verb
# auto-captures the current uplink TEID (which changes every session, ~72s
# under load) so you never hand-copy it. Run from the repo root.
#
# Every verb takes an optional trailing UE index (default 0 = the first/only
# UE), so the same commands work whether the lab runs one UE or many
# (NUM_UES>1). UE i uses tunnel uesimtun<i> and static-NAT egress address
# NAT_i = NAT_IP_BASE + i, matching what tools/lab_provision.sh installs.
#
# Verbs:
#   showteid [all|<i>]              - print the live TEID / UE IP (all UEs, or UE i)
#   pingue <i> [count]              - drive UE i's tunnel so its rule counters climb
#   decap [<i>]                     - FULL-DUPLEX takeover of UE i: uplink decap+NAT
#                                     out EGRESS_IFACE, downlink NAT+encap to the gNB
#   drop [<i>]                      - discard UE i's tunnel
#   redirect [<i>]                  - MAC-rewrite + send out EGRESS_IFACE
#   ratelimit [pps] [<i>]           - cap UE i (default 5 pps)
#   quarantine [pps] [thr] [secs] [<i>] - cap + auto hard-block (default 5 3 30)
#   clearrule                       - remove ALL TEID + NAT rules (control back to the UPF)
#
# These mirror the dashboard's own CRUD (a/e/d); use whichever you prefer.

# EGRESS_IFACE / NAT_IP: usually injected via env by lab.sh; when sourced
# standalone, resolve them from ran.conf (the single source of truth).
if [ -z "${EGRESS_IFACE:-}" ] || [ -z "${NAT_IP:-}" ]; then
  [ -f tools/ran.conf ] && source tools/ran.conf
fi
LAB_NETNS=ran
LAB_VETH=veth-ran
LAB_VETH_NS=veth-ran-ns
LAB_RAN_N3=10.201.0.2
LAB_HOST_N3=10.201.0.1
GTP_CTRL=./build/gtp-ctrl
# NAT_IP_BASE defaults to the single NAT_IP for the one-UE case; NUM_UES lets
# `showteid all` know how many tunnels to enumerate.
LAB_NAT_BASE="${NAT_IP_BASE:-${NAT_IP:-10.99.0.10}}"
LAB_NUM_UES="${NUM_UES:-1}"

# nat_ip_for <i> - UE i's static-NAT egress address (last octet + i).
nat_ip_for() { echo "${LAB_NAT_BASE%.*}.$(( ${LAB_NAT_BASE##*.} + ${1:-0} ))"; }

# _elicit [idx]: push ONE round-trip through UE idx's tunnel so a G-PDU flies
# past the tcpdump taps. Deliberately NOT a ping to an internet host: some LANs
# drop the VM's WiFi association on egress ICMP, so we send a single DNS query
# (one UDP packet each way) bound to uesimtun<idx> instead.
_elicit() {
  local idx="${1:-0}"
  sudo ip netns exec "$LAB_NETNS" python3 - "$idx" <<'PYEOF' >/dev/null 2>&1 &
import socket, sys, time
idx = sys.argv[1] if len(sys.argv) > 1 else "0"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, 25, ("uesimtun%s" % idx).encode())  # SO_BINDTODEVICE
s.settimeout(2)
# minimal DNS query: ". NS" - 17 bytes out, one small reply back. Wait for
# the caller's tcpdump to be listening, and send twice so at least one
# round-trip lands inside its capture window.
q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01"
time.sleep(1.5)
for _ in range(2):
    s.sendto(q, ("1.1.1.1", 53))
    try: s.recv(512)
    except OSError: pass
PYEOF
}

# _ueip [idx]: the IPv4 on uesimtun<idx>.
_ueip() {
  sudo ip netns exec "$LAB_NETNS" ip -4 -o addr show "uesimtun${1:-0}" 2>/dev/null \
    | awk '{print $4}' | cut -d/ -f1
}

# _teid [idx]: capture UE idx's live uplink TEID (gNB->UPF) off the veth by
# driving ONLY that UE. If nothing is visible (e.g. a drop rule is swallowing it
# before the tap), fall back to the first TEID currently in teid_map. With
# multiple UEs, only drive one UE at a time so this capture is unambiguous.
_teid() {
  local idx="${1:-0}" t
  _elicit "$idx"
  t=$(sudo timeout 5 tcpdump -i "$LAB_VETH" -nn -x \
        "udp port 2152 and src $LAB_RAN_N3 and dst $LAB_HOST_N3" -c 1 2>/dev/null \
        | grep '0x0020' | awk '{print "0x"$2$3}')
  if [ -z "$t" ]; then
    t=$(sudo "$GTP_CTRL" list 2>/dev/null | grep '^0x' | awk '{print $1; exit}')
  fi
  echo "$t"
}

# _dlteid [idx]: the TEID the gNB expects on UE idx's downlink G-PDUs. Elicited
# by pinging UE idx's own IP from the host (via ogstun) so the UPF - which still
# owns the downlink at takeover time - emits a downlink G-PDU carrying it; falls
# back to what is already provisioned in nat_map.
_dlteid() {
  local idx="${1:-0}" ueip t
  ueip=$(_ueip "$idx")
  if [ -n "$ueip" ]; then
    ( for k in 1 2 3 4; do sudo ping -c1 -W1 "$ueip" >/dev/null 2>&1; sleep 0.4; done ) &
  fi
  t=$(sudo timeout 6 tcpdump -i "$LAB_VETH" -nn -x \
        "udp port 2152 and src $LAB_HOST_N3 and dst $LAB_RAN_N3" -c 1 2>/dev/null \
        | grep '0x0020' | awk '{print "0x"$2$3}')
  if [ -z "$t" ]; then
    t=$(sudo "$GTP_CTRL" list 2>/dev/null | awk '/^=== nat_map/{f=1;next} f && /^[0-9]+\./ {print $6; exit}')
  fi
  echo "$t"
}

_smac() { cat /sys/class/net/"$EGRESS_IFACE"/address 2>/dev/null; }

# veth MACs for the downlink encap leg (host side = source, ns side = dest).
_vmac_host() { cat /sys/class/net/"$LAB_VETH"/address 2>/dev/null; }
_vmac_ns()   { sudo ip netns exec "$LAB_NETNS" cat /sys/class/net/"$LAB_VETH_NS"/address 2>/dev/null; }

# _dmac: the next-hop MAC on the uplink egress leg. On the veth "internet"
# standin (tools/lab.sh) there is no LAN gateway to ARP - the next hop is the
# peer veth, whose MAC lab.sh pins via LAB_DMAC. When that is set we use it
# directly; otherwise we fall back to the real-egress gateway resolution.
_dmac() {
  local gw mac
  if [ -n "${LAB_DMAC:-}" ]; then echo "$LAB_DMAC"; return; fi
  gw=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}')
  [ -z "$gw" ] && return
  mac=$(ip neigh show "$gw" 2>/dev/null | awk '$NF=="REACHABLE" || $NF=="STALE" || $NF=="DELAY" || $NF=="PROBE" {print $5; exit}')
  if [ -z "$mac" ]; then
    sudo arping -c1 -w2 -I "$EGRESS_IFACE" "$gw" >/dev/null 2>&1
    mac=$(ip neigh show "$gw" 2>/dev/null | awk '{print $5; exit}')
  fi
  echo "$mac"
}

# showteid [all|<idx>] - print one UE's live TEID/UE-IP, or every UE's when
# given "all" (default: UE 0). Enumerates uesimtun0..uesimtun(LAB_NUM_UES-1).
showteid() {
  local sel="${1:-0}"
  if [ "$sel" = "all" ]; then
    local u
    for (( u=0; u<LAB_NUM_UES; u++ )); do
      local ip; ip=$(_ueip "$u")
      [ -z "$ip" ] && continue
      echo "UE $u  uesimtun$u  UEIP=$ip  TEID=$(_teid "$u")  NAT=$(nat_ip_for "$u")"
    done
  else
    echo "UE $sel  TEID=$(_teid "$sel")  UEIP=$(_ueip "$sel")  NAT=$(nat_ip_for "$sel")"
  fi
}

# pingue <idx> [count] - drive UE idx's tunnel so its own rule counters climb on
# the dashboard (the dashboard's own "p" ping only drives UE 0).
pingue() {
  local idx="${1:?usage: pingue <ue-index> [count]}" count="${2:-10}"
  local ip; ip=$(_ueip "$idx")
  [ -z "$ip" ] && { echo "uesimtun$idx has no IP (is UE $idx attached?)"; return 1; }
  echo "pinging peer ${LAB_PEER:-$PEER_IP} through uesimtun$idx ($count packets)..."
  sudo ip netns exec "$LAB_NETNS" ping -c "$count" -i 0.5 -I "uesimtun$idx" "${LAB_PEER:-${PEER_IP:-10.99.0.2}}"
}

# decap [idx]: full-duplex takeover of UE idx, entirely in the XDP hook.
#   uplink:   TEID rule - decap GTP-U, NAT src UE->NAT_i, redirect out egress
#   downlink: nat_map rule - dst==NAT_i, NAT dst back to UE, GTP-U encap to gNB
# Capture the downlink TEID FIRST: it needs the UPF to still own the downlink,
# and once the uplink rule is in, the UPF goes quiet.
decap() {
  local idx="${1:-0}" t dt u nat
  nat=$(nat_ip_for "$idx")
  dt=$(_dlteid "$idx")
  t=$(_teid "$idx");  [ -z "$t" ]  && { echo "no live uplink TEID for UE $idx (is traffic flowing?)"; return 1; }
  u=$(_ueip "$idx");  [ -z "$u" ]  && { echo "no UE IP for UE $idx (is it attached?)"; return 1; }
  [ -z "$nat" ] && { echo "NAT IP unresolved (see tools/ran.conf)"; return 1; }
  [ -z "$dt" ] && { echo "no downlink TEID captured and none in nat_map - downlink would be dead; aborting"; return 1; }
  sudo "$GTP_CTRL" add-teid --teid "$t" --action decap \
    --out-iface "$EGRESS_IFACE" --dmac "$(_dmac)" --smac "$(_smac)" \
    --nat-ip "$nat" \
    && echo "UE $idx uplink: decap+NAT ($u -> $nat) on $t, out $EGRESS_IFACE"
  sudo "$GTP_CTRL" add-nat --nat-ip "$nat" --ue-ip "$u" \
    --teid-out "$dt" --src-ip "$LAB_HOST_N3" --dst-ip "$LAB_RAN_N3" \
    --out-iface "$LAB_VETH" --dmac "$(_vmac_ns)" --smac "$(_vmac_host)" \
    && echo "UE $idx downlink: NAT ($nat -> $u) + encap teid=$dt, out $LAB_VETH"
}

drop() {
  local idx="${1:-0}" t; t=$(_teid "$idx"); [ -z "$t" ] && { echo "no live TEID for UE $idx"; return 1; }
  sudo "$GTP_CTRL" add-teid --teid "$t" --action drop && echo "drop set on $t (UE $idx)"
}

redirect() {
  local idx="${1:-0}" t; t=$(_teid "$idx"); [ -z "$t" ] && { echo "no live TEID for UE $idx"; return 1; }
  sudo "$GTP_CTRL" add-teid --teid "$t" --action redirect \
    --out-iface "$EGRESS_IFACE" --dmac "$(_dmac)" --smac "$(_smac)" \
    && echo "redirect set on $t (UE $idx, out $EGRESS_IFACE)"
}

# ratelimit/quarantine re-write UE idx's uplink rule in place, so they must
# carry --nat-ip too or they'd silently strip the NAT half of the data path.
ratelimit() {
  local pps="${1:-5}" idx="${2:-0}" t nat
  t=$(_teid "$idx"); nat=$(nat_ip_for "$idx")
  [ -z "$t" ] && { echo "no live TEID for UE $idx"; return 1; }
  sudo "$GTP_CTRL" add-teid --teid "$t" --action decap \
    --out-iface "$EGRESS_IFACE" --dmac "$(_dmac)" --smac "$(_smac)" \
    ${nat:+--nat-ip "$nat"} \
    --rate-pps "$pps" && echo "rate-limit ${pps}pps set on $t (UE $idx)"
}

quarantine() {
  local pps="${1:-5}" thr="${2:-3}" secs="${3:-30}" idx="${4:-0}" t nat
  t=$(_teid "$idx"); nat=$(nat_ip_for "$idx")
  [ -z "$t" ] && { echo "no live TEID for UE $idx"; return 1; }
  sudo "$GTP_CTRL" add-teid --teid "$t" --action decap \
    --out-iface "$EGRESS_IFACE" --dmac "$(_dmac)" --smac "$(_smac)" \
    ${nat:+--nat-ip "$nat"} \
    --rate-pps "$pps" --quarantine-threshold "$thr" --quarantine-seconds "$secs" \
    && echo "quarantine set on $t (UE $idx, cap ${pps}pps, ${thr} windows, ${secs}s)"
}

# clearrule: remove every TEID rule and every NAT rule (reads the maps rather
# than the live capture, so it works even while a drop rule hides the traffic).
# This clears ALL UEs at once - control returns entirely to the UPF.
clearrule() {
  local teids t nats n
  teids=$(sudo "$GTP_CTRL" list 2>/dev/null | grep '^0x' | awk '{print $1}')
  for t in $teids; do sudo "$GTP_CTRL" del-teid --teid "$t"; done
  # every nat_map row's first column is the NAT IP (a dotted quad).
  nats=$(sudo "$GTP_CTRL" list 2>/dev/null | awk '/^=== nat_map/{f=1;next} f && $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $1}')
  for n in $nats; do sudo "$GTP_CTRL" del-nat --nat-ip "$n" 2>/dev/null; done
  echo "cleared: ${teids:-<none>} + nat_map[${nats:-<none>}] (traffic back to the UPF)"
}

if [ "${LAB_NUM_UES:-1}" -gt 1 ] 2>/dev/null; then
  echo "lab verbs ($LAB_NUM_UES UEs): showteid [all|<i>] | pingue <i> [n] | decap [<i>] | drop [<i>] | redirect [<i>] | ratelimit [pps] [<i>] | quarantine [pps] [thr] [secs] [<i>] | clearrule"
else
  echo "lab verbs: showteid | decap | drop | redirect | ratelimit [pps] | quarantine [pps] [thr] [secs] | clearrule"
fi
