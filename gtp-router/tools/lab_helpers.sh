# tools/lab_helpers.sh - sourced into the lab's control pane by tools/lab.sh.
#
# Short verbs for driving the router against the live 5G session. Each set-verb
# auto-captures the current uplink TEID (which changes every session, ~72s
# under load) so you never hand-copy it. Run from the repo root.
#
# Verbs:
#   showteid                        - print the live TEID / UE IP
#   decap                           - FULL-DUPLEX takeover: uplink decap+NAT out
#                                     EGRESS_IFACE, downlink NAT+encap back to the gNB
#   drop                            - discard this subscriber's tunnel
#   redirect                        - MAC-rewrite + send out EGRESS_IFACE
#   ratelimit [pps]                 - cap the subscriber (default 5 pps)
#   quarantine [pps] [thr] [secs]   - cap + auto hard-block (default 5 3 30)
#   clearrule                       - remove TEID + NAT rules (control back to the UPF)
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

# _elicit: push ONE round-trip through the UE tunnel so a G-PDU flies past the
# tcpdump taps. Deliberately NOT a ping: this LAN drops the VM's WiFi
# association when it sees ICMP from the VM, so we send a single DNS query
# (one UDP packet each way) bound to uesimtun0 instead.
_elicit() {
  sudo ip netns exec "$LAB_NETNS" python3 - <<'PYEOF' >/dev/null 2>&1 &
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, 25, b"uesimtun0")  # SO_BINDTODEVICE
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

# _teid: capture the live uplink TEID (gNB->UPF) off the veth. If traffic isn't
# visible (e.g. a drop rule is already swallowing it before the tap), fall back
# to whatever TEID is currently provisioned in teid_map.
_teid() {
  local t
  _elicit
  t=$(sudo timeout 5 tcpdump -i "$LAB_VETH" -nn -x \
        "udp port 2152 and src $LAB_RAN_N3 and dst $LAB_HOST_N3" -c 1 2>/dev/null \
        | grep '0x0020' | awk '{print "0x"$2$3}')
  if [ -z "$t" ]; then
    t=$(sudo "$GTP_CTRL" list 2>/dev/null | grep '^0x' | awk '{print $1; exit}')
  fi
  echo "$t"
}

# _dlteid: the TEID the gNB expects on downlink G-PDUs. Captured from the
# UPF->gNB direction while the UPF still owns the downlink (i.e. run this at
# takeover time); falls back to what's already provisioned in nat_map.
_dlteid() {
  local t
  _elicit
  t=$(sudo timeout 5 tcpdump -i "$LAB_VETH" -nn -x \
        "udp port 2152 and src $LAB_HOST_N3 and dst $LAB_RAN_N3" -c 1 2>/dev/null \
        | grep '0x0020' | awk '{print "0x"$2$3}')
  if [ -z "$t" ]; then
    t=$(sudo "$GTP_CTRL" list 2>/dev/null | awk '/^=== nat_map/{f=1;next} f && /^[0-9]+\./ {print $6; exit}')
  fi
  echo "$t"
}

_ueip() {
  sudo ip netns exec "$LAB_NETNS" ip -4 -o addr show uesimtun0 2>/dev/null \
    | awk '{print $4}' | cut -d/ -f1
}

_smac() { cat /sys/class/net/"$EGRESS_IFACE"/address 2>/dev/null; }

# veth MACs for the downlink encap leg (host side = source, ns side = dest).
_vmac_host() { cat /sys/class/net/"$LAB_VETH"/address 2>/dev/null; }
_vmac_ns()   { sudo ip netns exec "$LAB_NETNS" cat /sys/class/net/"$LAB_VETH_NS"/address 2>/dev/null; }

# _dmac: the next-hop (gateway) MAC for real egress. Refresh the ARP cache
# with arping (pure L2, no ICMP - this LAN kicks the VM off WiFi when it sees
# ICMP from it) only if the kernel doesn't already have a valid entry.
_dmac() {
  local gw mac
  gw=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}')
  [ -z "$gw" ] && return
  mac=$(ip neigh show "$gw" 2>/dev/null | awk '$NF=="REACHABLE" || $NF=="STALE" || $NF=="DELAY" || $NF=="PROBE" {print $5; exit}')
  if [ -z "$mac" ]; then
    sudo arping -c1 -w2 -I "$EGRESS_IFACE" "$gw" >/dev/null 2>&1
    mac=$(ip neigh show "$gw" 2>/dev/null | awk '{print $5; exit}')
  fi
  echo "$mac"
}

showteid() { echo "TEID=$(_teid)  UEIP=$(_ueip)"; }

# decap: full-duplex takeover of the live subscriber, entirely in the XDP hook.
#   uplink:   TEID rule - decap GTP-U, NAT src UE->NAT_IP, redirect out egress
#   downlink: nat_map rule - dst==NAT_IP, NAT dst back to UE, GTP-U encap to gNB
# Capture the downlink TEID FIRST: it needs the UPF to still own the downlink,
# and once the uplink rule is in, the UPF goes quiet.
decap() {
  local t dt u
  dt=$(_dlteid)
  t=$(_teid);  [ -z "$t" ]  && { echo "no live uplink TEID (is traffic flowing?)"; return 1; }
  u=$(_ueip);  [ -z "$u" ]  && { echo "no UE IP (is the UE attached?)"; return 1; }
  [ -z "${NAT_IP:-}" ] && { echo "NAT_IP unset (see tools/ran.conf)"; return 1; }
  [ -z "$dt" ] && { echo "no downlink TEID captured and none in nat_map - downlink would be dead; aborting"; return 1; }
  sudo "$GTP_CTRL" add-teid --teid "$t" --action decap \
    --out-iface "$EGRESS_IFACE" --dmac "$(_dmac)" --smac "$(_smac)" \
    --nat-ip "$NAT_IP" \
    && echo "uplink: decap+NAT ($u -> $NAT_IP) on $t, out $EGRESS_IFACE"
  sudo "$GTP_CTRL" add-nat --nat-ip "$NAT_IP" --ue-ip "$u" \
    --teid-out "$dt" --src-ip "$LAB_HOST_N3" --dst-ip "$LAB_RAN_N3" \
    --out-iface "$LAB_VETH" --dmac "$(_vmac_ns)" --smac "$(_vmac_host)" \
    && echo "downlink: NAT ($NAT_IP -> $u) + encap teid=$dt, out $LAB_VETH"
}

drop() {
  local t; t=$(_teid); [ -z "$t" ] && { echo "no live TEID"; return 1; }
  sudo "$GTP_CTRL" add-teid --teid "$t" --action drop && echo "drop set on $t"
}

redirect() {
  local t; t=$(_teid); [ -z "$t" ] && { echo "no live TEID"; return 1; }
  sudo "$GTP_CTRL" add-teid --teid "$t" --action redirect \
    --out-iface "$EGRESS_IFACE" --dmac "$(_dmac)" --smac "$(_smac)" \
    && echo "redirect set on $t (out $EGRESS_IFACE)"
}

# ratelimit/quarantine re-write the uplink rule in place, so they must carry
# --nat-ip too or they'd silently strip the NAT half of the data path.
ratelimit() {
  local t pps; t=$(_teid); pps="${1:-5}"
  [ -z "$t" ] && { echo "no live TEID"; return 1; }
  sudo "$GTP_CTRL" add-teid --teid "$t" --action decap \
    --out-iface "$EGRESS_IFACE" --dmac "$(_dmac)" --smac "$(_smac)" \
    ${NAT_IP:+--nat-ip "$NAT_IP"} \
    --rate-pps "$pps" && echo "rate-limit ${pps}pps set on $t"
}

quarantine() {
  local t pps thr secs; t=$(_teid); pps="${1:-5}"; thr="${2:-3}"; secs="${3:-30}"
  [ -z "$t" ] && { echo "no live TEID"; return 1; }
  sudo "$GTP_CTRL" add-teid --teid "$t" --action decap \
    --out-iface "$EGRESS_IFACE" --dmac "$(_dmac)" --smac "$(_smac)" \
    ${NAT_IP:+--nat-ip "$NAT_IP"} \
    --rate-pps "$pps" --quarantine-threshold "$thr" --quarantine-seconds "$secs" \
    && echo "quarantine set on $t (cap ${pps}pps, ${thr} windows, ${secs}s)"
}

# clearrule: remove every TEID rule and the NAT rule (reads the maps rather
# than the live capture, so it works even while a drop rule hides the traffic).
clearrule() {
  local teids t
  teids=$(sudo "$GTP_CTRL" list 2>/dev/null | grep '^0x' | awk '{print $1}')
  for t in $teids; do sudo "$GTP_CTRL" del-teid --teid "$t"; done
  [ -n "${NAT_IP:-}" ] && sudo "$GTP_CTRL" del-nat --nat-ip "$NAT_IP" 2>/dev/null
  echo "cleared: ${teids:-<none>} + nat_map (traffic back to the UPF)"
}

echo "lab verbs: showteid | decap | drop | redirect | ratelimit [pps] | quarantine [pps] [thr] [secs] | clearrule"
