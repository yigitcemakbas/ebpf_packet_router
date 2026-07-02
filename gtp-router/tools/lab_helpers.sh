# tools/lab_helpers.sh - sourced into the lab's control pane by tools/lab.sh.
#
# Short verbs for driving the router against the live 5G session. Each set-verb
# auto-captures the current uplink TEID (which changes every session, ~72s
# under load) so you never hand-copy it. Run from the repo root.
#
# Verbs:
#   showteid                        - print the live TEID / UE IP
#   decap                           - strip GTP-U, forward inner packet out EGRESS_IFACE
#   drop                            - discard this subscriber's tunnel
#   redirect                        - MAC-rewrite + send out EGRESS_IFACE
#   ratelimit [pps]                 - cap the subscriber (default 5 pps)
#   quarantine [pps] [thr] [secs]   - cap + auto hard-block (default 5 3 30)
#   clearrule                       - remove TEID rules (hand control back to the UPF)
#
# These mirror the dashboard's own CRUD (a/e/d); use whichever you prefer.

: "${EGRESS_IFACE:=eth0}"
LAB_NETNS=ran
LAB_VETH=veth-ran
LAB_RAN_N3=10.201.0.2
LAB_HOST_N3=10.201.0.1
GTP_CTRL=./build/gtp-ctrl

# _teid: capture the live uplink TEID (gNB->UPF) off the veth. If traffic isn't
# visible (e.g. a drop rule is already swallowing it before the tap), fall back
# to whatever TEID is currently provisioned in teid_map.
_teid() {
  local t
  t=$(sudo tcpdump -i "$LAB_VETH" -nn -x \
        "udp port 2152 and src $LAB_RAN_N3 and dst $LAB_HOST_N3" -c 1 2>/dev/null \
        | grep '0x0020' | awk '{print "0x"$2$3}')
  if [ -z "$t" ]; then
    t=$(sudo "$GTP_CTRL" list 2>/dev/null | grep '^0x' | awk '{print $1; exit}')
  fi
  echo "$t"
}

_ueip() {
  sudo ip netns exec "$LAB_NETNS" ip -4 -o addr show uesimtun0 2>/dev/null \
    | awk '{print $4}' | cut -d/ -f1
}

_smac() { cat /sys/class/net/"$EGRESS_IFACE"/address 2>/dev/null; }

# _dmac: the next-hop (gateway) MAC for real egress; ping the gateway first to
# make sure it's in the ARP cache.
_dmac() {
  local gw
  gw=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}')
  [ -n "$gw" ] && sudo ping -c1 -W1 "$gw" >/dev/null 2>&1
  ip neigh show "$gw" 2>/dev/null | awk '{print $5; exit}'
}

showteid() { echo "TEID=$(_teid)  UEIP=$(_ueip)"; }

decap() {
  local t; t=$(_teid); [ -z "$t" ] && { echo "no live TEID (is traffic flowing?)"; return 1; }
  sudo "$GTP_CTRL" add-teid --teid "$t" --action decap \
    --out-iface "$EGRESS_IFACE" --dmac "$(_dmac)" --smac "$(_smac)" \
    && echo "decap set on $t (out $EGRESS_IFACE)"
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

ratelimit() {
  local t pps; t=$(_teid); pps="${1:-5}"
  [ -z "$t" ] && { echo "no live TEID"; return 1; }
  sudo "$GTP_CTRL" add-teid --teid "$t" --action decap \
    --out-iface "$EGRESS_IFACE" --dmac "$(_dmac)" --smac "$(_smac)" \
    --rate-pps "$pps" && echo "rate-limit ${pps}pps set on $t"
}

quarantine() {
  local t pps thr secs; t=$(_teid); pps="${1:-5}"; thr="${2:-3}"; secs="${3:-30}"
  [ -z "$t" ] && { echo "no live TEID"; return 1; }
  sudo "$GTP_CTRL" add-teid --teid "$t" --action decap \
    --out-iface "$EGRESS_IFACE" --dmac "$(_dmac)" --smac "$(_smac)" \
    --rate-pps "$pps" --quarantine-threshold "$thr" --quarantine-seconds "$secs" \
    && echo "quarantine set on $t (cap ${pps}pps, ${thr} windows, ${secs}s)"
}

# clearrule: remove every TEID rule (reads teid_map rather than the live
# capture, so it works even while a drop rule is hiding the traffic).
clearrule() {
  local teids t
  teids=$(sudo "$GTP_CTRL" list 2>/dev/null | grep '^0x' | awk '{print $1}')
  [ -z "$teids" ] && { echo "no TEID rules to clear"; return 0; }
  for t in $teids; do sudo "$GTP_CTRL" del-teid --teid "$t"; done
  echo "cleared: $teids (traffic back to the UPF)"
}

echo "lab verbs: showteid | decap | drop | redirect | ratelimit [pps] | quarantine [pps] [thr] [secs] | clearrule"
