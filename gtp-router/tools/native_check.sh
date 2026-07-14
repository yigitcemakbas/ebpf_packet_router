# tools/native_check.sh - shared native-XDP assertion, sourced by tools/lab.sh
# and tools/veth_roundtrip.sh.
#
# The whole premise of this router is pre-sk_buff processing, so every
# data-path interface MUST carry a real driver-mode XDP program (reported as
# "xdp" by `ip link show`), never the generic/SKB fallback ("xdpgeneric",
# post-sk_buff). This assertion is the single enforcement point for that claim
# in the shell tooling; it was previously copy-pasted verbatim into both
# scripts, which is why it now lives here.
#
# The set of XDP-bearing interfaces is FIXED regardless of how many UEs the lab
# runs: the router attaches to the veth legs (veth-ran, veth-inet0) and the
# xdp_pass stub rides the two receiving peers (veth-inet1, veth-ran-ns). The
# per-UE uesimtunN devices are UE-side TUN interfaces with no XDP program, so
# multi-UE runs do not add interfaces to check here.

# assert_native <iface> [netns]
# Prints "  <iface>  xdp (native)" on success; prints an error and returns 1 on
# generic mode or no program. Callers decide whether to exit/die on failure.
assert_native() {
  local iface="$1" ns="${2:-}" out
  if [[ -n "$ns" ]]; then
    out=$(ip netns exec "$ns" ip link show "$iface" 2>/dev/null)
  else
    out=$(ip link show "$iface" 2>/dev/null)
  fi
  case "$out" in
    *xdpgeneric*)
      echo "error: $iface is xdpgeneric (post-sk_buff) - requirement is native/xdp" >&2
      return 1 ;;
    *xdp*)
      printf "  %-12s %s\n" "$iface" "xdp (native)" ;;
    *)
      echo "error: $iface has NO xdp program attached" >&2
      return 1 ;;
  esac
}

# assert_native_all - assert every data-path interface for the standard veth
# topology (the four legs above). Args are the interface/netns names so the two
# callers can pass their own variable values. Returns non-zero if any fails.
# Usage: assert_native_all VETH VINET0 VINET1 INET_NS VRANNS RAN_NS
assert_native_all() {
  local veth="$1" vinet0="$2" vinet1="$3" inet_ns="$4" vranns="$5" ran_ns="$6"
  local rc=0
  assert_native "$veth"                 || rc=1
  assert_native "$vinet0"               || rc=1
  assert_native "$vinet1" "$inet_ns"    || rc=1
  assert_native "$vranns" "$ran_ns"     || rc=1
  return $rc
}
