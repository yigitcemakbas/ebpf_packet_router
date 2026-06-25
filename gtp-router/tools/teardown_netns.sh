
# Removes the test topology created by setup_netns.sh.
# Safe to run even if setup did not complete fully.
#
# Usage:
#   sudo bash tools/teardown_netns.sh

set -uo pipefail

GTP_CTRL="${GTP_CTRL:-./build/gtp-ctrl}"

if [[ $EUID -ne 0 ]]; then
  echo "error: must be run as root" >&2
  exit 1
fi

echo "[teardown] Removing test environment..."

# Detach XDP and unpin maps
if [[ -x "$GTP_CTRL" ]]; then
  "$GTP_CTRL" unload --iface veth-gnb1 2>/dev/null && \
    echo "[teardown] XDP detached from veth-gnb1" || \
    echo "[teardown] XDP was not attached (or already removed)"
else
  # Fallback: detach via iproute2
  ip link set dev veth-gnb1 xdp off 2>/dev/null || true
fi

# Delete namespaces (also removes the veth ends inside them)
for ns in gnb core; do
  if ip netns list | grep -q "^${ns}"; then
    ip netns del "$ns"
    echo "[teardown] Deleted namespace: $ns"
  fi
done

# Delete the default-namespace ends of the veth pairs
for iface in veth-gnb1 veth-core0; do
  if ip link show "$iface" &>/dev/null; then
    ip link del "$iface"
    echo "[teardown] Deleted interface: $iface"
  fi
done

# Remove BPF pin directory if it still exists
if [[ -d /sys/fs/bpf/gtp_router ]]; then
  rm -rf /sys/fs/bpf/gtp_router
  echo "[teardown] Removed /sys/fs/bpf/gtp_router"
fi

echo "[teardown] Done."