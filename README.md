# GTP-U XDP Router

## Overview

GTP-U XDP Router is a kernel-resident data plane for mobile network user
plane traffic, implemented in eBPF and attached to a network interface via
XDP (eXpress Data Path). It processes GPRS Tunneling Protocol - User Plane
(GTP-U) traffic, as defined in 3GPP TS 29.281, at the earliest point in the
Linux networking stack: the network interface driver's receive path, prior
to socket buffer (sk_buff) allocation and before the packet is handed to
the kernel's general-purpose IP forwarding logic.

Architecturally, this project implements the forwarding behavior of a
mobile core network's User Plane Function (UPF in 5G terminology; SGW-U or
PGW-U in 4G EPC), in software, on commodity Linux hardware. A conventional
IP router or firewall has no visibility into GTP-U: it observes only an
opaque UDP/2152 datagram and cannot distinguish, rate-limit, or apply
policy to the individual subscribers multiplexed within a single tunnel.
This router parses the tunnel header, the encapsulated subscriber IP
packet, and enforces policy keyed on subscriber identity, specifically the
GTP-U Tunnel Endpoint Identifier (TEID) or the subscriber's (UE) IP
address, rather than on the outer tunnel endpoint alone.

## Capabilities

**Decapsulation (uplink).** Strips the outer Ethernet/IP/UDP/GTP-U headers
from an incoming tunnel and redirects the encapsulated subscriber packet to
a configured egress interface, with destination and source MAC rewritten
in place.

**Encapsulation (downlink).** Constructs a new GTP-U tunnel, outer IPv4
header (with computed checksum), and UDP/2152 envelope around a bare
subscriber packet, and redirects it toward the radio access network.

**Per-subscriber rate limiting.** Enforces a configurable packets-per-second
ceiling on an individual TEID or UE IP, implemented as a fixed one-second
window counter evaluated and updated inline in the XDP program. Traffic
exceeding the configured rate is dropped before it reaches the rest of the
network stack.

**Autonomous quarantine.** A closed-loop security response triggered by
sustained, repeated rate-limit violations. After a configurable number of
consecutive one-second windows in which a subscriber exceeds its rate
ceiling, that subscriber is automatically escalated to an unconditional,
time-bounded block, independent of instantaneous traffic rate. The
quarantine state, its escalation trigger, and its expiry are all evaluated
and mutated entirely within the XDP packet-processing path. No userspace
process polls, schedules, or decides this; the block is applied on the
packet that crosses the violation threshold, and released on the first
packet received after the configured quarantine duration has elapsed.

**Runtime policy management.** Forwarding rules, in both the TEID-keyed and
UE-IP-keyed tables, can be inserted, modified, and removed at runtime
through a command-line control plane or an interactive terminal dashboard,
without interrupting traffic or reloading the XDP program.

## Architecture

The system is split into a data plane and a control plane, communicating
exclusively through pinned eBPF maps.

**Data plane** (`ebpf/gtp_xdp.c`): a single XDP program, compiled to BPF
bytecode and verified by the kernel's eBPF verifier prior to attachment. It
performs GTP-U header validation, tunnel and subscriber lookups, rate
enforcement, quarantine evaluation, and header rewriting, all within the
bounds the verifier permits (no unbounded loops, bounded memory access,
no blocking operations).

**Forwarding state** is held in three eBPF maps, shared between the data
plane and the control plane and persisted independently of any userspace
process:

- `teid_map`: hash map keyed by GTP-U TEID, holding the forwarding rule and
  per-rule counters for that tunnel.
- `ueip_map`: hash map keyed by subscriber IP address, used as a fallback
  for uplink traffic with no matching TEID rule, and as the lookup path for
  downlink encapsulation.
- `stats_map`: per-CPU array holding aggregate verdict counters (pass,
  drop, redirect), avoiding write contention across cores.

**Control plane** (`control/`): a Go binary, `gtp-ctrl`, built on the
`cilium/ebpf` library, responsible for loading and attaching the XDP
program, pinning its maps to `/sys/fs/bpf/gtp_router`, and providing a
command-line interface and an interactive terminal dashboard for runtime
rule management and observability.

## Requirements

- Linux with eBPF and XDP support. Developed and verified against a 6.x
  kernel.
- clang and llvm, to compile the eBPF program.
- Go 1.22 or later, to build the control plane.
- libbpf headers and the kernel headers matching the target system.
- iproute2, ethtool, and tcpdump.
- Python 3 with scapy, required only for the test traffic generator.

On Debian-based systems, including Kali:

```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r) \
                     golang-go iproute2 ethtool tcpdump python3-pip
pip3 install scapy
```

## Build

From the project root:

```bash
make clean && make all
```

This compiles `ebpf/gtp_xdp.c` to a BPF object file, generates Go bindings
for it via `bpf2go`, and builds the `gtp-ctrl` control-plane binary at
`build/gtp-ctrl`.

Always perform a clean build (`make clean && make all`) after modifying
`include/gtp_router.h`, any source file under `ebpf/`, or after changing Go
module dependencies. An incremental `make all` can, under certain
conditions, reuse a stale generated binding rather than regenerating it
against updated source.

After adding or updating a Go dependency:

```bash
cd control && go mod tidy && cd ..
```

## Test Environment

The repository includes a self-contained, two-namespace network topology
for exercising the router without physical radio access network hardware.

```bash
sudo bash tools/setup_netns.sh
```

This provisions two network namespaces, `gnb` and `core`, connected through
the default namespace via veth pairs, attaches the XDP program to the
interface representing the gNB-facing link, and inserts a default
decapsulation rule for TEID `0xDEAD`.

```
[gnb namespace]              [default namespace]              [core namespace]
veth-gnb0 ------ veth-gnb1 (XDP attached)   veth-core0 ------ veth-core1
10.0.0.1         10.0.0.2                    10.0.1.1          10.0.1.2
```

GTP-U traffic enters on `veth-gnb1`, where the XDP program is attached. A
matching uplink rule decapsulates the tunnel and redirects the inner
packet through `veth-core0`, arriving on `veth-core1` in the `core`
namespace. A matching downlink rule performs the inverse: a bare packet is
encapsulated into a new GTP-U tunnel and redirected back toward the `gnb`
namespace.

The addresses `10.1.0.1` and `10.1.0.2` represent subscriber endpoints
inside the tunnel payload. They are not bound to any interface; they exist
solely as test payload data.

`setup_netns.sh` may be re-run at any point to restore a clean state; it
tears down and recreates the entire topology. To remove the topology
without recreating it:

```bash
sudo bash tools/teardown_netns.sh
```

## Verification

Four scripts validate correct operation end to end, each provisioning its
own rule state, generating GTP-U traffic with scapy, capturing the result
on the relevant interface, and reporting a pass/fail summary:

```bash
sudo bash tools/verify.sh             # uplink decapsulation
sudo bash tools/verify_encap.sh       # downlink encapsulation
sudo bash tools/verify_ratelimit.sh   # per-subscriber rate limiting
sudo bash tools/verify_quarantine.sh  # autonomous quarantine
```

These should be run after every build and prior to any demonstration of
the system.

## Control Plane Reference

| Command | Description |
|---|---|
| `gtp-ctrl load --iface <name>` | Attach the XDP program to an interface |
| `gtp-ctrl unload --iface <name>` | Detach the XDP program |
| `gtp-ctrl add-teid` | Insert or update a rule keyed by GTP-U TEID |
| `gtp-ctrl del-teid --teid <id>` | Remove a TEID-keyed rule |
| `gtp-ctrl add-ueip` | Insert or update a rule keyed by subscriber IP |
| `gtp-ctrl del-ueip --ip <addr>` | Remove a UE-IP-keyed rule |
| `gtp-ctrl list` | Display all rules and their associated counters |
| `gtp-ctrl stats [--watch]` | Display aggregate verdict counters |
| `gtp-ctrl dashboard` | Launch the interactive terminal dashboard |

Each subcommand supports `--help` for its complete flag reference and usage
examples.

### Rule Provisioning

A forwarding rule requires an egress interface and the source and
destination MAC addresses to apply to the outgoing frame. Within the test
topology, these can be read after `setup_netns.sh` has been run:

```bash
cat /sys/class/net/veth-core0/address
cat /sys/class/net/veth-gnb1/address
```

Decapsulating uplink traffic for TEID `0xDEAD`:

```bash
sudo ./build/gtp-ctrl add-teid \
  --teid 0xDEAD \
  --action decap \
  --out-iface veth-core0 \
  --dmac <veth-core0 address> \
  --smac <veth-gnb1 address>
```

Encapsulating downlink traffic destined for subscriber `10.1.0.2`:

```bash
sudo ./build/gtp-ctrl add-ueip \
  --ip 10.1.0.2 \
  --action encap \
  --teid-out 0xBEEF \
  --src-ip 10.0.0.2 \
  --dst-ip 10.0.0.1 \
  --out-iface veth-core0 \
  --dmac <veth-core0 address> \
  --smac <veth-gnb1 address>
```

Supported actions are `drop`, `decap`, `encap`, and `redirect`.

### Per-Subscriber Policy Enforcement

`add-teid` and `add-ueip` accept the following policy flags, applicable
regardless of the configured action:

| Flag | Description |
|---|---|
| `--rate-pps <n>` | Maximum packets per second for this subscriber. Traffic in excess of this rate is dropped. A value of 0, or omission of this flag, disables rate limiting. |
| `--quarantine-threshold <n>` | Number of consecutive one-second windows that must exceed the rate cap before the subscriber is automatically quarantined. Requires `--rate-pps` and `--quarantine-seconds` to be set. |
| `--quarantine-seconds <n>` | Duration of an automatically triggered quarantine, after which it self-releases without external intervention. |

Example: a rule capped at 100 packets per second, escalating to a 30
second quarantine after 3 consecutive seconds of sustained violation:

```bash
sudo ./build/gtp-ctrl add-teid \
  --teid 0xDEAD \
  --action decap \
  --out-iface veth-core0 \
  --dmac <veth-core0 address> \
  --smac <veth-gnb1 address> \
  --rate-pps 100 \
  --quarantine-threshold 3 \
  --quarantine-seconds 30
```

The rate counter and quarantine deadline are evaluated against
`CLOCK_MONOTONIC`, read in-kernel via `bpf_ktime_get_ns()`. Quarantine
deadlines are not polled by a timer; expiry is evaluated lazily, on the
next packet the subscriber sends after the deadline has passed.

## Traffic Generation

`tools/gen_gtp_traffic.py` constructs and sends GTP-U traffic with scapy,
in either direction.

Uplink, matching a `decap` rule:

```bash
sudo ip netns exec gnb python3 tools/gen_gtp_traffic.py \
  --iface veth-gnb0 \
  --teid 0xDEAD \
  --src-ip 10.0.0.1 --dst-ip 10.0.0.2 \
  --inner-src 10.1.0.1 --inner-dst 10.1.0.2 \
  --count 50 --pps 20
```

Downlink, matching an `encap` rule (a UE-IP rule with `--action encap`
must already be provisioned):

```bash
sudo ip netns exec gnb python3 tools/gen_gtp_traffic.py \
  --iface veth-gnb0 \
  --mode downlink \
  --inner-src 10.0.0.1 --inner-dst 10.1.0.2 \
  --count 50 --pps 20
```

## Interactive Dashboard

```bash
sudo ./build/gtp-ctrl dashboard
```

Launches a full-screen terminal interface displaying both rule tables and
the aggregate verdict counters, refreshed at a configurable interval
(`--interval`, default one second). Rules can be inserted, modified, and
removed directly from the dashboard while traffic continues to flow.

| Key | Action |
|---|---|
| Tab | Switch focus between the TEID and UE-IP rule tables |
| Up / Down | Move the row selection within the focused table |
| a | Open the form to add a new rule for the focused table |
| e or Enter | Open the form to edit the selected rule |
| d or x | Delete the selected rule, with confirmation |
| c | Write a plain-text snapshot of the current view to /tmp/gtp-dashboard-snapshot.txt |
| q or Ctrl-C | Exit |

Within the add or edit form: Tab and Shift-Tab move between fields, Left
and Right cycle the action, Enter submits, and Escape cancels without
applying changes.

Editing an existing rule replaces it in full, including its counters.
There is no partial update; packet, byte, and drop counters for an edited
rule are reset to zero as a consequence.

## Project Layout

```
ebpf/                  XDP program source, compiled to a BPF object file
include/                Struct definitions shared by the eBPF program and
                        the Go control plane, defining the BPF map schema
control/
  cmd/                  gtp-ctrl subcommands
  maps/                 BPF map access, the forwarding rule structure,
                        and rule validation
  stats/                Aggregate counter access
  loader/                XDP attach and detach, generated eBPF bindings
  tui/                   Interactive dashboard implementation
tools/                  Test topology setup, teardown, traffic generation,
                        and verification scripts
```

## Troubleshooting

**`make all` fails with a missing Go module error.**
Run `cd control && go mod tidy && cd ..`, then rebuild.

**The dashboard's rule tables appear clipped or columns are missing.**
The layout adapts to terminal width. A terminal narrower than approximately
60 columns cannot display a complete table; widen the terminal.

**A verification script fails after manual testing through the dashboard
or CLI.**
Rules created manually may persist and interfere with a script's
assumptions about initial state. Run `tools/teardown_netns.sh` followed by
`tools/setup_netns.sh` to restore a clean topology, then retry.

**A rule's counters reset unexpectedly.**
This occurs whenever a rule is re-inserted via `add-teid`, `add-ueip`, or
the dashboard's edit form. These operations replace the rule in its
entirety; there is no mechanism for a partial update that preserves
existing counters.
