# Runtime Accelerator for N3 Appliance

## Overview

Runtime Accelerator for N3 Appliance (RANA) is a kernel-resident data plane for 5G network user
plane traffic, implemented in eBPF and attached via eXpress Data Path
(XDP). It processes GTP-U (GPRS Tunneling Protocol - User Plane) traffic
inside the network driver's receive path, before the kernel allocates a
socket buffer (sk_buff) and before the general-purpose IP stack ever sees
the packet. Every operation executes in that
pre-allocation window, which reduces overhead.

Architecturally, it reimplements the forwarding behavior of a mobile
core's User Plane Function in software. A conventional router sees GTP-U
only as an opaque UDP/2152 datagram; it cannot distinguish, rate-limit, or
police the individual subscribers multiplexed inside a single tunnel. This
router parses the tunnel header and the encapsulated subscriber packet,
and applies policy keyed on subscriber identity (the GTP-U Tunnel
Endpoint Identifier (TEID)) or the subscriber's (UE) IP address, rather
than on the tunnel endpoint alone.

The data plane has been validated against a real 5G standalone core
(Open5GS) and a real gNB/UE radio simulator (UERANSIM), exchanging
genuine, PFCP-negotiated GTP-U traffic conformant to 3GPP TS 38.415. 

## Capabilities

**Decapsulation (uplink).** Strips the outer Ethernet/IP/UDP/GTP-U headers
from an incoming tunnel and redirects the inner subscriber packet to a
configured egress interface, rewriting MACs in place. Walks the full
GTP-U extension header chain ( the 5G NR PDU Session Container and any
chained extensions), not just the mandatory 8-byte header, which means it parses
real 5G NR G-PDUs.

**Encapsulation (downlink).** Builds a new GTP-U tunnel ( outer IPv4
header with computed checksum, UDP/2152 envelope) around a bare
subscriber packet and redirects it toward the radio access network. Two
formats are implemented: a 4G-style form for the synthetic test topology,
and a 5G NR form carrying the mandatory PDU Session Container, used on the
real downlink path.

**Static NAT.** A subscriber's uplink traffic can have its inner source IP
rewritten to a routable NAT address, with IP and TCP/UDP checksums fixed
up incrementally per RFC 1624, before egress; the matching downlink reply
has its destination rewritten back to the subscriber's real address
before re-encapsulation. This is the same role a UPF's N6 interface
performs, implemented entirely as a packet rewrite inside the XDP hook
rather than handed off to netfilter, so both directions of a subscriber
takeover stay in the pre-sk_buff path.

**Per-subscriber rate limiting.** Enforces a configurable packets-per-
second ceiling on a given TEID, UE IP, or NAT address, using a fixed
one-second window counter evaluated inline in the XDP program. Traffic
over the configured rate is dropped before it reaches the rest of the
network stack.

**Autonomous quarantine.** After a configurable number of consecutive
one-second windows in which a subscriber exceeds its rate ceiling, that
subscriber is escalated to an unconditional, time-bounded block,
independent of instantaneous traffic rate. The block is applied and later
released entirely inside the XDP path. Release happens on the first packet received
after the quarantine duration elapses.

**Runtime policy management.** Rules in the TEID-keyed, UE-IP-keyed, and
NAT-keyed tables can be inserted, modified, and removed at runtime, from
the command line or the interactive dashboard, without interrupting
traffic or reloading the XDP program.

**Verified native-mode operation.** The control plane attaches in
native/driver XDP by default, with independent uplink/downlink attach
modes. Native (pre-sk_buff) mode is confirmed by inspecting the kernel's
own report of the attached program (`ip link show` reporting `xdp`, never
`xdpgeneric`).

## Architecture

The system is split into a data plane and a control plane, communicating
only through pinned eBPF maps.

**Data plane** (`ebpf/gtp_xdp.c`) is a single XDP program, compiled to BPF
bytecode and verified by the kernel's eBPF verifier before attachment. It
performs GTP-U header validation, including the extension chain, tunnel
and subscriber lookups, NAT rewriting, rate and quarantine evaluation, and
header rewriting, all within the bounds the verifier permits: no
unbounded loops, bounded memory access, no blocking operations.

Forwarding state is held in eBPF maps, shared between the two planes and
persisted independently of any userspace process:

- `teid_map` - hash map keyed by GTP-U TEID, holding the rule and
  per-rule counters for that tunnel.
- `ueip_map` - hash map keyed by subscriber IP, used as a fallback for
  uplink traffic with no matching TEID rule, and as the lookup path for
  downlink encapsulation of bare test traffic.
- `nat_map` - hash map keyed by the NAT-assigned IP. A downlink packet
  matching an entry here has its destination rewritten back to the real
  subscriber address and is re-encapsulated in 5G NR format toward the
  gNB - the downlink counterpart of the uplink NAT rewrite.
- `tx_port` - a `BPF_MAP_TYPE_DEVMAP`, keyed by egress interface index,
  the target of `bpf_redirect_map()`. A DEVMAP batches redirected frames
  and flushes them once per NAPI poll cycle rather than per frame, the
  standard pattern used by Cilium and Katran, and materially more robust
  under sustained load than an immediate single-frame `bpf_redirect()`.
- `stats_map` - per-CPU array holding aggregate verdict counters, to
  avoid write contention across cores.

**Control plane** (`control/`) is a Go binary, `gtp-ctrl`, built on the
`cilium/ebpf` library. It loads and attaches the XDP program, optionally
to two interfaces at once for uplink and downlink, pins maps under
`/sys/fs/bpf/gtp_router`, and provides the CLI and the interactive
terminal dashboard.

## Requirements

- Linux with eBPF and XDP support. Developed and verified against a 6.x
  kernel.
- clang and llvm, to compile the eBPF program.
- Go 1.22 or later, to build the control plane.
- libbpf headers and the kernel headers matching the target system.
- iproute2, ethtool, tcpdump, tmux.
- Python 3 with scapy, for the synthetic test traffic generator only.
- For the real 4G/5G integration only: MongoDB with the `mongosh` shell
  client, and the ability to build Open5GS and UERANSIM from source.

On Debian-based systems:

```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r) \
                     golang-go iproute2 ethtool tcpdump tmux python3-pip
pip3 install scapy
```

## Build

From the project root:

```bash
make clean && make all
```

This compiles `ebpf/gtp_xdp.c` and `ebpf/xdp_pass.c` to BPF object files,
generates Go bindings via `bpf2go`, and builds `gtp-ctrl` at
`build/gtp-ctrl`. Always run a clean build after modifying
`include/gtp_router.h`, anything under `ebpf/`, or Go module dependencies;
an incremental `make all` can reuse a stale generated binding.

After adding or updating a Go dependency:

```bash
cd control && go mod tidy && cd ..
```

## Real 4G/5G Integration

This section documents integration with a real Open5GS core and a real
UERANSIM gNB/UE simulator, in which this router takes over the live
subscriber's data-path role - normally the core's own User Plane
Function's job, while exchanging genuine GTP-U traffic.

### Building Open5GS and UERANSIM

MongoDB is required by Open5GS's subscriber database:

```bash
sudo systemctl start mongodb
sudo systemctl status mongodb
```

Substitute `mongod` above if that service name does not exist on your
system, and confirm it is actually accepting connections:

```bash
ss -lnt | grep 27017
```

Kali's `mongodb` package does not bundle `mongosh`, the shell client
needed to register a subscriber:

```bash
cd /tmp
curl -L -O https://downloads.mongodb.com/compass/mongosh-2.9.2-linux-arm64.tgz
tar xzf mongosh-2.9.2-linux-arm64.tgz
sudo cp mongosh-2.9.2-linux-arm64/bin/mongosh /usr/local/bin/
mongosh --eval 'db.runCommand({ ping: 1 })'   # expect { ok: 1 }
```

Build Open5GS:

```bash
cd ~ && git clone https://github.com/open5gs/open5gs && cd open5gs
meson build --prefix=$(pwd)/install
ninja -C build && sudo ninja -C build install
```

Build UERANSIM:

```bash
cd ~ && git clone https://github.com/aligungr/UERANSIM && cd UERANSIM
make
```

Register a test subscriber. `open5gs-dbctl` lives in the source tree, not
the installed binaries directory:

```bash
~/open5gs/misc/db/open5gs-dbctl add 999700000000001 \
  465B5CE8B199B49FAA5F0A2EE238A6BC E8ED289DEBA952E4283B54E88E6183CA
```

The three values are IMSI, Ki, and OPc, matching UERANSIM's default test
UE configuration (`~/UERANSIM/config/open5gs-ue.yaml`); no further editing
is required. Confirm with `~/open5gs/misc/db/open5gs-dbctl showall`. Both
paths can be overridden via the `OPEN5GS`/`UERANSIM` environment variables
if built elsewhere.

### Hypervisor Network Interface Constraints

Native XDP is implemented at the network driver level, so drivers that do
not support it - for example, the `e1000`/`e1000e` family VirtualBox
commonly emulates - cannot attach in native mode. The `virtio-net` driver
does support it, but requires disabling guest-side checksum/segmentation
offloads first, which in turn requires the hypervisor to negotiate
`VIRTIO_NET_F_CTRL_GUEST_OFFLOADS`. VirtualBox's virtio-net backend does
not negotiate this - confirmed both by direct testing and by long-standing
public VirtualBox reports of the identical symptom - so the affected
offloads report as permanently fixed and native XDP attach fails
unconditionally, regardless of guest configuration. Redirecting XDP frames
out such an interface under load can also stall its transmit ring, which
requires a VM restart to recover. Neither condition is a defect in this
project; both are external hypervisor limitations. The real-traffic
topology below therefore uses veth interfaces for the internet-facing
leg, since veth implements native XDP purely in-kernel, independent of any
hypervisor.

### Interactive Lab Environment

```bash
sudo bash tools/lab.sh
```

This performs the complete bring-up in native mode end to end, with no
fallback to generic mode anywhere in the default path. It applies
one-time, idempotent configuration edits to Open5GS's AMF/UPF and
UERANSIM's gNB/UE, rebinding NGAP and N3/GTP-U from loopback onto a
dedicated veth so the simulated radio network runs inside an isolated
namespace; creates a `ran` namespace and veth pair, starts MongoDB and all
eleven Open5GS network functions in dependency order (each logging to
`/tmp/open5gs/<name>.log`), brings up the UPF's `ogstun` interface, and
configures forwarding and NAT; creates a second veth pair
(`veth-inet0`/`veth-inet1`) as the internet-facing leg, avoiding the
hypervisor limitation above; attaches XDP natively on both legs, stopping
with an error rather than falling back to generic mode if native attach
fails; and opens a `tmux` session (`gtplab`) with five windows -
`control` (an interactive shell plus the live dashboard), `gnb`, `ue`
(which waits for the gNB), `provision`, and `traffic`.

The `provision` window runs `tools/lab_provision.sh`, which waits for the
UE to attach, captures the live uplink and downlink TEIDs directly off the
wire, installs a route forcing the dashboard's test ping through the
actual GTP-U tunnel rather than the namespace's default route, and
provisions the real decapsulation/NAT/encapsulation rules against that
live session automatically - no manual TEID capture is required to see
the router process genuine traffic.

Once `provision` reports that rules are installed, switch to `control`
and press `p` in the dashboard to start the tunnel ping. The `teid_map`
and `nat_map` packet counters climb from zero under confirmed native XDP
operation.

Interactive control-pane verbs each auto-capture the currently live TEID,
which rotates approximately every 72 seconds under sustained load:

```
showteid                        print the live TEID and UE IP
decap                            full-duplex takeover: decap+NAT uplink, NAT+encap downlink
drop                              discard this subscriber's tunnel
redirect                          MAC-rewrite and send out the egress interface
ratelimit [pps]                   cap this subscriber (default 5 packets/second)
quarantine [pps] [thr] [secs]     cap, plus auto hard-block after [thr] violated windows
clearrule                         remove this subscriber's rules, returning control to the UPF
```

Dashboard keys: `a` add, `e`/Enter edit, `d`/`x` delete, `p` start/stop the
tunnel ping, `c` snapshot, `q`/Ctrl-C quit.

```bash
sudo bash tools/lab.sh --down
```

The Open5GS core itself is left running, so a later `lab.sh` run does not
need to re-register the subscriber. Stop it separately:

```bash
sudo bash tools/stop_5gc.sh
```

### Standalone Round-Trip Verification

```bash
sudo bash tools/setup_ran.sh      # if the base RAN infrastructure is not already up
sudo bash tools/veth_roundtrip.sh
```

This is a single, non-interactive proof of the complete data path -
decapsulation, static NAT, and 5G NR re-encapsulation, in both directions,
with native mode asserted at every hop. It recreates the veth "internet"
standin, attaches the router in native mode on both legs, attaches a
minimal pass-through XDP stub (`ebpf/xdp_pass.c`) on the two receiving
veth peers - a veth only accepts a redirected frame when its peer runs an
XDP program, so this stub exists purely to keep that path native and is
not part of the router's own logic - starts a fresh gNB and UE, captures
the live TEIDs, provisions the rules, and reports a result block, for
example:

```
UE ping loss                         : 0% packet loss
uplink   decap+NAT teid_map[0x...] pkts : 6
downlink NAT+encap nat_map[...] pkts    : 6
```

Before that, it asserts native mode on every data-path interface directly
from `ip link show` and aborts if any interface reports `xdpgeneric`
rather than `xdp`.

Tear down just this standin leg, leaving the RAN infrastructure and core
running:

```bash
sudo bash tools/veth_roundtrip.sh --down
```

### Manual Control Sequence

What the scripts above automate, made explicit:

```bash
sudo bash tools/setup_ran.sh
# separate terminals:
cd ~/UERANSIM && sudo ip netns exec ran ./build/nr-gnb -c config/open5gs-gnb.yaml
cd ~/UERANSIM && sudo ip netns exec ran ./build/nr-ue  -c config/open5gs-ue.yaml

sudo ./build/gtp-ctrl load --iface veth-ran --mode native \
  --dl-iface <egress-iface> --dl-mode native

sudo ./build/gtp-ctrl add-teid --teid 0x<TEID> --action decap \
  --out-iface <egress-iface> --dmac <mac> --smac <mac> --nat-ip <ip>
sudo ./build/gtp-ctrl add-nat --nat-ip <ip> --ue-ip <ue-ip> \
  --teid-out 0x<downlink-TEID> --src-ip <ip> --dst-ip <ip> \
  --out-iface veth-ran --dmac <mac> --smac <mac>

sudo ./build/gtp-ctrl list
sudo ./build/gtp-ctrl dashboard
sudo ./build/gtp-ctrl unload --iface veth-ran
```

`tools/setup_ran.sh --down` tears down the RAN namespace and veth without
stopping the Open5GS core.

## Synthetic Test Topology

This topology confirms the router builds and forwards correctly in a
self-contained, two-namespace environment, independent of the real 5G
integration above. It requires no external projects and no radio hardware.

```bash
sudo bash tools/setup_netns.sh
```

This provisions two namespaces, `gnb` and `core`, connected through the
default namespace by veth pairs, attaches the XDP program to the
gNB-facing interface, and inserts a default decapsulation rule for TEID
`0xDEAD`.

```
[gnb namespace]              [default namespace]              [core namespace]
veth-gnb0 ------ veth-gnb1 (XDP attached)   veth-core0 ------ veth-core1
10.0.0.1         10.0.0.2                    10.0.1.1          10.0.1.2
```

GTP-U traffic enters on `veth-gnb1`, where the program is attached. A
matching uplink rule decapsulates the tunnel and redirects the inner
packet through `veth-core0`, arriving on `veth-core1`. A matching downlink
rule performs the inverse: a bare packet is encapsulated and redirected
back toward the `gnb` namespace. The addresses `10.1.0.1` and `10.1.0.2`
represent subscriber endpoints inside the tunnel payload; they are not
bound to any interface and exist only as test payload data.

`setup_netns.sh` can be re-run at any point to restore a clean state. To
remove the topology without recreating it:

```bash
sudo bash tools/teardown_netns.sh
```

Four scripts validate correct operation end to end, each provisioning its
own rule state, generating scapy traffic, and reporting a pass/fail
summary:

```bash
sudo bash tools/verify.sh             # uplink decapsulation
sudo bash tools/verify_encap.sh       # downlink encapsulation
sudo bash tools/verify_ratelimit.sh   # per-subscriber rate limiting
sudo bash tools/verify_quarantine.sh  # autonomous quarantine
```

Run these after every build. They use synthetic scapy traffic only and do
not exercise 5G NR extension header parsing, NAT, or the lab tooling above.

## Control Plane Reference

| Command | Description |
|---|---|
| `gtp-ctrl load --iface <name> [--mode native\|generic\|offload] [--dl-iface <name>] [--dl-mode ...]` | Attach the XDP program. `--dl-iface` additionally attaches on a second interface for the downlink direction. |
| `gtp-ctrl unload --iface <name>` | Detach the XDP program and remove pinned maps. |
| `gtp-ctrl add-teid` | Insert or update a rule keyed by GTP-U TEID. |
| `gtp-ctrl del-teid --teid <id>` | Remove a TEID-keyed rule. |
| `gtp-ctrl add-ueip` | Insert or update a rule keyed by subscriber IP. |
| `gtp-ctrl del-ueip --ip <addr>` | Remove a UE-IP-keyed rule. |
| `gtp-ctrl add-nat` | Insert or update a static NAT rule: downlink packets destined for `--nat-ip` are restored to `--ue-ip` and re-encapsulated toward the gNB. |
| `gtp-ctrl del-nat --nat-ip <ip>` | Remove a NAT rule. |
| `gtp-ctrl list` | Display every rule, across all three tables, with counters. |
| `gtp-ctrl stats [--watch]` | Display aggregate verdict counters. |
| `gtp-ctrl dashboard` | Launch the interactive terminal dashboard. |

Each subcommand supports `--help` for its complete flag reference.

### Rule Provisioning (synthetic topology)

A rule requires an egress interface and source/destination MAC addresses
for the outgoing frame. In the synthetic topology these can be read after
`setup_netns.sh`:

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

Supported actions are `drop`, `decap`, `encap`, and `redirect`. `add-teid`
additionally accepts `--nat-ip` to install the static uplink NAT rewrite
described above.

### Per-Subscriber Policy Enforcement

`add-teid` and `add-ueip` accept the following policy flags, applicable
regardless of the configured action:

| Flag | Description |
|---|---|
| `--rate-pps <n>` | Maximum packets per second for this subscriber. Traffic in excess of this rate is dropped. A value of 0, or omission, disables rate limiting. |
| `--quarantine-threshold <n>` | Consecutive one-second windows that must exceed the rate cap before the subscriber is automatically quarantined. Requires `--rate-pps` and `--quarantine-seconds`. |
| `--quarantine-seconds <n>` | Duration of an automatically triggered quarantine, after which it self-releases without external intervention. |

Example - a rule capped at 100 packets per second, escalating to a 30
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
expiry is not polled by a timer; it is evaluated lazily, on the next
packet the subscriber sends after the deadline has passed.

## Traffic Generation (synthetic topology)

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

Launches a full-screen terminal interface displaying the TEID and UE-IP
rule tables and the aggregate verdict counters, refreshed at a
configurable interval (`--interval`, default one second). Rules can be
inserted, modified, and removed directly from the dashboard while traffic
continues to flow.

| Key | Action |
|---|---|
| Tab | Switch focus between the TEID and UE-IP rule tables |
| Up / Down | Move the row selection within the focused table |
| a | Open the form to add a new rule for the focused table |
| e or Enter | Open the form to edit the selected rule |
| d or x | Delete the selected rule, with confirmation |
| p | Start or stop a traffic ping through the live tunnel (used in the real-integration lab) |
| c | Write a plain-text snapshot of the current view to /tmp/gtp-dashboard-snapshot.txt |
| ? or h | Show the built-in manual |
| q or Ctrl-C | Exit |

Within the add or edit form: Tab and Shift-Tab move between fields, Left
and Right cycle the action, Enter submits, Escape cancels without applying
changes.

Editing an existing rule replaces it in full, including its counters -
there is no partial update, so packet, byte, and drop counters reset to
zero on edit.

`nat_map` rules are not currently displayed in the dashboard; manage them
via `gtp-ctrl add-nat` / `del-nat` / `list`, or the `decap`/`clearrule`
control-pane verbs in the real-integration lab, which provision and
remove both the TEID and NAT rule together.

## Project Layout

```
ebpf/                   XDP program source (gtp_xdp.c, and the xdp_pass.c
                        pass-through stub used to keep veth peers in
                        native mode), compiled to BPF object files
include/                Struct definitions shared by the eBPF program and
                        the Go control plane, defining the BPF map schema
control/
  cmd/                  gtp-ctrl subcommands
  maps/                 BPF map access, the forwarding rule structure,
                        and rule validation
  stats/                Aggregate counter access
  loader/                XDP attach and detach (uplink and optional
                        downlink interfaces), generated eBPF bindings
  tui/                   Interactive dashboard implementation
tools/
  setup_netns.sh          Synthetic two-namespace test topology
  teardown_netns.sh       Tears down the synthetic topology
  verify*.sh              Synthetic-topology regression scripts
  gen_gtp_traffic.py      Scapy-based synthetic GTP-U traffic generator
  SETUP_5GC.md            Open5GS/UERANSIM build and bring-up runbook
  start_5gc.sh            Starts all Open5GS network functions in order
  stop_5gc.sh             Stops the Open5GS network functions
  setup_ran.sh            Brings up the RAN network namespace, veth, and
                        core data-plane prerequisites (ogstun/NAT/forwarding)
  ran.conf                Editable demo/harness knobs (egress interface,
                        NAT address, traffic-generator settings)
  lab.sh                  One-command interactive lab: full bring-up plus
                        a tmux control room with the dashboard
  lab_provision.sh        Auto-captures live TEIDs and provisions the real
                        round-trip rules against the live session
  lab_helpers.sh          Interactive control-pane verbs (showteid, decap,
                        drop, redirect, ratelimit, quarantine, clearrule)
  veth_roundtrip.sh       Standalone, non-interactive, fully-native
                        round-trip proof against real 5G traffic
```

## Troubleshooting

**`make all` fails with a missing Go module error.**
Run `cd control && go mod tidy && cd ..`, then rebuild.

**The dashboard's rule tables appear clipped or columns are missing.**
The layout adapts to terminal width; widen the terminal past roughly 60
columns.

**A verification script fails after manual testing through the dashboard
or CLI.**
Manually created rules can persist and interfere with a script's
assumptions about initial state. Run `tools/teardown_netns.sh` then
`tools/setup_netns.sh` to restore a clean topology, then retry.

**A rule's counters reset unexpectedly.**
This happens whenever a rule is re-inserted via `add-teid`, `add-ueip`,
`add-nat`, or the dashboard's edit form - these operations replace the
rule in its entirety, with no partial-update path that preserves counters.

**`gtp-ctrl load --mode native` fails on a hypervisor's virtual NIC.**
See "Hypervisor Network Interface Constraints" above - a hypervisor/driver
limitation, not a defect in the router. Use the veth standin topology
(`tools/lab.sh` or `tools/veth_roundtrip.sh`) for a fully native
demonstration independent of the host's NIC driver.

**A rule shows zero packets even though traffic is flowing.**
Two distinct causes. The rule's key may not match what is currently on
the wire - TEIDs rotate approximately every 72 seconds under load, so a
rule provisioned against a stale, manually recorded TEID will not match;
recapture it with `showteid` or re-run `lab_provision.sh`. Alternatively,
traffic may be reaching an incorrect destination - addressing a peer
directly from inside the `ran` namespace without the route
`lab_provision.sh` installs bypasses the tunnel entirely via the
namespace's default route. In both cases, a rising PASS counter in
`gtp-ctrl stats` alongside a rule counter stuck at zero means the hook is
processing traffic that does not match that rule's key, not that the hook
is broken.

**Open5GS network functions fail to start after a fresh boot.**
`systemd` can report MongoDB active before it is accepting connections on
port 27017. `tools/start_5gc.sh` waits for the socket; if starting the
core manually, confirm with `ss -lnt | grep 27017` first.
