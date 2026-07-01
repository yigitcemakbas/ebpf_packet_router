# Real 4G/5G Integration: Open5GS + UERANSIM

This runbook brings up a real 5G core (Open5GS) and a real gNB/UE simulator
(UERANSIM), then hands the live PDU session's N3 data plane to this router
instead of Open5GS's own UPF process. No code in this repository changes for
this: `decap_fwd` and `encap_fwd` already do exactly what a UPF's N3-to-N6
and N6-to-N3 data plane does. This is wiring, not development.

Everything here targets this project's existing ARM64 Kali VM
(`linux/arm64`, confirmed via `uname -m`).

## Why Open5GS instead of free5gc

free5gc's official Docker deployment (`free5gc-compose`) ships
`linux/amd64`-only images and will not run on this VM. UERANSIM has full
ARM64 support either way. Open5GS is ARM64-viable, but only via a source
build - there is no prebuilt ARM64 package.

## 1. Build Open5GS from source

```bash
sudo apt update
sudo apt install -y python3-pip python3-setuptools python3-wheel \
    ninja-build build-essential flex bison git libsctp-dev libgnutls28-dev \
    libgcrypt-dev libssl-dev libidn11-dev libmongoc-dev libbson-dev \
    libyaml-dev libnghttp2-dev libmicrohttpd-dev libcurl4-gnutls-dev \
    libnghttp2-dev libtins-dev libtalloc-dev meson mongodb

# MongoDB on ARM64 needs ARMv8.2-A or newer. Confirm before relying on it:
lscpu | grep -i "Model name"

git clone https://github.com/open5gs/open5gs
cd open5gs
meson build --prefix=`pwd`/install
ninja -C build
sudo ninja -C build install
```

If `mongodb` from apt is unavailable or refuses to start on this CPU, use
Open5GS's MongoDB-free minimal config (subscriber data only needs to persist
for the duration of the demo - a single hand-edited subscriber via the WebUI
is enough either way).

## 2. Build UERANSIM from source

```bash
sudo apt install -y cmake build-essential libsctp-dev lksctp-tools
git clone https://github.com/aligungr/UERANSIM
cd UERANSIM
make
```

Produces `build/nr-gnb` and `build/nr-ue`.

## 3. Bring up the core and confirm a PDU session establishes

Follow Open5GS's standard quickstart (AMF/SMF/UPF/etc. as systemd services
or run manually; register a test subscriber via the WebUI at
`http://127.0.0.1:9999`, IMSI/key/OPc matching UERANSIM's `ue.yaml`).

Start UERANSIM's gNB, then the UE:

```bash
sudo ./build/nr-gnb -c config/free5gc-gnb.yaml   # or open5gs-gnb.yaml
sudo ./build/nr-ue  -c config/open5gs-ue.yaml
```

Confirm the UE attaches and a PDU session establishes - `nr-ue` reports a
new `uesimtun0` interface and a ping through it succeeds. This step is a
standard Open5GS/UERANSIM smoke test, independent of this router; do not
proceed until it works on its own.

At this point Open5GS's own `upfd` is servicing the session end-to-end.

## 4. Discover the real TEID and UE IP

The TEID is negotiated dynamically over PFCP between the SMF and UPF - it is
not known ahead of time. With the PDU session established, generate some
traffic (`ping` from inside the UE's namespace, or through `uesimtun0`) and
observe:

```bash
sudo tcpdump -i <gNB-facing interface> -nn udp port 2152
```

Note the uplink TEID in the GTP-U header, and the UE IP Open5GS assigned
(visible in the `nr-ue` log or via `ip addr show uesimtun0`). The downlink
TEID (the one the gNB expects to receive on) is visible in the same capture,
in the reverse-direction GTP-U headers Open5GS's UPF sends back, or in the
PFCP session-establishment exchange.

## 5. Attach this router to the real N3 link

Identify the real interface facing the gNB (whatever UERANSIM's `nr-gnb` is
bound to) and load the XDP program on it, exactly as `setup_netns.sh` does
for the synthetic test topology:

```bash
sudo ./build/gtp-ctrl load --iface <gNB-facing-iface> --mode generic
```

## 6. Take over the data plane for this subscriber

Point the egress at the VM's real internet-facing interface and enable NAT
once:

```bash
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

Provision the uplink rule (decapsulate this subscriber's GTP-U traffic and
forward the inner packet out to the real internet):

```bash
ETH0_MAC=$(cat /sys/class/net/eth0/address)
GNB_IFACE_MAC=$(cat /sys/class/net/<gNB-facing-iface>/address)

sudo ./build/gtp-ctrl add-teid \
  --teid <uplink TEID from step 4> \
  --action decap \
  --out-iface eth0 \
  --dmac "$ETH0_MAC" \
  --smac "$GNB_IFACE_MAC"
```

Provision the downlink rule (wrap return traffic back into a GTP-U tunnel
toward the gNB):

```bash
sudo ./build/gtp-ctrl add-ueip \
  --ip <UE IP from step 4> \
  --action encap \
  --teid-out <downlink TEID from step 4> \
  --src-ip <this VM's IP on the gNB-facing interface> \
  --dst-ip <gNB's IP> \
  --out-iface <gNB-facing-iface> \
  --dmac "$GNB_IFACE_MAC" \
  --smac "$ETH0_MAC"
```

Open5GS's `upfd` no longer needs to see this subscriber's user-plane
traffic - this router is now the N3 termination point for it. AMF/SMF and
PFCP signaling are untouched and still real.

## 7. Verify end-to-end

From inside the UE's namespace (or through `uesimtun0`), run a ping or
`iperf3` against a real internet host and confirm it succeeds - the traffic
is now flowing through this router's existing `decap_fwd`/`encap_fwd` data
plane, not Open5GS's UPF. Watch it live:

```bash
sudo ./build/gtp-ctrl dashboard
```

`PACKETS`/`PPS` on the provisioned TEID and UE-IP rules should climb in step
with the UE's real traffic.

## 8. Demonstrate autonomous quarantine against real traffic

Add rate limiting and quarantine to the same uplink rule (re-running
`add-teid` overwrites it in place):

```bash
sudo ./build/gtp-ctrl add-teid \
  --teid <uplink TEID> \
  --action decap \
  --out-iface eth0 \
  --dmac "$ETH0_MAC" \
  --smac "$GNB_IFACE_MAC" \
  --rate-pps 50 \
  --quarantine-threshold 3 \
  --quarantine-seconds 30
```

Flood from inside the UE's session past the cap (e.g. `iperf3 -u -b 500M`
through `uesimtun0`) and watch the dashboard: `RATE-DROPS` climbing, the
rule entering quarantine after 3 consecutive violated windows, this
subscriber's real traffic fully blocked, then self-released after the
cooldown - the same behavior `tools/verify_quarantine.sh` proves against
synthetic traffic, now against a real, PFCP-negotiated PDU session.

## Teardown

```bash
sudo ./build/gtp-ctrl unload --iface <gNB-facing-iface>
sudo iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
```

Then stop `nr-ue`, `nr-gnb`, and the Open5GS services in the usual way.
