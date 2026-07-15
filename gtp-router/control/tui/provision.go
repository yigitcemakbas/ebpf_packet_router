// provision.go implements the dashboard's "t" key: provision the REAL
// round-trip rules from the currently-running 5G session, instead of inserting
// fake placeholder rules. It captures the live uplink/downlink TEIDs (which
// rotate every session) and the UE IP straight off the wire, then installs a
// decap+NAT rule in teid_map (uplink) and an encap rule in nat_map (downlink) -
// exactly what tools/lab_provision.sh does, folded into the dashboard so a
// single keystroke wires the panels to live traffic.
package tui

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/gtp-router/control/maps"
)

// labTopo is the veth-lab (tools/lab.sh) interface/addressing layout the live
// provisioning needs. Every field has an env override whose name matches what
// tools/lab.sh already exports, with a default matching the lab's veth standin
// so "t" works out of the box and can be repointed at another topology.
type labTopo struct {
	netns  string // UE network namespace (the gNB/UE live here)
	veth   string // gNB-facing veth on the host: uplink ingress / downlink egress
	vethNS string // its peer inside netns: downlink next-hop (dmac)
	inetNS string // "internet" namespace holding the uplink egress peer
	vinet0 string // uplink egress iface on the host
	vinet1 string // its peer in inetNS: uplink next-hop (dmac)
	hostN3 string // UPF/router N3 IP (outer src on downlink encap)
	ranN3  string // gNB N3 IP (outer dst on downlink encap)
	peerIP string // the "internet host" the UE pings (uplink nudge target)
	natIP  string // in-XDP static 1:1 NAT address
}

func topoFromEnv() labTopo {
	return labTopo{
		netns:  envOr("NETNS", "ran"),
		veth:   envOr("VETH", "veth-ran"),
		vethNS: envOr("VRANNS", "veth-ran-ns"),
		inetNS: envOr("INET_NS", "inet"),
		vinet0: envOr("VINET0", "veth-inet0"),
		vinet1: envOr("VINET1", "veth-inet1"),
		hostN3: envOr("HOST_N3", "10.201.0.1"),
		ranN3:  envOr("RAN_N3", "10.201.0.2"),
		peerIP: envOr("PEER_IP", "10.99.0.2"),
		natIP:  envOr("NAT_IP", "10.99.0.10"),
	}
}

// provisionResultMsg is delivered back to Update when the (async) live
// provisioning finishes.
type provisionResultMsg struct {
	err    error
	teid   uint32 // uplink TEID (teid_map key)
	dlteid uint32 // downlink TEID (encapped toward the gNB)
	ueIP   string
}

// captureScript nudges the tunnel in both directions and snapshots the live
// TEIDs + the MACs of the two egress legs. It prints key=value lines on stdout;
// an "ERR=" line signals a soft failure (no live UE) that should surface as a
// friendly status rather than a crash. The TEID extraction (offset 0x0020 of
// the GTP-U frame) mirrors tools/lab_provision.sh / veth_roundtrip.sh.
const captureScript = `set -u
D=$(mktemp -d)
UEIP=$(ip netns exec {{NETNS}} ip -4 -o addr show uesimtun0 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
if [ -z "$UEIP" ]; then echo "ERR=no live UE (uesimtun0 is down in netns {{NETNS}}); is the gNB+UE attached?"; rm -rf "$D"; exit 0; fi
# nudge both directions so the live G-PDUs fly past the taps: ping the UE from
# the host (downlink) and ping the peer through the tunnel (uplink).
( for k in $(seq 1 24); do ping -c1 -W1 "$UEIP" >/dev/null 2>&1; sleep 0.3; done ) & NDL=$!
ip netns exec {{NETNS}} ping -i 0.3 -I uesimtun0 {{PEER}} >/dev/null 2>&1 & NUL=$!
timeout 8 tcpdump -i {{VETH}} -nn -x "udp port 2152 and src {{HOST}} and dst {{RAN}}" -c1 >"$D/dl" 2>/dev/null & PDL=$!
timeout 8 tcpdump -i {{VETH}} -nn -x "udp port 2152 and src {{RAN}} and dst {{HOST}}" -c1 >"$D/ul" 2>/dev/null & PUL=$!
wait $PDL $PUL 2>/dev/null
kill $NDL $NUL 2>/dev/null
echo "UEIP=$UEIP"
echo "TEID=$(grep 0x0020 "$D/ul" | awk '{print "0x"$2$3}')"
echo "DLTEID=$(grep 0x0020 "$D/dl" | awk '{print "0x"$2$3}')"
echo "VINET0_MAC=$(cat /sys/class/net/{{VINET0}}/address 2>/dev/null)"
echo "VINET1_MAC=$(ip netns exec {{INET}} cat /sys/class/net/{{VINET1}}/address 2>/dev/null)"
echo "VETH_MAC=$(cat /sys/class/net/{{VETH}}/address 2>/dev/null)"
echo "VRANNS_MAC=$(ip netns exec {{NETNS}} cat /sys/class/net/{{VETHNS}}/address 2>/dev/null)"
rm -rf "$D"
`

// provisionLiveCmd captures the live session and installs the round-trip rules.
// It runs as a tea.Cmd (its own goroutine) so the dashboard keeps refreshing
// during the ~8s capture. tm is the already-open teid_map; the nat_map is
// opened and closed here since the dashboard doesn't otherwise hold it.
func provisionLiveCmd(tm *maps.TeidMap, topo labTopo) tea.Cmd {
	return func() tea.Msg {
		vals, err := runCapture(topo)
		if err != nil {
			return provisionResultMsg{err: err}
		}
		if e := vals["ERR"]; e != "" {
			return provisionResultMsg{err: fmt.Errorf("%s", e)}
		}

		teid, dlteid, ueIP, err := parseCapture(vals)
		if err != nil {
			return provisionResultMsg{err: err}
		}

		if err := installLiveRules(tm, topo, vals, teid, dlteid, ueIP); err != nil {
			return provisionResultMsg{err: err}
		}

		// Force the peer through the tunnel so the dashboard's plain `ping
		// <peer>` (the "p" ping has no -I uesimtun0) traverses the UE's PDU
		// session instead of the namespace default route - otherwise the rules
		// just installed never see the ping. Best-effort: the rules are already
		// in, so a route hiccup shouldn't fail the whole provision.
		_ = exec.Command("ip", "netns", "exec", topo.netns,
			"ip", "route", "replace", topo.peerIP+"/32", "dev", "uesimtun0").Run()

		return provisionResultMsg{teid: teid, dlteid: dlteid, ueIP: ueIP.String()}
	}
}

func runCapture(topo labTopo) (map[string]string, error) {
	script := strings.NewReplacer(
		"{{NETNS}}", topo.netns,
		"{{VETH}}", topo.veth,
		"{{VETHNS}}", topo.vethNS,
		"{{INET}}", topo.inetNS,
		"{{VINET0}}", topo.vinet0,
		"{{VINET1}}", topo.vinet1,
		"{{HOST}}", topo.hostN3,
		"{{RAN}}", topo.ranN3,
		"{{PEER}}", topo.peerIP,
	).Replace(captureScript)

	out, err := exec.Command("bash", "-c", script).Output()
	if err != nil {
		return nil, fmt.Errorf("capture failed (need root; is the session up?): %w", err)
	}

	vals := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			vals[k] = strings.TrimSpace(v)
		}
	}
	return vals, nil
}

func parseCapture(vals map[string]string) (teid, dlteid uint32, ueIP net.IP, err error) {
	if vals["TEID"] == "" {
		return 0, 0, nil, fmt.Errorf("no uplink TEID seen - is the UE passing traffic?")
	}
	if vals["DLTEID"] == "" {
		return 0, 0, nil, fmt.Errorf("no downlink TEID seen - did the UPF emit a downlink G-PDU?")
	}
	teid, err = parseHexOrDec(vals["TEID"])
	if err != nil {
		return 0, 0, nil, fmt.Errorf("uplink teid: %w", err)
	}
	dlteid, err = parseHexOrDec(vals["DLTEID"])
	if err != nil {
		return 0, 0, nil, fmt.Errorf("downlink teid: %w", err)
	}
	ueIP = net.ParseIP(vals["UEIP"])
	if ueIP == nil || ueIP.To4() == nil {
		return 0, 0, nil, fmt.Errorf("bad UE IP %q", vals["UEIP"])
	}
	return teid, dlteid, ueIP, nil
}

// installLiveRules writes the uplink decap+NAT rule (teid_map) and the downlink
// encap rule (nat_map), mirroring add_teid.go/add_nat.go, and registers both
// egress ifindexes as valid bpf_redirect_map targets.
func installLiveRules(tm *maps.TeidMap, topo labTopo, vals map[string]string, teid, dlteid uint32, ueIP net.IP) error {
	vinet0Mac, err := maps.ParseMAC(vals["VINET0_MAC"])
	if err != nil {
		return fmt.Errorf("vinet0 mac: %w", err)
	}
	vinet1Mac, err := maps.ParseMAC(vals["VINET1_MAC"])
	if err != nil {
		return fmt.Errorf("vinet1 mac: %w", err)
	}
	vethMac, err := maps.ParseMAC(vals["VETH_MAC"])
	if err != nil {
		return fmt.Errorf("veth mac: %w", err)
	}
	vranssMac, err := maps.ParseMAC(vals["VRANNS_MAC"])
	if err != nil {
		return fmt.Errorf("veth-ns mac: %w", err)
	}

	vinet0, err := net.InterfaceByName(topo.vinet0)
	if err != nil {
		return fmt.Errorf("egress %s: %w", topo.vinet0, err)
	}
	veth, err := net.InterfaceByName(topo.veth)
	if err != nil {
		return fmt.Errorf("egress %s: %w", topo.veth, err)
	}

	natIP := net.ParseIP(topo.natIP)
	if natIP == nil || natIP.To4() == nil {
		return fmt.Errorf("bad NAT_IP %q", topo.natIP)
	}
	natU32, err := maps.IPToUint32(natIP)
	if err != nil {
		return err
	}
	ueU32, err := maps.IPToUint32(ueIP)
	if err != nil {
		return err
	}
	hostU32, err := ipToU32(topo.hostN3)
	if err != nil {
		return fmt.Errorf("HOST_N3: %w", err)
	}
	ranU32, err := ipToU32(topo.ranN3)
	if err != nil {
		return fmt.Errorf("RAN_N3: %w", err)
	}

	// uplink: decap the GTP-U, NAT the UE src -> NAT_IP, redirect out vinet0.
	uplink := &maps.FwdRule{
		Action:     maps.ActionDecapFwd,
		OutIfindex: uint32(vinet0.Index),
		DMac:       vinet1Mac,
		SMac:       vinet0Mac,
		NatIP:      natU32,
	}
	if err := maps.ValidateRule(uplink); err != nil {
		return fmt.Errorf("uplink rule: %w", err)
	}

	// downlink: dst==NAT_IP -> restore dst to the UE, GTP-U encap toward the gNB.
	downlink := &maps.FwdRule{
		Action:     maps.ActionEncapFwd,
		OutIfindex: uint32(veth.Index),
		DMac:       vranssMac,
		SMac:       vethMac,
		TeidOut:    dlteid,
		SrcIP:      hostU32,
		DstIP:      ranU32,
		NatIP:      ueU32, // nat_map value: UE IP to restore as inner dst
	}
	if err := maps.ValidateRule(downlink); err != nil {
		return fmt.Errorf("downlink rule: %w", err)
	}

	if err := tm.Put(teid, uplink); err != nil {
		return fmt.Errorf("teid_map put: %w", err)
	}
	nm, err := maps.OpenNatMap()
	if err != nil {
		return err
	}
	defer nm.Close()
	if err := nm.Put(natIP, downlink); err != nil {
		return fmt.Errorf("nat_map put: %w", err)
	}

	// Both egress ifindexes must be valid devmap targets or the redirect drops.
	if err := maps.EnsureTxPort(uint32(vinet0.Index)); err != nil {
		return err
	}
	return maps.EnsureTxPort(uint32(veth.Index))
}

func ipToU32(s string) (uint32, error) {
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return 0, fmt.Errorf("invalid IPv4 %q", s)
	}
	return maps.IPToUint32(ip)
}
