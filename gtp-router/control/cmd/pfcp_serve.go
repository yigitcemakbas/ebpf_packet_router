package cmd

import (
	"fmt"
	"net"

	"github.com/spf13/cobra"

	"github.com/gtp-router/control/maps"
	"github.com/gtp-router/control/pfcp"
)

var (
	pfcpListen  string
	pfcpNodeID  string
	pfcpN3Addr  string
	pfcpULIface string
	pfcpULDMac  string
	pfcpULSMac  string
	pfcpDLIface string
	pfcpDLDMac  string
	pfcpDLSMac  string
	pfcpNATBase string
)

var pfcpServeCmd = &cobra.Command{
	Use:   "pfcp-serve",
	Short: "Run a minimal PFCP (N4) server so a real SMF can drive this router as its UPF",
	Long: `Start the router's PFCP/N4 control interface (3GPP TS 29.244) on UDP/8805.

This is the standards-defined way a UPF is provisioned: a real 5G core's SMF
(e.g. Open5GS) establishes, modifies, and deletes GTP-U sessions on this router
exactly as it would on any UPF. Incoming Session Establishment messages are
translated into the same teid_map/nat_map rules the add-teid/add-nat subcommands
install (the manual alternative to this); the router must already be loaded
(gtp-ctrl load) so those pinned maps exist.

PFCP conveys TEIDs, UE IPs, and the gNB tunnel endpoint, but not L2 addressing
or which interface to egress on, so those are supplied here as flags exactly as
they are for add-teid/add-nat. UE traffic is statically NATed to an egress
address per session (--nat-base + n); those addresses must already be reachable
on the uplink egress interface.`,
	Example: `  # Point Open5GS's SMF at this host's N4 address, stop open5gs-upfd, then:
  sudo ./build/gtp-ctrl pfcp-serve \
    --listen 10.201.0.1:8805 --n3-addr 10.201.0.1 \
    --ul-iface veth-inet0 --ul-dmac <peer-mac> --ul-smac <veth-inet0-mac> \
    --dl-iface veth-ran    --dl-dmac <veth-ran-ns-mac> --dl-smac <veth-ran-mac> \
    --nat-base 10.99.0.10`,
	RunE: func(cmd *cobra.Command, args []string) error {
		n3 := net.ParseIP(pfcpN3Addr)
		if n3 == nil || n3.To4() == nil {
			return fmt.Errorf("invalid --n3-addr: %s", pfcpN3Addr)
		}
		nodeID := n3
		if pfcpNodeID != "" {
			nodeID = net.ParseIP(pfcpNodeID)
			if nodeID == nil || nodeID.To4() == nil {
				return fmt.Errorf("invalid --node-id: %s", pfcpNodeID)
			}
		}
		natBase := net.ParseIP(pfcpNATBase)
		if natBase == nil || natBase.To4() == nil {
			return fmt.Errorf("invalid --nat-base: %s", pfcpNATBase)
		}

		ulDMac, err := maps.ParseMAC(pfcpULDMac)
		if err != nil {
			return fmt.Errorf("--ul-dmac: %w", err)
		}
		ulSMac, err := maps.ParseMAC(pfcpULSMac)
		if err != nil {
			return fmt.Errorf("--ul-smac: %w", err)
		}
		dlDMac, err := maps.ParseMAC(pfcpDLDMac)
		if err != nil {
			return fmt.Errorf("--dl-dmac: %w", err)
		}
		dlSMac, err := maps.ParseMAC(pfcpDLSMac)
		if err != nil {
			return fmt.Errorf("--dl-smac: %w", err)
		}

		cfg := pfcp.Config{
			Listen:  pfcpListen,
			NodeIP:  nodeID,
			N3IP:    n3,
			ULIface: pfcpULIface,
			ULDMac:  ulDMac,
			ULSMac:  ulSMac,
			DLIface: pfcpDLIface,
			DLDMac:  dlDMac,
			DLSMac:  dlSMac,
			NATBase: natBase,
		}
		return pfcp.Serve(cfg)
	},
}

func init() {
	pfcpServeCmd.Flags().StringVar(&pfcpListen, "listen", "10.201.0.1:8805", "UDP address to bind PFCP/N4 on")
	pfcpServeCmd.Flags().StringVar(&pfcpNodeID, "node-id", "", "Our Node ID / F-SEID IPv4 (default: --n3-addr)")
	pfcpServeCmd.Flags().StringVar(&pfcpN3Addr, "n3-addr", "10.201.0.1", "UP IPv4 advertised in the uplink F-TEID (where the gNB sends uplink G-PDUs)")
	pfcpServeCmd.Flags().StringVar(&pfcpULIface, "ul-iface", "", "Uplink egress interface (toward N6/internet) (required)")
	pfcpServeCmd.Flags().StringVar(&pfcpULDMac, "ul-dmac", "", "Uplink egress next-hop MAC (required)")
	pfcpServeCmd.Flags().StringVar(&pfcpULSMac, "ul-smac", "", "Uplink egress source MAC (required)")
	pfcpServeCmd.Flags().StringVar(&pfcpDLIface, "dl-iface", "", "Downlink egress interface (toward gNB) (required)")
	pfcpServeCmd.Flags().StringVar(&pfcpDLDMac, "dl-dmac", "", "Downlink egress next-hop MAC, i.e. the gNB-side veth peer (required)")
	pfcpServeCmd.Flags().StringVar(&pfcpDLSMac, "dl-smac", "", "Downlink egress source MAC (required)")
	pfcpServeCmd.Flags().StringVar(&pfcpNATBase, "nat-base", "10.99.0.10", "First static-NAT egress IP; session n is NATed to nat-base + n")

	for _, f := range []string{"ul-iface", "ul-dmac", "ul-smac", "dl-iface", "dl-dmac", "dl-smac"} {
		_ = pfcpServeCmd.MarkFlagRequired(f)
	}
}
