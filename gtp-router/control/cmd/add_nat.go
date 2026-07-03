package cmd

import (
	"fmt"
	"net"

	"github.com/spf13/cobra"

	"github.com/gtp-router/control/maps"
)

var (
	addNatNatIP   string
	addNatUeIP    string
	addNatOutIface string
	addNatDMac    string
	addNatSMac    string
	addNatTeidOut uint32
	addNatDstIP   string
	addNatSrcIP   string
)

var addNatCmd = &cobra.Command{
	Use:   "add-nat",
	Short: "Insert or update a static 1:1 NAT rule in nat_map (downlink path on eth0)",
	Long: `Insert or update a rule in nat_map.

When eth0 receives a packet whose destination IP matches --nat-ip, the XDP
program rewrites the destination back to --ue-ip, encapsulates the packet in
a GTP-U tunnel described by the remaining flags, and redirects it out
--out-iface toward the gNB.

This is the downlink counterpart to:
  gtp-ctrl add-teid --nat-ip <nat-ip> ...
which rewrites the source of uplink packets from the UE IP to the NAT IP.`,
	Example: `  gtp-ctrl add-nat \
    --nat-ip  192.168.10.73 \
    --ue-ip   10.45.0.2 \
    --teid-out 0x00000001 \
    --src-ip  10.201.0.1 \
    --dst-ip  10.201.0.2 \
    --out-iface veth-ran \
    --dmac 1a:d2:ab:7b:7e:43 \
    --smac ea:84:c9:05:be:86`,
	RunE: func(cmd *cobra.Command, args []string) error {
		natIP := net.ParseIP(addNatNatIP)
		if natIP == nil || natIP.To4() == nil {
			return fmt.Errorf("invalid --nat-ip: %s", addNatNatIP)
		}
		ueIP := net.ParseIP(addNatUeIP)
		if ueIP == nil || ueIP.To4() == nil {
			return fmt.Errorf("invalid --ue-ip: %s", addNatUeIP)
		}

		rule := &maps.FwdRule{
			Action:  maps.ActionEncapFwd,
			TeidOut: addNatTeidOut,
		}

		// NatIP stores the UE IP so the XDP program knows what to restore dst to.
		var err error
		rule.NatIP, err = maps.IPToUint32(ueIP)
		if err != nil {
			return err
		}

		if addNatOutIface != "" {
			iface, err := net.InterfaceByName(addNatOutIface)
			if err != nil {
				return fmt.Errorf("egress interface %q: %w", addNatOutIface, err)
			}
			rule.OutIfindex = uint32(iface.Index)
		}

		if addNatDMac != "" {
			rule.DMac, err = maps.ParseMAC(addNatDMac)
			if err != nil {
				return fmt.Errorf("--dmac: %w", err)
			}
		}
		if addNatSMac != "" {
			rule.SMac, err = maps.ParseMAC(addNatSMac)
			if err != nil {
				return fmt.Errorf("--smac: %w", err)
			}
		}

		if addNatDstIP != "" {
			ip := net.ParseIP(addNatDstIP)
			if ip == nil {
				return fmt.Errorf("invalid --dst-ip: %s", addNatDstIP)
			}
			rule.DstIP, err = maps.IPToUint32(ip)
			if err != nil {
				return err
			}
		}
		if addNatSrcIP != "" {
			ip := net.ParseIP(addNatSrcIP)
			if ip == nil {
				return fmt.Errorf("invalid --src-ip: %s", addNatSrcIP)
			}
			rule.SrcIP, err = maps.IPToUint32(ip)
			if err != nil {
				return err
			}
		}

		if err := maps.ValidateRule(rule); err != nil {
			return err
		}

		nm, err := maps.OpenNatMap()
		if err != nil {
			return err
		}
		defer nm.Close()

		if err := nm.Put(natIP, rule); err != nil {
			return err
		}

		fmt.Printf("OK  nat_map[%s] -> ue=%s teid=0x%08X ifindex=%d\n",
			natIP, ueIP, addNatTeidOut, rule.OutIfindex)
		return nil
	},
}

func init() {
	addNatCmd.Flags().StringVar(&addNatNatIP, "nat-ip", "", "NAT IP address (key; packets arriving on eth0 with this dst are redirected)")
	addNatCmd.Flags().StringVar(&addNatUeIP, "ue-ip", "", "UE IPv4 address to restore as inner dst")
	addNatCmd.Flags().StringVar(&addNatOutIface, "out-iface", "", "Egress interface toward gNB (e.g. veth-ran)")
	addNatCmd.Flags().StringVar(&addNatDMac, "dmac", "", "Destination MAC on egress (gNB-side veth MAC)")
	addNatCmd.Flags().StringVar(&addNatSMac, "smac", "", "Source MAC on egress (host-side veth MAC)")
	addNatCmd.Flags().Uint32Var(&addNatTeidOut, "teid-out", 0, "Downlink GTP-U TEID (gNB's expected TEID)")
	addNatCmd.Flags().StringVar(&addNatDstIP, "dst-ip", "", "Outer GTP-U destination IP (gNB IP)")
	addNatCmd.Flags().StringVar(&addNatSrcIP, "src-ip", "", "Outer GTP-U source IP (UPF/router IP on gNB-facing link)")

	_ = addNatCmd.MarkFlagRequired("nat-ip")
	_ = addNatCmd.MarkFlagRequired("ue-ip")
}
