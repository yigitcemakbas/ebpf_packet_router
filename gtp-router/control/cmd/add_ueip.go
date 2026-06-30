package cmd

import (
	"fmt"
	"net"

	"github.com/spf13/cobra"

	"github.com/gtp-router/control/maps"
)

var (
	addUeipIP       string
	addUeipAction   string
	addUeipOutIface string
	addUeipDMac     string
	addUeipSMac     string
	addUeipTeidOut  uint32
	addUeipDstIP    string
	addUeipSrcIP    string
	addUeipRatePPS  uint32
)

var addUeipCmd = &cobra.Command{
	Use:   "add-ueip",
	Short: "Insert or update a forwarding rule keyed by UE IP address",
	Long: `Insert or update a rule in ueip_map.

The UE IP is the inner destination IP address found inside the GTP-U envelope.
This map is used as a fallback when no TEID rule matches. It's useful for
routing traffic to a specific UE regardless of which tunnel it arrived on.`,
	Example: `  # Decapsulate and forward traffic destined for UE 10.1.0.50
  gtp-ctrl add-ueip \
    --ip 10.1.0.50 \
    --action decap \
    --out-iface eth1 \
    --dmac aa:bb:cc:dd:ee:ff \
    --smac 11:22:33:44:55:66

  # Drop all GTP-U traffic to UE 10.1.0.99
  gtp-ctrl add-ueip --ip 10.1.0.99 --action drop

  # Encapsulate downlink traffic for UE 10.1.0.2 into a GTP-U tunnel
  # (TEID 0xBEEF) toward gNB 10.0.0.1, sourced from 10.0.0.2
  gtp-ctrl add-ueip \
    --ip 10.1.0.2 \
    --action encap \
    --teid-out 0xBEEF \
    --src-ip 10.0.0.2 \
    --dst-ip 10.0.0.1 \
    --out-iface veth-core0 \
    --dmac aa:bb:cc:dd:ee:ff \
    --smac 11:22:33:44:55:66

  # Cap UE 10.1.0.50 to 50 packets/sec regardless of action
  gtp-ctrl add-ueip --ip 10.1.0.50 --action decap \
    --out-iface eth1 --dmac aa:bb:cc:dd:ee:ff --smac 11:22:33:44:55:66 \
    --rate-pps 50`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Parse UE IP 
		ueip := net.ParseIP(addUeipIP)
		if ueip == nil {
			return fmt.Errorf("invalid --ip: %s", addUeipIP)
		}
		if ueip.To4() == nil {
			return fmt.Errorf("only IPv4 UE addresses are supported")
		}

		// Parse action
		action, err := maps.ParseAction(addUeipAction)
		if err != nil {
			return err
		}

		// Build rule
		rule := &maps.FwdRule{
			Action:  action,
			RatePPS: addUeipRatePPS,
		}

		if addUeipOutIface != "" {
			iface, err := net.InterfaceByName(addUeipOutIface)
			if err != nil {
				return fmt.Errorf("egress interface %q: %w", addUeipOutIface, err)
			}
			rule.OutIfindex = uint32(iface.Index)
		}

		if addUeipDMac != "" {
			rule.DMac, err = maps.ParseMAC(addUeipDMac)
			if err != nil {
				return fmt.Errorf("--dmac: %w", err)
			}
		}
		if addUeipSMac != "" {
			rule.SMac, err = maps.ParseMAC(addUeipSMac)
			if err != nil {
				return fmt.Errorf("--smac: %w", err)
			}
		}

		// Encap (downlink) tunnel parameters: the TEID and outer IPs to put on
		// the GTP-U envelope built around packets destined to this UE.
		rule.TeidOut = addUeipTeidOut
		if addUeipDstIP != "" {
			ip := net.ParseIP(addUeipDstIP)
			if ip == nil {
				return fmt.Errorf("invalid --dst-ip: %s", addUeipDstIP)
			}
			if rule.DstIP, err = maps.IPToUint32(ip); err != nil {
				return err
			}
		}
		if addUeipSrcIP != "" {
			ip := net.ParseIP(addUeipSrcIP)
			if ip == nil {
				return fmt.Errorf("invalid --src-ip: %s", addUeipSrcIP)
			}
			if rule.SrcIP, err = maps.IPToUint32(ip); err != nil {
				return err
			}
		}

		// Validate required fields for the chosen action.
		if err := maps.ValidateRule(rule); err != nil {
			return err
		}

		// Write to map
		um, err := maps.OpenUeipMap()
		if err != nil {
			return err
		}
		defer um.Close()

		if err := um.Put(ueip, rule); err != nil {
			return err
		}

		fmt.Printf("OK  ueip_map[%s] = %s -> %s (ifindex=%d)\n",
			ueip, maps.ActionString(action), addUeipOutIface, rule.OutIfindex)
		return nil
	},
}

func init() {
	addUeipCmd.Flags().StringVar(&addUeipIP, "ip", "", "UE IPv4 address (required)")
	addUeipCmd.Flags().StringVar(&addUeipAction, "action", "decap", "Forwarding action: drop|decap|encap|redirect")
	addUeipCmd.Flags().StringVar(&addUeipOutIface, "out-iface", "", "Egress interface name (e.g. eth1)")
	addUeipCmd.Flags().StringVar(&addUeipDMac, "dmac", "", "Destination MAC to write on egress")
	addUeipCmd.Flags().StringVar(&addUeipSMac, "smac", "", "Source MAC to write on egress")
	addUeipCmd.Flags().Uint32Var(&addUeipTeidOut, "teid-out", 0, "Outgoing GTP-U TEID for the encap tunnel (encap action)")
	addUeipCmd.Flags().StringVar(&addUeipDstIP, "dst-ip", "", "Outer destination IP, e.g. the gNB (encap action)")
	addUeipCmd.Flags().StringVar(&addUeipSrcIP, "src-ip", "", "Outer source IP for the encap tunnel (encap action)")
	addUeipCmd.Flags().Uint32Var(&addUeipRatePPS, "rate-pps", 0, "Cap this UE to N packets/sec, dropping the rest (0 = unlimited)")

	_ = addUeipCmd.MarkFlagRequired("ip")
}