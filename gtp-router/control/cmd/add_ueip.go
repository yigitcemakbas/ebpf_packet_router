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
  gtp-ctrl add-ueip --ip 10.1.0.99 --action drop`,
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
			Action: action,
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

		// Validate required fields for non-drop actions 
		if action != maps.ActionDrop {
			if rule.OutIfindex == 0 {
				return fmt.Errorf("--out-iface is required for action %s", addUeipAction)
			}
			if rule.DMac == [6]byte{} {
				return fmt.Errorf("--dmac is required for action %s", addUeipAction)
			}
			if rule.SMac == [6]byte{} {
				return fmt.Errorf("--smac is required for action %s", addUeipAction)
			}
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

	_ = addUeipCmd.MarkFlagRequired("ip")
}