package cmd

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/spf13/cobra"

	"github.com/gtp-router/control/maps"
)

var (
	addTeidTeid     string
	addTeidAction   string
	addTeidOutIface string
	addTeidDMac     string
	addTeidSMac     string
	addTeidDstIP    string
	addTeidSrcIP    string
	addTeidTeidOut  uint32
	addTeidDstPort  uint16
	addTeidRatePPS  uint32
)

var addTeidCmd = &cobra.Command{
	Use:   "add-teid",
	Short: "Insert or update a forwarding rule keyed by TEID",
	Long: `Insert or update a rule in teid_map.

The TEID (Tunnel Endpoint Identifier) is the 32-bit value in the GTP-U header
that identifies a bearer/session. When the XDP program sees a GTP-U packet
with this TEID, it applies the forwarding rule you specify here.`,
	Example: `  # Decapsulate GTP-U for TEID 0xDEAD and forward the inner IP to eth1
  gtp-ctrl add-teid \
    --teid 0xDEAD \
    --action decap \
    --out-iface eth1 \
    --dmac aa:bb:cc:dd:ee:ff \
    --smac 11:22:33:44:55:66

  # Drop all traffic arriving on TEID 0x1234
  gtp-ctrl add-teid --teid 0x1234 --action drop

  # Same as above, but cap this subscriber's tunnel to 100 packets/sec
  gtp-ctrl add-teid \
    --teid 0xDEAD \
    --action decap \
    --out-iface eth1 \
    --dmac aa:bb:cc:dd:ee:ff \
    --smac 11:22:33:44:55:66 \
    --rate-pps 100`,
	RunE: func(cmd *cobra.Command, args []string) error {
		teid, err := parseTEID(addTeidTeid)
		if err != nil {
			return err
		}

		action, err := maps.ParseAction(addTeidAction)
		if err != nil {
			return err
		}

		// Build rule
		rule := &maps.FwdRule{
			Action:  action,
			TeidOut: addTeidTeidOut,
			RatePPS: addTeidRatePPS,
		}

		// Resolve egress interface index.
		if addTeidOutIface != "" {
			iface, err := net.InterfaceByName(addTeidOutIface)
			if err != nil {
				return fmt.Errorf("egress interface %q: %w", addTeidOutIface, err)
			}
			rule.OutIfindex = uint32(iface.Index)
		}

		// Parse MACs (required for decap/redirect).
		if addTeidDMac != "" {
			rule.DMac, err = maps.ParseMAC(addTeidDMac)
			if err != nil {
				return fmt.Errorf("--dmac: %w", err)
			}
		}
		if addTeidSMac != "" {
			rule.SMac, err = maps.ParseMAC(addTeidSMac)
			if err != nil {
				return fmt.Errorf("--smac: %w", err)
			}
		}

		// Outer IPs for encap path
		if addTeidDstIP != "" {
			ip := net.ParseIP(addTeidDstIP)
			if ip == nil {
				return fmt.Errorf("invalid --dst-ip: %s", addTeidDstIP)
			}
			rule.DstIP, err = maps.IPToUint32(ip)
			if err != nil {
				return err
			}
		}
		if addTeidSrcIP != "" {
			ip := net.ParseIP(addTeidSrcIP)
			if ip == nil {
				return fmt.Errorf("invalid --src-ip: %s", addTeidSrcIP)
			}
			rule.SrcIP, err = maps.IPToUint32(ip)
			if err != nil {
				return err
			}
		}
		if addTeidDstPort != 0 {
			// Store in network byte order (big-endian) as a uint16
			b := make([]byte, 2)
			binary.BigEndian.PutUint16(b, addTeidDstPort)
			rule.DstPort = binary.LittleEndian.Uint16(b)
		}

		// Validate required fields for the chosen action.
		if err := maps.ValidateRule(rule); err != nil {
			return err
		}

		// Write to map 
		tm, err := maps.OpenTeidMap()
		if err != nil {
			return err
		}
		defer tm.Close()

		if err := tm.Put(teid, rule); err != nil {
			return err
		}

		fmt.Printf("OK  teid_map[0x%08X] = %s -> %s (ifindex=%d)\n",
			teid, maps.ActionString(action), addTeidOutIface, rule.OutIfindex)
		return nil
	},
}

func init() {
	addTeidCmd.Flags().StringVar(&addTeidTeid, "teid", "", "TEID value in hex or decimal (required)")
	addTeidCmd.Flags().StringVar(&addTeidAction, "action", "decap", "Forwarding action: drop|decap|encap|redirect")
	addTeidCmd.Flags().StringVar(&addTeidOutIface, "out-iface", "", "Egress interface name (e.g. eth1)")
	addTeidCmd.Flags().StringVar(&addTeidDMac, "dmac", "", "Destination MAC to write on egress (e.g. aa:bb:cc:dd:ee:ff)")
	addTeidCmd.Flags().StringVar(&addTeidSMac, "smac", "", "Source MAC to write on egress")
	addTeidCmd.Flags().StringVar(&addTeidDstIP, "dst-ip", "", "Outer destination IP (encap path)")
	addTeidCmd.Flags().StringVar(&addTeidSrcIP, "src-ip", "", "Outer source IP (encap path)")
	addTeidCmd.Flags().Uint32Var(&addTeidTeidOut, "teid-out", 0, "Outgoing TEID (encap path)")
	addTeidCmd.Flags().Uint16Var(&addTeidDstPort, "dst-port", 2152, "Outer UDP destination port (encap path)")
	addTeidCmd.Flags().Uint32Var(&addTeidRatePPS, "rate-pps", 0, "Cap this rule to N packets/sec, dropping the rest (0 = unlimited)")

	_ = addTeidCmd.MarkFlagRequired("teid")
}