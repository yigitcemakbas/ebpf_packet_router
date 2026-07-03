package cmd

import (
	"fmt"
	"net"

	"github.com/spf13/cobra"

	"github.com/gtp-router/control/maps"
)

var delNatIP string

var delNatCmd = &cobra.Command{
	Use:   "del-nat",
	Short: "Remove a static NAT rule from nat_map",
	Example: `  gtp-ctrl del-nat --nat-ip 192.168.10.73`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ip := net.ParseIP(delNatIP)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("invalid --nat-ip: %s", delNatIP)
		}

		nm, err := maps.OpenNatMap()
		if err != nil {
			return err
		}
		defer nm.Close()

		if err := nm.Delete(ip); err != nil {
			return err
		}

		fmt.Printf("OK  nat_map[%s] deleted\n", ip)
		return nil
	},
}

func init() {
	delNatCmd.Flags().StringVar(&delNatIP, "nat-ip", "", "NAT IP to remove (required)")
	_ = delNatCmd.MarkFlagRequired("nat-ip")
}
