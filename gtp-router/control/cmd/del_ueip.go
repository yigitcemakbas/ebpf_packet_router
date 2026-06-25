package cmd

import (
	"fmt"
	"net"

	"github.com/spf13/cobra"

	"github.com/gtp-router/control/maps"
)

var delUeipIP string

var delUeipCmd = &cobra.Command{
	Use:     "del-ueip",
	Short:   "Remove a forwarding rule from ueip_map",
	Example: `  gtp-ctrl del-ueip --ip 10.1.0.50`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ueip := net.ParseIP(delUeipIP)
		if ueip == nil {
			return fmt.Errorf("invalid --ip: %s", delUeipIP)
		}

		um, err := maps.OpenUeipMap()
		if err != nil {
			return err
		}
		defer um.Close()

		if err := um.Delete(ueip); err != nil {
			return err
		}

		fmt.Printf("OK  ueip_map[%s] removed\n", ueip)
		return nil
	},
}

func init() {
	delUeipCmd.Flags().StringVar(&delUeipIP, "ip", "", "UE IPv4 address (required)")
	_ = delUeipCmd.MarkFlagRequired("ip")
}