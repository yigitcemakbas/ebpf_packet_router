package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/gtp-router/control/loader"
)

var unloadIface string

var unloadCmd = &cobra.Command{
	Use:   "unload",
	Short: "Detach the XDP program from a network interface",
	Example: `  gtp-ctrl unload --iface eth0`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if unloadIface == "" {
			return fmt.Errorf("--iface is required")
		}
		if err := loader.Unload(unloadIface); err != nil {
			return err
		}
		fmt.Printf("OK  XDP program detached from %s\n", unloadIface)
		return nil
	},
}

func init() {
	unloadCmd.Flags().StringVar(&unloadIface, "iface", "", "Network interface to detach from (required)")
}