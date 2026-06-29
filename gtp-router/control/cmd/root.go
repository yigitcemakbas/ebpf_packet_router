// Package cmd implements the gtp-ctrl command-line interface.
//
// Commands:
//   gtp-ctrl load      -> attach XDP program to a NIC
//   gtp-ctrl unload    -> detach XDP program from a NIC
//   gtp-ctrl add-teid  -> insert/update a TEID forwarding rule
//   gtp-ctrl del-teid  -> remove a TEID forwarding rule
//   gtp-ctrl add-ueip  -> insert/update a UE-IP forwarding rule
//   gtp-ctrl del-ueip  -> remove a UE-IP forwarding rule
//   gtp-ctrl list      -> print all rules in both maps
//   gtp-ctrl stats     -> print global XDP verdict counters
//   gtp-ctrl dashboard -> live terminal dashboard of rules and verdict counters
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "gtp-ctrl",
	Short: "Control plane for the GTP-U XDP router",
	Long: `gtp-ctrl manages the eBPF/XDP GTP-U router.

It loads the XDP program onto a network interface and lets you insert,
update, and remove forwarding rules in the kernel BPF maps at runtime
without interrupting traffic.`,
	// Require root for every sub-command
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if os.Getuid() != 0 {
			return fmt.Errorf("gtp-ctrl must be run as root (current uid=%d)", os.Getuid())
		}
		return nil
	},
}

// Execute is the entry point called from main.go
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(
		loadCmd,
		unloadCmd,
		addTeidCmd,
		delTeidCmd,
		addUeipCmd,
		delUeipCmd,
		listCmd,
		statsCmd,
		dashboardCmd,
	)
}