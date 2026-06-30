package cmd

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/gtp-router/control/tui"
)

var dashboardInterval time.Duration

var dashboardCmd = &cobra.Command{
	Use:   "dashboard",
	Short: "Live terminal dashboard of rules and verdict counters",
	Long: `Launches a full-screen, auto-refreshing view of teid_map, ueip_map,
and the global XDP verdict counters (PASS/DROP/REDIRECT), including a live
packets-per-second figure for each rule and verdict.

Press q or Ctrl-C to exit.`,
	Example: `  gtp-ctrl dashboard
  gtp-ctrl dashboard --interval 500ms`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return tui.Run(dashboardInterval)
	},
}

func init() {
	dashboardCmd.Flags().DurationVar(&dashboardInterval, "interval", time.Second, "Refresh interval")
}
