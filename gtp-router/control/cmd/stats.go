package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/gtp-router/control/maps"
	"github.com/gtp-router/control/stats"
)

var statsWatch bool

var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Print global XDP verdict counters",
	Example: `  # Print once
  gtp-ctrl stats

  # Refresh every second until Ctrl-C
  gtp-ctrl stats --watch`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if statsWatch {
			return watchStats()
		}
		return printStats()
	},
}

func printStats() error {
	c, err := stats.Read(maps.PinStatsMap)
	if err != nil {
		return err
	}
	printCounters(c)
	return nil
}

func watchStats() error {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	// Clear screen on first print.
	fmt.Print("\033[H\033[2J")

	for {
		select {
		case <-sig:
			fmt.Println("\nstopped")
			return nil
		case <-ticker.C:
			c, err := stats.Read(maps.PinStatsMap)
			if err != nil {
				return err
			}
			// Move cursor to top-left and overwrite.
			fmt.Print("\033[H")
			fmt.Printf("GTP-U XDP Router - stats  (Ctrl-C to stop)\n\n")
			printCounters(c)
		}
	}
}

func printCounters(c *stats.Counters) {
	fmt.Printf("%-12s  %12s  %12s\n", "VERDICT", "PACKETS", "BYTES")
	fmt.Printf("%-12s  %12s  %12s\n", "-------", "-------", "-----")
	fmt.Printf("%-12s  %12d  %12s\n", "PASS",     c.Pass.Packets,     stats.FormatBytes(c.Pass.Bytes))
	fmt.Printf("%-12s  %12d  %12s\n", "DROP",     c.Drop.Packets,     stats.FormatBytes(c.Drop.Bytes))
	fmt.Printf("%-12s  %12d  %12s\n", "REDIRECT", c.Redirect.Packets, stats.FormatBytes(c.Redirect.Bytes))
}

func init() {
	statsCmd.Flags().BoolVar(&statsWatch, "watch", false, "Refresh counters every second")
}