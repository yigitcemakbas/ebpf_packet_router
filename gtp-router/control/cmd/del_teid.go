package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/gtp-router/control/maps"
)

var delTeidTeid string

var delTeidCmd = &cobra.Command{
	Use:   "del-teid",
	Short: "Remove a forwarding rule from teid_map",
	Example: `  gtp-ctrl del-teid --teid 0xDEAD`,
	RunE: func(cmd *cobra.Command, args []string) error {
		teid, err := parseTEID(delTeidTeid)
		if err != nil {
			return err
		}

		tm, err := maps.OpenTeidMap()
		if err != nil {
			return err
		}
		defer tm.Close()

		if err := tm.Delete(teid); err != nil {
			return err
		}

		fmt.Printf("OK  teid_map[0x%08X] removed\n", teid)
		return nil
	},
}

func init() {
	delTeidCmd.Flags().StringVar(&delTeidTeid, "teid", "", "TEID value in hex or decimal (required)")
	_ = delTeidCmd.MarkFlagRequired("teid")
}