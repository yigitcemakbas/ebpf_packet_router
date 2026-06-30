package cmd

import (
	"fmt"
	"net"
	"sort"
	"text/tabwriter"
	"os"

	"github.com/spf13/cobra"

	"github.com/gtp-router/control/maps"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "Print all forwarding rules in teid_map and ueip_map",
	RunE: func(cmd *cobra.Command, args []string) error {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)

		// teid_map 
		tm, err := maps.OpenTeidMap()
		if err != nil {
			return err
		}
		defer tm.Close()

		teidEntries, err := tm.List()
		if err != nil {
			return err
		}

		fmt.Fprintf(w, "=== teid_map (%d entries) ===\n", len(teidEntries))
		if len(teidEntries) > 0 {
			fmt.Fprintln(w, "TEID\tACTION\tIFINDEX\tDST MAC\tSRC MAC\tPACKETS\tBYTES\tRATE-CAP\tRATE-DROPS")
			fmt.Fprintln(w, "----\t------\t-------\t-------\t-------\t-------\t-----\t--------\t----------")

			// Sort by TEID for stable output.
			teids := make([]uint32, 0, len(teidEntries))
			for k := range teidEntries {
				teids = append(teids, k)
			}
			sort.Slice(teids, func(i, j int) bool { return teids[i] < teids[j] })

			for _, teid := range teids {
				r := teidEntries[teid]
				fmt.Fprintf(w, "0x%08X\t%s\t%d\t%s\t%s\t%d\t%s\t%s\t%d\n",
					teid,
					maps.ActionString(r.Action),
					r.OutIfindex,
					maps.MACString(r.DMac),
					maps.MACString(r.SMac),
					r.PktCount,
					maps.FormatBytes(r.ByteCount),
					formatRateCap(r.RatePPS),
					r.RateDropCount,
				)
			}
		} else {
			fmt.Fprintln(w, "(empty)")
		}

		fmt.Fprintln(w)

		// ueip_map
		um, err := maps.OpenUeipMap()
		if err != nil {
			return err
		}
		defer um.Close()

		ueipEntries, err := um.List()
		if err != nil {
			return err
		}

		fmt.Fprintf(w, "=== ueip_map (%d entries) ===\n", len(ueipEntries))
		if len(ueipEntries) > 0 {
			fmt.Fprintln(w, "UE IP\tACTION\tIFINDEX\tDST MAC\tSRC MAC\tPACKETS\tBYTES\tRATE-CAP\tRATE-DROPS")
			fmt.Fprintln(w, "-----\t------\t-------\t-------\t-------\t-------\t-----\t--------\t----------")

			// Sort by IP for stable output.
			ips := make([]uint32, 0, len(ueipEntries))
			for k := range ueipEntries {
				ips = append(ips, k)
			}
			sort.Slice(ips, func(i, j int) bool { return ips[i] < ips[j] })

			for _, ipKey := range ips {
				r := ueipEntries[ipKey]
				ip := maps.Uint32ToIP(ipKey)
				fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%d\t%s\t%s\t%d\n",
					net.IP(ip).String(),
					maps.ActionString(r.Action),
					r.OutIfindex,
					maps.MACString(r.DMac),
					maps.MACString(r.SMac),
					r.PktCount,
					maps.FormatBytes(r.ByteCount),
					formatRateCap(r.RatePPS),
					r.RateDropCount,
				)
			}
		} else {
			fmt.Fprintln(w, "(empty)")
		}

		return w.Flush()
	},
}

func formatRateCap(ratePPS uint32) string {
	if ratePPS == 0 {
		return "-"
	}
	return fmt.Sprintf("%d/s", ratePPS)
}