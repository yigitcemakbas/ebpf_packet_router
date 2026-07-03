package cmd

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/spf13/cobra"

	"github.com/gtp-router/control/loader"
)

var (
	loadIface  string
	loadMode   string
	loadDLIface string
	loadDLMode  string
)

var loadCmd = &cobra.Command{
	Use:   "load",
	Short: "Attach the XDP program to a network interface",
	Long: `Loads the embedded GTP-U XDP program into the kernel and attaches it
to the given network interface. The BPF maps are pinned under
/sys/fs/bpf/gtp_router/ so that subsequent gtp-ctrl commands can
read and write rules without re-loading the program.`,
	Example: `  # Uplink only (veth-ran in native mode)
  gtp-ctrl load --iface veth-ran --mode native

  # Uplink + downlink (eth0 must use generic: e1000 driver has no native XDP)
  gtp-ctrl load --iface veth-ran --mode native --dl-iface eth0 --dl-mode generic`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if loadIface == "" {
			return fmt.Errorf("--iface is required")
		}

		parseMode := func(s string) (link.XDPAttachFlags, error) {
			switch s {
			case "native", "driver":
				return link.XDPDriverMode, nil
			case "generic", "skb":
				return link.XDPGenericMode, nil
			case "offload", "hw":
				return link.XDPOffloadMode, nil
			default:
				return 0, fmt.Errorf("unknown mode %q: must be native|generic|offload", s)
			}
		}

		xdpFlags, err := parseMode(loadMode)
		if err != nil {
			return err
		}

		var dlFlags link.XDPAttachFlags
		if loadDLIface != "" {
			dlFlags, err = parseMode(loadDLMode)
			if err != nil {
				return fmt.Errorf("--dl-mode: %w", err)
			}
		}

		l, err := loader.Load(loadIface, xdpFlags, loadDLIface, dlFlags)
		if err != nil {
			return err
		}
		l.Close()

		fmt.Printf("OK  XDP program loaded on %s (mode: %s)\n", loadIface, loadMode)
		if loadDLIface != "" {
			fmt.Printf("OK  XDP program loaded on %s (mode: %s)\n", loadDLIface, loadDLMode)
		}
		fmt.Printf("    Maps pinned under /sys/fs/bpf/gtp_router/\n")
		fmt.Printf("    Add rules with: gtp-ctrl add-teid / add-ueip / add-nat\n")
		return nil
	},
}

func init() {
	loadCmd.Flags().StringVar(&loadIface, "iface", "", "Uplink interface to attach to (required)")
	loadCmd.Flags().StringVar(&loadMode, "mode", "native", "Uplink XDP attach mode: native|generic|offload")
	loadCmd.Flags().StringVar(&loadDLIface, "dl-iface", "", "Downlink interface (e.g. eth0); omit to skip downlink attachment")
	loadCmd.Flags().StringVar(&loadDLMode, "dl-mode", "generic", "Downlink XDP attach mode: native|generic|offload")
}