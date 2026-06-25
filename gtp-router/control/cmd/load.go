package cmd

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/spf13/cobra"

	"github.com/gtp-router/control/loader"
)

var (
	loadIface string
	loadMode  string
)

var loadCmd = &cobra.Command{
	Use:   "load",
	Short: "Attach the XDP program to a network interface",
	Long: `Loads the embedded GTP-U XDP program into the kernel and attaches it
to the given network interface. The BPF maps are pinned under
/sys/fs/bpf/gtp_router/ so that subsequent gtp-ctrl commands can
read and write rules without re-loading the program.`,
	Example: `  # Native mode (fastest, requires driver support)
  gtp-ctrl load --iface eth0

  # Generic mode (works on any driver, slightly slower)
  gtp-ctrl load --iface eth0 --mode generic`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if loadIface == "" {
			return fmt.Errorf("--iface is required")
		}

		var xdpFlags link.XDPAttachFlags
		switch loadMode {
		case "native", "driver":
			xdpFlags = link.XDPDriverMode
		case "generic", "skb":
			xdpFlags = link.XDPGenericMode
		case "offload", "hw":
			xdpFlags = link.XDPOffloadMode
		default:
			return fmt.Errorf("unknown mode %q: must be native|generic|offload", loadMode)
		}

		// Load the embedded .o, attach XDP, pin maps, then exit.
		// The XDP program keeps running in the kernel after exit.
		l, err := loader.Load(loadIface, xdpFlags)
		if err != nil {
			return err
		}
		l.Close()

		fmt.Printf("OK  XDP program loaded on %s (mode: %s)\n", loadIface, loadMode)
		fmt.Printf("    Maps pinned under /sys/fs/bpf/gtp_router/\n")
		fmt.Printf("    Add rules with: gtp-ctrl add-teid / add-ueip\n")
		return nil
	},
}

func init() {
	loadCmd.Flags().StringVar(&loadIface, "iface", "", "Network interface to attach to (required)")
	loadCmd.Flags().StringVar(&loadMode, "mode", "native", "XDP attach mode: native|generic|offload")
}