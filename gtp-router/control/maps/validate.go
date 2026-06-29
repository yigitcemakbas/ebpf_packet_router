package maps

import "fmt"

// ValidateRule checks that a FwdRule carries the fields its action needs
// before it's written to a map. Shared by the CLI (add-teid, add-ueip) and
// the dashboard's interactive rule editor, so the two can never enforce
// different rules.
func ValidateRule(rule *FwdRule) error {
	if rule.Action == ActionDrop {
		return nil
	}

	if rule.OutIfindex == 0 {
		return fmt.Errorf("--out-iface is required for action %s", ActionString(rule.Action))
	}
	if rule.DMac == [6]byte{} {
		return fmt.Errorf("--dmac is required for action %s", ActionString(rule.Action))
	}
	if rule.SMac == [6]byte{} {
		return fmt.Errorf("--smac is required for action %s", ActionString(rule.Action))
	}

	if rule.Action == ActionEncapFwd {
		if rule.TeidOut == 0 {
			return fmt.Errorf("--teid-out is required for action encap")
		}
		if rule.DstIP == 0 {
			return fmt.Errorf("--dst-ip (gNB / outer destination IP) is required for action encap")
		}
		if rule.SrcIP == 0 {
			return fmt.Errorf("--src-ip (outer source IP) is required for action encap")
		}
	}

	return nil
}
