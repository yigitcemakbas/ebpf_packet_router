// Package maps mirrors the BPF map schema from include/gtp_router.h.
// FwdRule must match struct fwd_rule exactly (same field order, same sizes)
// so cilium/ebpf can marshal it directly into kernel map memory.
package maps

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
)

const (
	ActionDrop     uint32 = 0
	ActionDecapFwd uint32 = 1
	ActionEncapFwd uint32 = 2
	ActionRedirect uint32 = 3
)

func ActionString(a uint32) string {
	switch a {
	case ActionDrop:     return "DROP"
	case ActionDecapFwd: return "DECAP_FWD"
	case ActionEncapFwd: return "ENCAP_FWD"
	case ActionRedirect: return "REDIRECT"
	default:             return fmt.Sprintf("UNKNOWN(%d)", a)
	}
}

func ParseAction(s string) (uint32, error) {
	switch s {
	case "drop":              return ActionDrop, nil
	case "decap", "decap_fwd": return ActionDecapFwd, nil
	case "encap", "encap_fwd": return ActionEncapFwd, nil
	case "redirect":          return ActionRedirect, nil
	default:
		return 0, fmt.Errorf("unknown action %q: must be drop|decap|encap|redirect", s)
	}
}

// Mirrors struct fwd_rule in gtp_router.h (56 bytes)
type FwdRule struct {
	Action     uint32
	OutIfindex uint32
	DMac       [6]byte
	SMac       [6]byte
	TeidOut    uint32
	DstIP      uint32
	SrcIP      uint32
	DstPort    uint16
	Pad        [6]byte
	PktCount   uint64
	ByteCount  uint64
}

func IPToUint32(ip net.IP) (uint32, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("only IPv4 supported, got %s", ip)
	}
	return binary.BigEndian.Uint32(ip4), nil
}

func Uint32ToIP(n uint32) net.IP {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return net.IP(b)
}

func AddrToUint32(a netip.Addr) (uint32, error) {
	if !a.Is4() {
		return 0, fmt.Errorf("only IPv4 supported, got %s", a)
	}
	b := a.As4()
	return binary.BigEndian.Uint32(b[:]), nil
}

func ParseMAC(s string) ([6]byte, error) {
	hw, err := net.ParseMAC(s)
	if err != nil {
		return [6]byte{}, err
	}
	if len(hw) != 6 {
		return [6]byte{}, fmt.Errorf("expected 6-byte MAC, got %d bytes", len(hw))
	}
	var out [6]byte
	copy(out[:], hw)
	return out, nil
}

func MACString(mac [6]byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

func FormatBytes(b uint64) string {
	switch {
	case b >= 1<<30: return fmt.Sprintf("%.2f GB", float64(b)/float64(1<<30))
	case b >= 1<<20: return fmt.Sprintf("%.2f MB", float64(b)/float64(1<<20))
	case b >= 1<<10: return fmt.Sprintf("%.2f KB", float64(b)/float64(1<<10))
	default:         return fmt.Sprintf("%d B", b)
	}
}