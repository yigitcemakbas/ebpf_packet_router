// Package stats reads the per-CPU stats_map and aggregates counts across CPUs.
// Map slots: 0=XDP_PASS, 1=XDP_DROP, 3=XDP_REDIRECT
package stats

import (
	"fmt"

	"github.com/cilium/ebpf"
)

func FormatBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.2f MB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.2f KB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

type Counters struct {
	Pass     VerdictStat
	Drop     VerdictStat
	Redirect VerdictStat
}

type VerdictStat struct {
	Packets uint64
	Bytes   uint64
}

type perCPUStat struct {
	Packets uint64
	Bytes   uint64
}

func Read(pinPath string) (*Counters, error) {
	m, err := ebpf.LoadPinnedMap(pinPath, nil)
	if err != nil {
		return nil, fmt.Errorf("open stats_map: %w", err)
	}
	defer m.Close()
	return ReadFromMap(m)
}

func ReadFromMap(m *ebpf.Map) (*Counters, error) {
	totals := make([]VerdictStat, 4)

	for _, key := range []uint32{0, 1, 3} {
		var perCPU []perCPUStat
		if err := m.Lookup(key, &perCPU); err != nil {
			return nil, fmt.Errorf("stats_map lookup key=%d: %w", key, err)
		}
		for _, cpu := range perCPU {
			totals[key].Packets += cpu.Packets
			totals[key].Bytes += cpu.Bytes
		}
	}

	return &Counters{
		Pass:     totals[0],
		Drop:     totals[1],
		Redirect: totals[3],
	}, nil
}