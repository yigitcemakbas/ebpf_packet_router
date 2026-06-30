package maps

import "golang.org/x/sys/unix"

// MonotonicNowNs returns nanoseconds since boot - the same clock domain
// bpf_ktime_get_ns() uses in the eBPF program (CLOCK_MONOTONIC). Comparing
// this against FwdRule.QuarantineUntilNs/WindowStartNs is correct; comparing
// time.Now() (wall-clock) against them is not, since the two clocks have
// different epochs.
func MonotonicNowNs() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return uint64(ts.Nano())
}
