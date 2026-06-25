package cmd

import (
	"fmt"
	"strconv"
	"strings"
)

// parseTEID parses a TEID string in hex ("0xDEAD") or decimal ("57005") form.
func parseTEID(s string) (uint32, error) {
	if s == "" {
		return 0, fmt.Errorf("TEID must not be empty")
	}
	s = strings.TrimSpace(s)

	var val uint64
	var err error
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		val, err = strconv.ParseUint(s[2:], 16, 32)
	} else {
		val, err = strconv.ParseUint(s, 10, 32)
	}
	if err != nil {
		return 0, fmt.Errorf("invalid TEID %q: must be hex (0xDEAD) or decimal", s)
	}
	return uint32(val), nil
}