// Package pfcp implements the router's PFCP (3GPP TS 29.244) control interface -
// the N4 reference point by which a 5G core's SMF drives a UPF. It is a
// first-class operating mode of the router: with it, a real SMF (e.g. Open5GS)
// establishes, modifies, and deletes GTP-U sessions on this router exactly as it
// would on any UPF, and the router installs the corresponding data-plane rules.
// This is the standards-defined way a UPF is provisioned; the CLI add-teid/
// add-nat path is the manual alternative to it, not the other way around.
//
// The codec is self-contained (no external dependency) and covers the message
// set a UPF must speak for basic session management: Heartbeat, Association
// Setup, and Session Establishment/Modification/Deletion, with Create PDR /
// Create FAR parsing mapped onto the same maps.FwdRule install path the CLI
// uses. Usage Reporting (URR), QoS Enforcement (QER), and PFD management are out
// of scope for this codec. See server.go for the session handling.
//
// This file implements the Information Element (IE) layer: TLV framing plus the
// specific IEs the messages above carry. PFCP IEs are big-endian
// type(2)/length(2)/value, and several are "grouped" (their value is itself a
// sequence of IEs), which walkIEs handles recursively.
package pfcp

import (
	"encoding/binary"
	"fmt"
	"net"
)

// IE type values (TS 29.244 Table 8.1.2-1). Only those used here are listed.
const (
	ieCreatePDR           uint16 = 1
	iePDI                 uint16 = 2
	ieCreateFAR           uint16 = 3
	ieForwardingParams    uint16 = 4
	ieCreatedPDR          uint16 = 8
	ieUpdateFAR           uint16 = 10
	ieUpdateForwardingPrm uint16 = 11
	ieCause               uint16 = 19
	ieSourceInterface     uint16 = 20
	ieFTEID               uint16 = 21
	ieNetworkInstance     uint16 = 22
	iePrecedence          uint16 = 29
	ieDestinationIface    uint16 = 42
	ieUPFunctionFeatures  uint16 = 43
	ieApplyAction         uint16 = 44
	iePDRID               uint16 = 56
	ieFSEID               uint16 = 57
	ieNodeID              uint16 = 60
	ieOuterHeaderCreation uint16 = 84
	ieUEIPAddress         uint16 = 93
	ieOuterHeaderRemoval  uint16 = 95
	ieRecoveryTimeStamp   uint16 = 96
	ieFARID               uint16 = 108
)

// Cause values (TS 29.244 Table 8.2.1-1). Only the two outcomes we emit.
const (
	causeRequestAccepted uint8 = 1
	causeRequestRejected uint8 = 64
)

// Source/Destination Interface values (TS 29.244 §8.2.2 / §8.2.24).
const (
	ifaceAccess uint8 = 0 // gNB side (uplink ingress / downlink egress)
	ifaceCore   uint8 = 1 // N6 side (uplink egress / downlink ingress)
)

// ie is a decoded Information Element. For grouped IEs, Children holds the
// decoded sub-IEs and Value holds the raw grouped payload.
type ie struct {
	Type     uint16
	Value    []byte
	Children []ie
}

// grouped reports whether an IE type carries a sequence of sub-IEs as its
// value, so the decoder knows to recurse.
func grouped(t uint16) bool {
	switch t {
	case ieCreatePDR, iePDI, ieCreateFAR, ieForwardingParams,
		ieCreatedPDR, ieUpdateFAR, ieUpdateForwardingPrm:
		return true
	}
	return false
}

// walkIEs decodes a flat sequence of TLV IEs, recursing into grouped ones.
func walkIEs(b []byte) ([]ie, error) {
	var out []ie
	for len(b) > 0 {
		if len(b) < 4 {
			return nil, fmt.Errorf("truncated IE header (%d bytes left)", len(b))
		}
		t := binary.BigEndian.Uint16(b[0:2])
		l := binary.BigEndian.Uint16(b[2:4])
		if len(b) < 4+int(l) {
			return nil, fmt.Errorf("IE type %d claims len %d, only %d bytes left", t, l, len(b)-4)
		}
		val := b[4 : 4+int(l)]
		e := ie{Type: t, Value: val}
		if grouped(t) {
			kids, err := walkIEs(val)
			if err != nil {
				return nil, fmt.Errorf("grouped IE %d: %w", t, err)
			}
			e.Children = kids
		}
		out = append(out, e)
		b = b[4+int(l):]
	}
	return out, nil
}

// find returns the first child IE of type t, or nil.
func findIE(ies []ie, t uint16) *ie {
	for i := range ies {
		if ies[i].Type == t {
			return &ies[i]
		}
	}
	return nil
}

// findAll returns every child IE of type t.
func findAllIE(ies []ie, t uint16) []ie {
	var out []ie
	for i := range ies {
		if ies[i].Type == t {
			out = append(out, ies[i])
		}
	}
	return out
}

// --- IE encoders ----------------------------------------------------------

// encodeIE frames one TLV IE.
func encodeIE(t uint16, val []byte) []byte {
	b := make([]byte, 4+len(val))
	binary.BigEndian.PutUint16(b[0:2], t)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(val)))
	copy(b[4:], val)
	return b
}

// encodeGrouped frames a grouped IE from already-encoded child IEs.
func encodeGrouped(t uint16, children ...[]byte) []byte {
	var val []byte
	for _, c := range children {
		val = append(val, c...)
	}
	return encodeIE(t, val)
}

// Node ID (§8.2.38): type 0 => IPv4 address form.
func encodeNodeIDv4(ip net.IP) []byte {
	v := append([]byte{0x00}, ip.To4()...)
	return encodeIE(ieNodeID, v)
}

// Recovery Time Stamp (§8.2.65): seconds since 1900 (NTP epoch), 4 bytes.
func encodeRecoveryTimeStamp(ntpSecs uint32) []byte {
	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v, ntpSecs)
	return encodeIE(ieRecoveryTimeStamp, v)
}

// Cause (§8.2.1): single byte.
func encodeCause(c uint8) []byte { return encodeIE(ieCause, []byte{c}) }

// UP Function Features (§8.2.25): 2+ bytes of feature flags; we advertise none
// (all zero), which is valid and means "basic forwarding only".
func encodeUPFunctionFeatures() []byte { return encodeIE(ieUPFunctionFeatures, []byte{0x00, 0x00}) }

// F-SEID (§8.2.37): flags(1) + SEID(8) + [IPv4] + [IPv6]. We always set V4.
func encodeFSEIDv4(seid uint64, ip net.IP) []byte {
	v := make([]byte, 0, 13)
	v = append(v, 0x02) // flags: V4=1 (bit 2), V6=0
	s := make([]byte, 8)
	binary.BigEndian.PutUint64(s, seid)
	v = append(v, s...)
	v = append(v, ip.To4()...)
	return encodeIE(ieFSEID, v)
}

// F-TEID (§8.2.3): flags(1) + [TEID(4)] + [IPv4(4)] + [IPv6(16)] + [ChooseID].
// We emit the allocated form: CH=0, V4=1, with a concrete TEID+IPv4.
func encodeFTEIDv4(teid uint32, ip net.IP) []byte {
	v := make([]byte, 0, 9)
	v = append(v, 0x01) // flags: V4=1 (bit0), V6=0, CH=0, CHID=0
	t := make([]byte, 4)
	binary.BigEndian.PutUint32(t, teid)
	v = append(v, t...)
	v = append(v, ip.To4()...)
	return encodeIE(ieFTEID, v)
}

// PDR ID (§8.2.36): 2 bytes.
func encodePDRID(id uint16) []byte {
	v := make([]byte, 2)
	binary.BigEndian.PutUint16(v, id)
	return encodeIE(iePDRID, v)
}

// --- IE decoders ----------------------------------------------------------

// decodedFTEID is the parsed content of an F-TEID IE.
type decodedFTEID struct {
	Choose bool // CH bit: UPF must allocate the TEID/IP (SMF left it to us)
	TEID   uint32
	IPv4   net.IP
}

func parseFTEID(v []byte) (decodedFTEID, error) {
	if len(v) < 1 {
		return decodedFTEID{}, fmt.Errorf("F-TEID too short")
	}
	var d decodedFTEID
	flags := v[0]
	v = v[1:]
	hasV4 := flags&0x01 != 0
	hasV6 := flags&0x02 != 0
	d.Choose = flags&0x04 != 0
	if d.Choose {
		// CHOOSE form carries no TEID/address; UPF allocates.
		return d, nil
	}
	if len(v) < 4 {
		return d, fmt.Errorf("F-TEID missing TEID")
	}
	d.TEID = binary.BigEndian.Uint32(v[0:4])
	v = v[4:]
	if hasV4 {
		if len(v) < 4 {
			return d, fmt.Errorf("F-TEID missing IPv4")
		}
		d.IPv4 = net.IP(append([]byte(nil), v[0:4]...))
		v = v[4:]
	}
	_ = hasV6
	return d, nil
}

// parseUEIPAddress (§8.2.62): flags(1) + [IPv4] + [IPv6]. Returns the IPv4 if
// present.
func parseUEIPAddress(v []byte) net.IP {
	if len(v) < 1 {
		return nil
	}
	flags := v[0]
	rest := v[1:]
	// bit1 = V4 present (S/D bits are higher); TS 29.244 §8.2.62.
	if flags&0x02 != 0 && len(rest) >= 4 {
		return net.IP(append([]byte(nil), rest[0:4]...))
	}
	return nil
}

// decodedOHC is the parsed Outer Header Creation IE (downlink encap target).
type decodedOHC struct {
	GTPU bool
	TEID uint32
	IPv4 net.IP
}

// parseOuterHeaderCreation (§8.2.56): description(2, flags) + [TEID(4)] +
// [IPv4(4)] + [IPv6] + [port]. The low bits of the description word select
// GTP-U/UDP/IPv4 etc. We care about the GTP-U/IPv4 case for downlink encap.
func parseOuterHeaderCreation(v []byte) (decodedOHC, error) {
	if len(v) < 2 {
		return decodedOHC{}, fmt.Errorf("OHC too short")
	}
	desc := binary.BigEndian.Uint16(v[0:2])
	rest := v[2:]
	var d decodedOHC
	// Description bit0 (0x0100 in the 2-octet field per spec ordering) = GTP-U/
	// UDP/IPv4. Accept any variant that includes a GTP-U TEID + IPv4, which is
	// how an SMF describes an N3 downlink tunnel.
	gtpuV4 := desc&0x0100 != 0 || desc&0x0001 != 0
	if gtpuV4 {
		d.GTPU = true
		if len(rest) < 4 {
			return d, fmt.Errorf("OHC missing TEID")
		}
		d.TEID = binary.BigEndian.Uint32(rest[0:4])
		rest = rest[4:]
		if len(rest) >= 4 {
			d.IPv4 = net.IP(append([]byte(nil), rest[0:4]...))
		}
	}
	return d, nil
}

// applyActionForwards reports whether an Apply Action IE (§8.2.26) has the
// FORW bit set (as opposed to DROP/BUFF/NOCP/DUPL).
func applyActionForwards(v []byte) bool {
	if len(v) < 1 {
		return false
	}
	// bit1 = DROP, bit2 = FORW (TS 29.244 §8.2.26).
	return v[0]&0x02 != 0
}

// firstByte returns v[0] or 0 for empty IEs (Source/Destination Interface).
func firstByte(v []byte) uint8 {
	if len(v) == 0 {
		return 0
	}
	return v[0] & 0x0f
}
