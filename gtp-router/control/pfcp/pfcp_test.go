package pfcp

import (
	"bytes"
	"net"
	"testing"
)

// TestHeaderRoundTrip builds a node message (no SEID) and a session message
// (with SEID) and parses each back, checking the header fields survive.
func TestHeaderRoundTrip(t *testing.T) {
	// node message: Association Setup Response, seq 7.
	node := buildMessage(msgAssociationSetupResponse, false, 0, 7,
		encodeNodeIDv4(net.IPv4(10, 201, 0, 1)),
		encodeCause(causeRequestAccepted),
	)
	m, err := parseMessage(node)
	if err != nil {
		t.Fatalf("parse node msg: %v", err)
	}
	if m.Type != msgAssociationSetupResponse {
		t.Errorf("type = %d, want %d", m.Type, msgAssociationSetupResponse)
	}
	if m.HasSEID {
		t.Errorf("node message unexpectedly has SEID")
	}
	if m.Seq != 7 {
		t.Errorf("seq = %d, want 7", m.Seq)
	}
	if findIE(m.IEs, ieCause) == nil {
		t.Errorf("cause IE missing")
	}

	// session message: Establishment Response with SEID 0x1122334455667788.
	const seid = 0x1122334455667788
	sess := buildMessage(msgSessionEstablishmentResponse, true, seid, 42,
		encodeFSEIDv4(1, net.IPv4(10, 201, 0, 1)),
	)
	sm, err := parseMessage(sess)
	if err != nil {
		t.Fatalf("parse session msg: %v", err)
	}
	if !sm.HasSEID || sm.SEID != seid {
		t.Errorf("SEID = %#x (has=%v), want %#x", sm.SEID, sm.HasSEID, uint64(seid))
	}
	if sm.Seq != 42 {
		t.Errorf("seq = %d, want 42", sm.Seq)
	}
}

// TestGroupedIE builds a Created PDR (grouped) carrying a PDR ID and an F-TEID,
// then walks it back out.
func TestGroupedIE(t *testing.T) {
	grp := encodeGrouped(ieCreatedPDR,
		encodePDRID(5),
		encodeFTEIDv4(0x00010000, net.IPv4(10, 201, 0, 1)),
	)
	ies, err := walkIEs(grp)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(ies) != 1 || ies[0].Type != ieCreatedPDR {
		t.Fatalf("top-level = %+v, want one Created PDR", ies)
	}
	fteid := findIE(ies[0].Children, ieFTEID)
	if fteid == nil {
		t.Fatalf("F-TEID child missing")
	}
	d, err := parseFTEID(fteid.Value)
	if err != nil {
		t.Fatalf("parse F-TEID: %v", err)
	}
	if d.Choose {
		t.Errorf("F-TEID unexpectedly CHOOSE")
	}
	if d.TEID != 0x00010000 {
		t.Errorf("TEID = %#x, want 0x00010000", d.TEID)
	}
	if !d.IPv4.Equal(net.IPv4(10, 201, 0, 1)) {
		t.Errorf("IPv4 = %v, want 10.201.0.1", d.IPv4)
	}
}

// TestParseFTEIDChoose checks the CHOOSE form (UPF allocates) decodes without
// demanding a TEID/address.
func TestParseFTEIDChoose(t *testing.T) {
	// flags: CH=1 (0x04), V4=1 (0x01); CHOOSE carries no TEID/addr.
	d, err := parseFTEID([]byte{0x05})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !d.Choose {
		t.Errorf("Choose = false, want true")
	}
}

// TestParseOuterHeaderCreation decodes a GTP-U/IPv4 downlink tunnel descriptor.
func TestParseOuterHeaderCreation(t *testing.T) {
	// desc = 0x0100 (GTP-U/UDP/IPv4), TEID = 0x00000abc, IPv4 = 10.201.0.2.
	v := []byte{0x01, 0x00, 0x00, 0x00, 0x0a, 0xbc, 10, 201, 0, 2}
	d, err := parseOuterHeaderCreation(v)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !d.GTPU {
		t.Fatalf("GTPU = false, want true")
	}
	if d.TEID != 0x0abc {
		t.Errorf("TEID = %#x, want 0xabc", d.TEID)
	}
	if !d.IPv4.Equal(net.IPv4(10, 201, 0, 2)) {
		t.Errorf("IPv4 = %v, want 10.201.0.2", d.IPv4)
	}
}

// TestParseUEIPAddress checks V4 extraction.
func TestParseUEIPAddress(t *testing.T) {
	// flags: V4=1 (0x02), then 10.45.0.2.
	got := parseUEIPAddress([]byte{0x02, 10, 45, 0, 2})
	if got == nil || !got.Equal(net.IPv4(10, 45, 0, 2)) {
		t.Errorf("UE IP = %v, want 10.45.0.2", got)
	}
}

// TestLengthField confirms the header Length field equals the byte count after
// octet 4, which a strict SMF parser will check.
func TestLengthField(t *testing.T) {
	msg := buildMessage(msgHeartbeatResponse, false, 0, 1,
		encodeRecoveryTimeStamp(0xdeadbeef))
	// Length is octets 3-4 (big-endian).
	length := int(msg[2])<<8 | int(msg[3])
	if length != len(msg)-4 {
		t.Errorf("length field = %d, want %d (len-4)", length, len(msg)-4)
	}
	// Sanity: the recovery timestamp IE round-trips.
	m, err := parseMessage(msg)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	rt := findIE(m.IEs, ieRecoveryTimeStamp)
	if rt == nil || !bytes.Equal(rt.Value, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Errorf("recovery ts IE = %+v, want 0xdeadbeef", rt)
	}
}
