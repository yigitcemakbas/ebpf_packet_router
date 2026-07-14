package pfcp

import (
	"encoding/binary"
	"fmt"
)

// PFCP message type values (TS 29.244 Table 7.3-1). Only those handled here.
const (
	msgHeartbeatRequest             uint8 = 1
	msgHeartbeatResponse            uint8 = 2
	msgAssociationSetupRequest      uint8 = 5
	msgAssociationSetupResponse     uint8 = 6
	msgAssociationReleaseRequest    uint8 = 9
	msgAssociationReleaseResponse   uint8 = 10
	msgSessionEstablishmentRequest  uint8 = 50
	msgSessionEstablishmentResponse uint8 = 51
	msgSessionModificationRequest   uint8 = 52
	msgSessionModificationResponse  uint8 = 53
	msgSessionDeletionRequest       uint8 = 54
	msgSessionDeletionResponse      uint8 = 55
)

const pfcpVersion = 1

// header is a decoded PFCP message header (TS 29.244 §7.2.2). SEID is only
// present for session-related messages (the S flag).
type header struct {
	Type    uint8
	HasSEID bool
	SEID    uint64
	Seq     uint32 // 24-bit sequence number
	Length  uint16 // value of the Length field (payload after octet 4)
}

// message is a fully decoded PFCP message.
type message struct {
	header
	IEs []ie
}

// parseMessage decodes one PFCP message from a UDP datagram.
func parseMessage(b []byte) (*message, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("short PFCP header (%d bytes)", len(b))
	}
	flags := b[0]
	ver := flags >> 5
	if ver != pfcpVersion {
		return nil, fmt.Errorf("unsupported PFCP version %d", ver)
	}
	var h header
	h.HasSEID = flags&0x01 != 0
	h.Type = b[1]
	h.Length = binary.BigEndian.Uint16(b[2:4])

	off := 4
	if h.HasSEID {
		if len(b) < off+8+4 {
			return nil, fmt.Errorf("short SEID header")
		}
		h.SEID = binary.BigEndian.Uint64(b[off : off+8])
		off += 8
	}
	// 3-byte sequence number + 1 spare byte follow.
	if len(b) < off+4 {
		return nil, fmt.Errorf("short seq header")
	}
	h.Seq = uint32(b[off])<<16 | uint32(b[off+1])<<8 | uint32(b[off+2])
	off += 4

	ies, err := walkIEs(b[off:])
	if err != nil {
		return nil, fmt.Errorf("decode IEs: %w", err)
	}
	return &message{header: h, IEs: ies}, nil
}

// buildMessage frames a PFCP message. seid is written only when hasSEID.
// The Length field covers everything after octet 4 (i.e. optional SEID + the
// 4-byte seq/spare block + all IEs), per TS 29.244 §7.2.2.4.
func buildMessage(msgType uint8, hasSEID bool, seid uint64, seq uint32, ies ...[]byte) []byte {
	var body []byte
	for _, e := range ies {
		body = append(body, e...)
	}

	var hdr []byte
	flags := byte(pfcpVersion << 5)
	if hasSEID {
		flags |= 0x01
	}
	hdr = append(hdr, flags, msgType, 0, 0) // length filled in below

	var tail []byte
	if hasSEID {
		s := make([]byte, 8)
		binary.BigEndian.PutUint64(s, seid)
		tail = append(tail, s...)
	}
	// 3-byte sequence + 1 spare.
	tail = append(tail, byte(seq>>16), byte(seq>>8), byte(seq), 0x00)

	length := len(tail) + len(body)
	out := append(hdr, tail...)
	out = append(out, body...)
	binary.BigEndian.PutUint16(out[2:4], uint16(length))
	return out
}
