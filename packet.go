package minq

import (
	"bytes"
	"fmt"
)

// Encode a QUIC packet.
/*
Long header

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+
|1|   Type (7)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                       Connection ID (64)                      +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Packet Number (32)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Version (32)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Payload (*)                        ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


Short Header

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 11
+-+-+-+-+-+-+-+-+
|0|C|K| Type (5)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                     [Connection ID (64)]                      +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Packet Number (8/16/32)                ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Protected Payload (*)                   ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

const (
	packetFlagLongHeader = 0x80
	packetFlagC          = 0x40
	packetFlagK          = 0x20
)

const (
	packetTypeVersionNegotiation   = 1
	packetTypeClientInitial        = 2
	packetTypeServerStatelessRetry = 3
	packetTypeServerCleartext      = 4
	packetTypeClientCleartext      = 5
	packetType0RTTProtected        = 6
	packetType1RTTProtectedPhase0  = 7
	packetType1RTTProtectedPhase1  = 8
	packetTypePublicReset          = 9
)

type ConnectionId uint64
type version uint32

// The PDU definition for the header.
// These types are capitalized so that |codec| can use the,
type packetHeader struct {
	Type         byte
	ConnectionID ConnectionId
	PacketNumber uint64 // Never more than 32 bits on the wire.
	Version      VersionNumber
}

func (p *packetHeader) String() string {
	ht := "SHORT"
	if isLongHeader(p) {
		ht = "LONG"
	}
	return fmt.Sprintf("%s PT=%x", ht, p.getHeaderType())
}

type packet struct {
	packetHeader
	payload []byte
}

// Functions to support encoding and decoding.
func isSet(b byte, flag byte) bool {
	return (b & flag) != 0
}

func isLongHeader(p *packetHeader) bool {
	return isSet(p.Type, packetFlagLongHeader)
}

func (p *packetHeader) isProtected() bool {
	if !isLongHeader(p) {
		return true
	}

	switch p.Type & 0x7f {
	case packetTypeClientInitial, packetTypeClientCleartext, packetTypeServerCleartext, packetTypeServerStatelessRetry, packetTypeVersionNegotiation:
		return false
	}
	return true
}

func (p *packetHeader) hasConnId() bool {
	if isLongHeader(p) {
		return true
	}
	if (p.Type & packetFlagC) != 0 {
		return true
	}
	return false
}

func (p *packetHeader) getHeaderType() byte {
	if isLongHeader(p) {
		return p.Type & 0x7f
	}
	// Short header.
	if (p.Type & packetFlagK) != 0 {
		return packetType1RTTProtectedPhase1
	}
	return packetType1RTTProtectedPhase0
}

func (p packetHeader) ConnectionID__length() uintptr {
	if isLongHeader(&p) || isSet(p.Type, packetFlagC) {
		return 8
	}
	return codecDefaultSize
}

func (p packetHeader) PacketNumber__length() uintptr {
	logf(logTypeTrace, "PacketNumber__length() Type=%v", p.Type)
	if isLongHeader(&p) {
		return 4
	}

	switch p.Type & 0xf {
	case 1:
		return 1
	case 2:
		return 2
	case 3:
		return 4
	default:
		return 4 // TODO(ekr@rtfm.com): This is actually currently an error.
	}
}
func (p packetHeader) Version__length() uintptr {
	if isLongHeader(&p) {
		return 4
	}
	return 0
}

func (p *packetHeader) setLongHeaderType(typ byte) {
	p.Type = packetFlagLongHeader | typ
}

type versionNegotiationPacket struct {
	Versions []byte
}

func newVersionNegotiationPacket(versions []VersionNumber) *versionNegotiationPacket {
	var buf bytes.Buffer

	for _, v := range versions {
		buf.Write(encodeArgs(v))
	}

	return &versionNegotiationPacket{buf.Bytes()}
}

/*
We don't use these.

func encodePacket(c ConnectionState, aead Aead, p *Packet) ([]byte, error) {
	hdr, err := encode(&p.packetHeader)
	if err != nil {
		return nil, err
	}

	b, err := aead.protect(p.packetHeader.PacketNumber, hdr, p.payload)
	if err != nil {
		return nil, err
	}

	return encodeArgs(hdr, b), nil
}

func decodePacket(c ConnectionState, aead Aead, b []byte) (*Packet, error) {
	// Parse the header
	var hdr packetHeader
	br, err := decode(&hdr, b)
	if err != nil {
		return nil, err
	}

	hdr.PacketNumber = c.expandPacketNumber(hdr.PacketNumber)
	pt, err := aead.unprotect(hdr.PacketNumber, b[0:br], b[br:])
	if err != nil {
		return nil, err
	}

	return &Packet{hdr, pt}, nil
}
*/

func dumpPacket(payload []byte) string {
	first := true
	ret := fmt.Sprintf("%d=[", len(payload))

	for len(payload) > 0 {
		if !first {
			ret += ", "
		}
		first = false
		n, f, err := decodeFrame(payload)
		if err != nil {
			ret += fmt.Sprintf("Undecoded: [%x]", payload)
			break
		}
		payload = payload[n:]
		// TODO(ekr@rtfm.com): Not sure why %v doesn't work
		ret += f.String()
	}
	ret += "]"

	return ret
}
