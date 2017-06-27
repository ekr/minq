package minq

import ()

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
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
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
	PacketFlagLongHeader = 0x80
	PacketFlagC          = 0x40
	PacketFlagK          = 0x20
)

const (
	PacketTypeVersionNegotiation   = 1
	PacketTypeClientInitial        = 2
	PacketTypeServerStatelessRetry = 3
	PacketTypeServerCleartext      = 4
	PacketTypeClientCleartext      = 5
	PacketType0RTTProtected        = 6
	PacketType1RTTProtectedPhase0  = 7
	PacketType1RTTProtectedPhase1  = 8
	PacketTypePublicReset          = 9
)

type connectionId uint64
type version uint32

// The PDU definition for the header.
// These types are capitalized so that |codec| can use the,
type PacketHeader struct {
	Type         byte
	ConnectionID connectionId
	PacketNumber uint64 // Never more than 32 bits on the wire.
	Version      VersionNumber
}

type Packet struct {
	PacketHeader
	payload []byte
}

// Functions to support encoding and decoding.
func isSet(b byte, flag byte) bool {
	return (b & flag) != 0
}

func isLongHeader(p *PacketHeader) bool {
	return isSet(p.Type, PacketFlagLongHeader)
}

func (p *PacketHeader) isProtected() bool {
	if !isLongHeader(p) {
		return true
	}

	switch p.Type & 0x7f {
	case PacketTypeClientInitial, PacketTypeClientCleartext, PacketTypeServerCleartext:
		return false
	}
	return true
}

func (p *PacketHeader) hasConnId() bool {
	if isLongHeader(p) {
		return true
	}
	if (p.Type & PacketFlagC) != 0 {
		return true
	}
	return false
}

func (p *PacketHeader) getHeaderType() byte {
	if isLongHeader(p) {
		return p.Type & 0x7f
	}
	panic("Can't parse short header yet")
	return 0
}

func (p PacketHeader) ConnectionID__length() uintptr {
	if isLongHeader(&p) || isSet(p.Type, PacketFlagC) {
		return 8
	}
	return CodecDefaultSize
}

func (p PacketHeader) PacketNumber__length() uintptr {
	logf(logTypeTrace, "PacketNumber__length()")
	if isLongHeader(&p) {
		return 4
	}

	switch p.Type {
	case 1, 2, 3:
		return 1 << p.Type
	default:
		return 4
	}
}
func (p PacketHeader) Version__length() uintptr {
	if isLongHeader(&p) {
		return 4
	}
	return CodecDefaultSize
}

func (p *PacketHeader) setLongHeaderType(typ byte) {
	p.Type = PacketFlagLongHeader | typ
}

/*
We don't use these.

func encodePacket(c ConnectionState, aead Aead, p *Packet) ([]byte, error) {
	hdr, err := encode(&p.PacketHeader)
	if err != nil {
		return nil, err
	}

	b, err := aead.protect(p.PacketHeader.PacketNumber, hdr, p.payload)
	if err != nil {
		return nil, err
	}

	return encodeArgs(hdr, b), nil
}

func decodePacket(c ConnectionState, aead Aead, b []byte) (*Packet, error) {
	// Parse the header
	var hdr PacketHeader
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
