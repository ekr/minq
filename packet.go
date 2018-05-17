package minq

import (
	"bytes"
	"encoding/hex"
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
|                         Version (32)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|DCIL(4)|SCIL(4)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Destination Connection ID (0/32..144)         ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Source Connection ID (0/32..144)            ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Payload Length (i)                    ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Packet Number (8/16/32)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Payload (*)                        ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+
|0|K|1|1|0|R R R|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                Destination Connection ID (0..144)           ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Packet Number (8/16/32)                ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Protected Payload (*)                   ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

const (
	packetFlagLongHeader  = byte(0x80)
	packetFlagK           = byte(0x40)
	packetFlagShortHeader = byte(0x30)
)

// This packet type differs considerably from the spec.  It includes both
// long and short headers in the same value space.  Long headers are from
// 0-0x7f (inclusive); short headers are always represented as 0xff.
type packetType byte

const (
	packetTypeInitial        = packetType(0x7f)
	packetTypeRetry          = packetType(0x7e)
	packetTypeHandshake      = packetType(0x7d)
	packetType0RTTProtected  = packetType(0x7c)
	packetTypeProtectedShort = packetType(0xff) // Not a real type
)

func (pt packetType) isLongHeader() bool {
	return pt&packetType(packetFlagLongHeader) != 0
}

func (pt packetType) isProtected() bool {
	if !pt.isLongHeader() {
		return true
	}

	switch pt & 0x7f {
	case packetTypeInitial, packetTypeHandshake, packetTypeRetry:
		return false
	}
	return true
}

// kCidDefaultLength is the length of connection ID we generate.
// TODO: make this configurable.
const kCidDefaultLength = 5

// ConnectionId identifies the connection that a packet belongs to.
type ConnectionId []byte

// String stringifies a connection ID in the natural way.
func (c ConnectionId) String() string {
	return hex.EncodeToString(c)
}

// EncodeLength produces the length encoding used in the long packet header.
func (c ConnectionId) EncodeLength() byte {
	if len(c) == 0 {
		return 0
	}
	assert(len(c) >= 4 && len(c) <= 18)
	return byte(len(c) - 3)
}

// The PDU definition for the header.
// These types are capitalized so that |codec| can use them.
type packetHeader struct {
	// Type is the on-the-wire form of the packet type.
	// Consult getHeaderType if you want a value that corresponds to the
	// definition of packetType.
	Type                    packetType
	ConnectionIDLengths     byte
	DestinationConnectionID ConnectionId
	SourceConnectionID      ConnectionId
	Version                 VersionNumber
	PayloadLength           uint64 `tls:"varint"`
	PacketNumber            uint64 // Never more than 32 bits on the wire.

	// In order to decode a short header, the length of the connection
	// ID must be set in |shortCidLength| before decoding.
	shortCidLength uintptr
}

func (p packetHeader) String() string {
	ht := "SHORT"
	if p.Type.isLongHeader() {
		ht = "LONG"
	}
	prot := "CLEAR"
	if p.Type.isProtected() {
		prot = "ENC"
	}
	return fmt.Sprintf("%s %s PT=%x PN=%x", ht, prot, p.getHeaderType(), p.PacketNumber)
}

func (p *packetHeader) getHeaderType() packetType {
	if p.Type.isLongHeader() {
		return p.Type & 0x7f
	}
	return packetTypeProtectedShort
}

type packet struct {
	packetHeader
	payload []byte
}

// This reads from p.ConnectionIDLengths.
func (p packetHeader) ConnectionIDLengths__length() uintptr {
	if p.Type.isLongHeader() {
		return 1
	}
	return 0
}

func (p packetHeader) DestinationConnectionID__length() uintptr {
	if !p.Type.isLongHeader() {
		return p.shortCidLength
	}
	l := p.ConnectionIDLengths >> 4
	if l != 0 {
		l += 3
	}
	return uintptr(l)
}

func (p packetHeader) SourceConnectionID__length() uintptr {
	if !p.Type.isLongHeader() {
		return 0
	}
	l := p.ConnectionIDLengths & 0xf
	if l != 0 {
		l += 3
	}
	return uintptr(l)
}

func (p packetHeader) PayloadLength__length() uintptr {
	if p.Type.isLongHeader() {
		return codecDefaultSize
	}
	return 0
}

func (p packetHeader) PacketNumber__length() uintptr {
	logf(logTypeTrace, "PacketNumber__length() Type=%v", p.Type)
	if p.Type.isLongHeader() {
		return 4
	}

	switch p.Type & 0x3 {
	case 0:
		return 1
	case 1:
		return 2
	case 2:
		return 4
	default:
		return 4 // TODO(ekr@rtfm.com): This is actually currently an error.
	}
}
func (p packetHeader) Version__length() uintptr {
	if p.Type.isLongHeader() {
		return 4
	}
	return 0
}

func newPacket(pt packetType, destCid ConnectionId, srcCid ConnectionId, ver VersionNumber, pn uint64, payload []byte, aeadOverhead int) *packet {
	if pt == packetTypeProtectedShort {
		// Only support writing the 32-bit packet number.
		pt = packetType(0x2 | packetFlagShortHeader)
		srcCid = nil
	} else {
		pt = pt | packetType(packetFlagLongHeader)
	}
	lengths := (destCid.EncodeLength() << 4) | srcCid.EncodeLength()
	return &packet{
		packetHeader: packetHeader{
			Type:                    pt,
			ConnectionIDLengths:     lengths,
			DestinationConnectionID: destCid,
			SourceConnectionID:      srcCid,
			Version:                 ver,
			PayloadLength:           uint64(len(payload) + aeadOverhead),
			PacketNumber:            pn,
		},
		payload: payload,
	}
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
