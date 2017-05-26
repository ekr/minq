package chip

import (
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
	PacketFlagC = 0x40
	PacketFlagK = 0x20
)

const (
	PacketTypeVersionNegotiation = 1
	PacketTypeClientInitial = 2
	PacketTypeServerStatelessRetry = 3
	PacketTypeServerCleartext = 4
	PacketTypeClientCleartext = 5
	PacketType0RTTProtected = 6
	PacketType1RTTProtectedPhase0 = 7
	PacketType1RTTProtectedPhase1 = 8 
	PacketTypePublicReset = 9
)

type connectionId uint64
type version uint32

type Packet struct {
	Type byte
	ConnectionID uint64
	PacketNumber uint32
	Version version
	Payload []byte
}


// Functions to support encoding and decoding.
func isSet(b byte, flag byte) bool {
	return (b & flag) != 0
}

func isLongHeader(p *Packet) bool {
	return isSet(p.Type, PacketFlagLongHeader)
}

func PacketConnectionID__length(p *Packet) uintptr {
	if isLongHeader(p) || isSet(p.Type, PacketFlagC) {
		return 8
	}
	return CodecDefaultSize
}

func PacketPacketNumber__length(p *Packet) uintptr {
	if isLongHeader(p) {
		return 0
	}

	switch (p.Type) {
	case 1, 2, 3:
		return 1 << p.Type
	default:
		return CodecDefaultSize
	}
}			
func PacketVersion__length(p *Packet) uintptr {
	if isLongHeader(p) {
		return 4
	}
	return CodecDefaultSize
}

func (p *Packet) setLongHeaderType(typ byte) {
	p.Type = PacketFlagLongHeader | typ
}




