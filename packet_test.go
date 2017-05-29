package chip

import (
	"encoding/hex"
	"fmt"
	"testing"
)

// Packet header tests.
func packetHeaderEDE(t *testing.T, p *PacketHeader) {
	var p2 PacketHeader
	res, err := encode(p)
	assertNotError(t, err, "Could not encode")

	fmt.Println("Result = ", hex.EncodeToString(res))

	_, err = decode(&p2, res)
	assertNotError(t, err, "Could not decode")

	res2, err := encode(&p2)
	assertNotError(t, err, "Could not re-encode")
	fmt.Println("Result2 = ", hex.EncodeToString(res2))
	assertByteEquals(t, res, res2)
}

func TestLongHeader(t *testing.T) {
	p1 := PacketHeader{
		0,
		0x0123456789abcdef,
		0xdeadbeef,
		0xff000001,
	}

	p1.setLongHeaderType(PacketTypeClientInitial)

	packetHeaderEDE(t, &p1)
}

// Whole packet tests.

// Mock for connection state
type ConnectionStateMock struct {
	aead AeadFNV
}

func (c *ConnectionStateMock) expandPacketNumber(pn uint64) uint64 {
	return pn
}

// Mock for AEAD
