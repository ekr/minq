package minq

import (
	"encoding/hex"
	"fmt"
	"testing"
)

var kTestPacketHeader = PacketHeader{
	0,
	0x0123456789abcdef,
	0xdeadbeef,
	0xff000001,
}

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
	p := kTestPacketHeader

	p.setLongHeaderType(PacketTypeClientInitial)

	packetHeaderEDE(t, &p)
}

// Whole packet tests.

// Mock for connection state
type ConnectionStateMock struct {
	aead AeadFNV
}

func (c *ConnectionStateMock) established() bool    { return false }
func (c *ConnectionStateMock) zeroRttAllowed() bool { return false }
func (c *ConnectionStateMock) expandPacketNumber(pn uint64) uint64 {
	return pn
}

func TestEDEPacket(t *testing.T) {
	var c ConnectionStateMock

	p := Packet{
		kTestPacketHeader,
		[]byte{'a', 'b', 'c', 'd', 'e', 'f', 'g'},
	}

	encoded, err := encodePacket(&c, &c.aead, &p)
	assertNotError(t, err, "Could not encode packet")

	p2, err := decodePacket(&c, &c.aead, encoded)
	assertNotError(t, err, "Could not decode packet")

	encoded2, err := encodePacket(&c, &c.aead, p2)
	assertNotError(t, err, "Could not re-encode packet")

	assertByteEquals(t, encoded, encoded2)
}
