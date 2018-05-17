package minq

import (
	"encoding/hex"
	"fmt"
	"testing"
)

var (
	testCid7    = ConnectionId([]byte{7, 7, 7, 7, 7, 7, 7})
	testCid4    = ConnectionId([]byte{4, 4, 4, 4})
	testVersion = VersionNumber(0xdeadbeef)
	testPn      = uint64(0xff000001)
)

// Packet header tests.
func packetHeaderEDE(t *testing.T, p *packetHeader, cidLen uintptr) {
	res, err := encode(p)
	assertNotError(t, err, "Could not encode")
	fmt.Println("Encoded = ", hex.EncodeToString(res))

	var p2 packetHeader
	p2.shortCidLength = cidLen
	_, err = decode(&p2, res)
	assertNotError(t, err, "Could not decode")
	fmt.Println("Decoded = ", p2)

	res2, err := encode(&p2)
	assertNotError(t, err, "Could not re-encode")
	fmt.Println("Encoded2 =", hex.EncodeToString(res2))
	assertByteEquals(t, res, res2)
}

func TestLongHeader(t *testing.T) {
	p := newPacket(packetTypeInitial, testCid7, testCid4, testVersion,
		testPn, make([]byte, 65), 16)
	packetHeaderEDE(t, &p.packetHeader, 0)
}

func TestShortHeader(t *testing.T) {
	p := newPacket(packetTypeProtectedShort, testCid7, testCid4, testVersion,
		testPn, make([]byte, 65), 16)

	// We have to provide assistance to the decoder for short headers.
	// Otherwise, it can't know long the destination connection ID is.
	packetHeaderEDE(t, &p.packetHeader, uintptr(len(p.DestinationConnectionID)))
}

/*
* TODO(ekr@rtfm.com): Rewrite this code and merge it into
* connection.go
// Mock for connection state
type ConnectionStateMock struct {
	aead aeadFNV
}

func (c *ConnectionStateMock) established() bool    { return false }
func (c *ConnectionStateMock) zeroRttAllowed() bool { return false }
func (c *ConnectionStateMock) expandPacketNumber(pn uint64) uint64 {
	return pn
}

func TestEDEPacket(t *testing.T) {
	var c ConnectionStateMock

	p := Packet{
		kTestpacketHeader,
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
*/
