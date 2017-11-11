package minq

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestAckFrameOneRange(t *testing.T) {
	ar := []ackRange{{0xdeadbeef, 2}}

	f, _, err := newAckFrame(ar, 21)
	assertNotError(t, err, "Couldn't make ack frame")

	err = f.encode()
	assertNotError(t, err, "Couldn't encode ack frame")

	fmt.Println("Encoded frame ", hex.EncodeToString(f.encoded))

	n, _, err := decodeFrame(f.encoded)
	assertNotError(t, err, "Couldn't decode ack frame")
	assertEquals(t, n, uintptr(len(f.encoded)))
}

func TestAckFrameTwoRanges(t *testing.T) {
	ar := []ackRange{{0xdeadbeef, 2}, {0xdeadbee0, 1}}

	f, _, err := newAckFrame(ar, 26)
	assertNotError(t, err, "Couldn't make ack frame")

	err = f.encode()
	assertNotError(t, err, "Couldn't encode ack frame")

	fmt.Println("Encoded frame ", hex.EncodeToString(f.encoded))

	n, _, err := decodeFrame(f.encoded)
	assertNotError(t, err, "Couldn't decode ack frame")
	assertEquals(t, n, uintptr(len(f.encoded)))
}

func TestQuantAckFrame(t *testing.T) {
	af := "a8676c3690000002000000000000000000000000000000000000000000000000000000000000000000c30000f4003a1703010035c1a1e4d0c42db1f0bff054dd80d5de9601745ad482162823bd322452e5e73c0ed01808f020ed5dc8d6a308b9595799ffccb4948834"
	afb, _ := hex.DecodeString(af)
	n, _, err := decodeFrame(afb)
	assertNotError(t, err, "Couldn't decode ack frame")
	fmt.Println(n)
}
