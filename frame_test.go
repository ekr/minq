package minq

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestAckFrameOneRange(t *testing.T) {
	ar := []ackRange{{0xdeadbeef, 2}}

	f, _, err := newAckFrame(ar, 5)
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

	f, _, err := newAckFrame(ar, 10)
	assertNotError(t, err, "Couldn't make ack frame")

	err = f.encode()
	assertNotError(t, err, "Couldn't encode ack frame")

	fmt.Println("Encoded frame ", hex.EncodeToString(f.encoded))

	n, _, err := decodeFrame(f.encoded)
	assertNotError(t, err, "Couldn't decode ack frame")
	assertEquals(t, n, uintptr(len(f.encoded)))
}
