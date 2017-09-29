package minq

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestAckFrameOneRange(t *testing.T) {
	ar := []ackRange{{0xdeadbeef, 2}}

	f, err := newAckFrame(ar)
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

	f, err := newAckFrame(ar)
	assertNotError(t, err, "Couldn't make ack frame")

	err = f.encode()
	assertNotError(t, err, "Couldn't encode ack frame")

	fmt.Println("Encoded frame ", hex.EncodeToString(f.encoded))

	n, _, err := decodeFrame(f.encoded)
	assertNotError(t, err, "Couldn't decode ack frame")
	assertEquals(t, n, uintptr(len(f.encoded)))
}

func testStreamFrameInner(t *testing.T, related bool) {
	f := newStreamFrame(11, 22, []byte{1, 2, 3, 4}, false)
	sf := f.f.(*streamFrame)
	if related {
		sf.setRelated(1234)
	}
	assertNotNil(t, f, "Couldn't make stream frame")

	err := f.encode()
	assertNotError(t, err, "Couldn't encode stream frame")
	fmt.Println("Encoded frame ", hex.EncodeToString(f.encoded))

	n, f2, err := decodeFrame(f.encoded)
	assertNotError(t, err, "Couldn't decode ack frame")
	assertEquals(t, n, uintptr(len(f.encoded)))

	sf2, ok := f2.f.(*streamFrame)
	assertX(t, ok, "Decoded as stream frame")
	assertEquals(t, sf.StreamId, sf2.StreamId)
	assertEquals(t, sf.Offset, sf2.Offset)
	assertByteEquals(t, sf.Data, sf2.Data)
	rs, ok := sf2.isRelated()
	assertEquals(t, related, ok)
	if related {
		assertEquals(t, uint32(1234), rs)
	}
}

func TestStreamFrameNormal(t *testing.T) {
	testStreamFrameInner(t, false)
}

func TestStreamFrameRelated(t *testing.T) {
	testStreamFrameInner(t, true)
}
