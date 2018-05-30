package minq

import (
	"bytes"
	"fmt"
	"testing"
)

func testEncodeDecodeEncode(t *testing.T, f *frame) {
	err := f.encode()
	assertNotError(t, err, "Encode failed")
	fmt.Printf("Encoded: [%x]\n", f.encoded)

	consumed, f2, err := decodeFrame(f.encoded)
	assertNotError(t, err, "Failed to decode frame")
	assertEquals(t, len(f.encoded), int(consumed))
	f2.encoded = nil // So we re-encode

	err = f2.encode()
	assertNotError(t, err, "Encode failed")
	assertByteEquals(t, f.encoded, f2.encoded)

	fmt.Printf("%+v\n", f2)
}

func TestStreamFrame(t *testing.T) {
	s := newStreamFrame(1, 0,
		bytes.Repeat([]byte{0xa0}, 100), false)
	testEncodeDecodeEncode(t, s)
}

func TestAckFrameOneRange(t *testing.T) {
	ar := []ackRange{{0xdeadbeef, 2}}

	recvd := newRecvdPackets(logf)
	recvd.init(ar[0].lastPacket)
	recvd.packetSetReceived(ar[0].lastPacket, false, false)

	f, _, err := newAckFrame(recvd, ar, 33)
	assertNotError(t, err, "Couldn't make ack frame")

	testEncodeDecodeEncode(t, f)
}

func TestAckFrameTwoRanges(t *testing.T) {
	ar := []ackRange{{0xdeadbeef, 2}, {0xdeadbee0, 1}}

	recvd := newRecvdPackets(logf)
	recvd.init(ar[0].lastPacket)
	recvd.packetSetReceived(ar[0].lastPacket, false, false)

	f, _, err := newAckFrame(recvd, ar, 49)
	assertNotError(t, err, "Couldn't make ack frame")

	testEncodeDecodeEncode(t, f)
}

func TestFixedSizedData(t *testing.T) {
	f := newPathChallengeFrame([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	testEncodeDecodeEncode(t, f)
	f = newPathResponseFrame([]byte{10, 9, 8, 7, 6, 5, 4, 3})
	testEncodeDecodeEncode(t, f)
}
