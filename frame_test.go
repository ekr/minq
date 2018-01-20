package minq

import (
	"bytes"
	"fmt"
	"testing"
)

func testEncodeDecodeEncode(t *testing.T, f frame) {
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

	f, _, err := newAckFrame(recvd, ar, 21)
	assertNotError(t, err, "Couldn't make ack frame")

	testEncodeDecodeEncode(t, *f)
}

func TestAckFrameTwoRanges(t *testing.T) {
	ar := []ackRange{{0xdeadbeef, 2}, {0xdeadbee0, 1}}

	recvd := newRecvdPackets(logf)
	recvd.init(ar[0].lastPacket)
	recvd.packetSetReceived(ar[0].lastPacket, false, false)

	f, _, err := newAckFrame(recvd, ar, 26)
	assertNotError(t, err, "Couldn't make ack frame")

	testEncodeDecodeEncode(t, *f)
}

/*
func TestQuantAckFrame(t *testing.T) {
	af := "a8676c3690000002000000000000000000000000000000000000000000000000000000000000000000c30000f4003a1703010035c1a1e4d0c42db1f0bff054dd80d5de9601745ad482162823bd322452e5e73c0ed01808f020ed5dc8d6a308b9595799ffccb4948834"
	afb, _ := hex.DecodeString(af)
	n, _, err := decodeFrame(afb)
	assertNotError(t, err, "Couldn't decode ack frame")
	fmt.Println(n)
}
*/
