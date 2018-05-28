package minq

import (
	"fmt"
	"github.com/bifurcation/mint"
	"runtime"
	"testing"
)

type testTrackingFixture struct {
	pns []uint64
	r   *recvdPackets
}

func newTestTrackingFixture() *testTrackingFixture {
	pc, _, _, ok := runtime.Caller(1)
	name := "unknown"
	if ok {
		name = runtime.FuncForPC(pc).Name()
	}
	log := func(tag string, format string, args ...interface{}) {
		fullFormat := fmt.Sprintf("%s: %s", name, format)
		logf(tag, fullFormat, args...)
	}

	pns := make([]uint64, 10)
	for i := uint64(0); i < 10; i++ {
		pns[i] = uint64(0xdead0000) + i
	}
	return &testTrackingFixture{
		pns,
		newRecvdPackets(log),
	}
}

func TestTrackingPacketsReceived(t *testing.T) {
	f := newTestTrackingFixture()
	assertEquals(t, true, f.r.packetNotReceived(f.pns[1]))
	f.r.init(f.pns[0])
	assertEquals(t, true, f.r.packetNotReceived(f.pns[0]))
	assertEquals(t, true, f.r.packetNotReceived(f.pns[1]))
	f.r.packetSetReceived(f.pns[0], false, true)
	assertEquals(t, false, f.r.packetNotReceived(f.pns[0]))
	assertEquals(t, true, f.r.packetNotReceived(f.pns[1]))
	f.r.packetSetReceived(f.pns[1], true, true)
	assertEquals(t, false, f.r.packetNotReceived(f.pns[1]))

	// Check that things less than min are received
	assertEquals(t, false, f.r.packetNotReceived(f.pns[0]-1))

	// Now make some ACKs
	ar := f.r.prepareAckRange(mint.EpochApplicationData, false)
	assertX(t, len(ar) == 1, "Should be one entry in ACK range")
	assertEquals(t, ar[0].lastPacket, f.pns[1])
	assertEquals(t, ar[0].count, uint64(2))

	f.r.packetSetReceived(f.pns[3], true, true)
	ar = f.r.prepareAckRange(mint.EpochApplicationData, false)
	assertX(t, len(ar) == 2, "Should be two entry in ACK range")
	assertEquals(t, ar[0].lastPacket, f.pns[3])
	assertEquals(t, ar[1].lastPacket, f.pns[1])
	assertEquals(t, ar[1].count, uint64(2))

	// Now ack all the acks, so that we should send nothing.
	f.r.packetSetAcked2(f.pns[0])
	f.r.packetSetAcked2(f.pns[1])
	f.r.packetSetAcked2(f.pns[3])
	ar = f.r.prepareAckRange(mint.EpochApplicationData, false)
	assertX(t, len(ar) == 0, "Should be no acks")
}
