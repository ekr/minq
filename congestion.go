/*
Package minq is a minimal implementation of QUIC, as documented at
https://quicwg.github.io/. Minq partly implements draft-04.

*/
package minq

import (
	"math"
)

const (
	kDefaultMss            = 1460  // bytes
	kInitalWindow          = 10 * kDefaultMss
	kMinimumWindow         =  2 * kDefaultMss
	kMaximumWindow         = kInitalWindow
	kLossReductionFactor   = 0.5
)

type CongestionController interface {
	/* |bytes_sent| bytes have been put on the wire */
	OnPacketSent(pn uint64, bytes_sent int)

	/* Packet |pn| has been acked */
	OnPacketAcked(pn uint64)

	OnPacketLoss(lost_packets uint64)

	OnRetransmissionTimeoutVerified()
}

type CongestionControllerIetf struct {
	bytes_in_flight      int
	congestion_window    int
	end_of_recovery      uint64
	sstresh              uint64
	packets_in_flight    map[uint64]int
}

func (cc *CongestionControllerIetf) OnPacketSent(pn uint64, bytes_sent int){
	//TODO(piet@devae.re) do not do this on an ACK only packet
	cc.packets_in_flight[pn] = bytes_sent
	cc.bytes_in_flight += bytes_sent
}

/* Function to be called whenever a packet is acked.
 * Note that it is safe to call this function multiple times
 * on the same packet, only the first time cc.packets_in_flight[pn]
 * will be nonzero */
func (cc *CongestionControllerIetf) OnPacketAcked(pn uint64){
	cc.bytes_in_flight -= cc.packets_in_flight[pn]
	delete(cc.packets_in_flight, pn)
}

func (cc *CongestionControllerIetf) OnPacketLoss(pn uint64){
}

func (cc *CongestionControllerIetf) OnRetransmissionTimeoutVerified(){
}

func newCongestionControllerIetf() *CongestionControllerIetf{
	return &CongestionControllerIetf{
		kInitalWindow,
		0,
		0,
		math.MaxUint64,
		make(map[uint64]int),
	}
}

