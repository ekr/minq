/*
Package minq is a minimal implementation of QUIC, as documented at
https://quicwg.github.io/. Minq partly implements draft-04.

*/
package minq

import (
	"math"
//	"fmt"
)

const (
	kDefaultMss            = 14600//1460  // bytes
	kInitalWindow          = 10 * kDefaultMss
	kMinimumWindow         =  2 * kDefaultMss
	kMaximumWindow         = kInitalWindow
	kLossReductionFactor   = 0.5
)

type CongestionController interface {
	//TODO(piet@devae.re) refactor these to non exported
	/* |bytes_sent| bytes have been put on the wire */
	OnPacketSent(pn uint64, bytes_sent int)
	/* Packet |pn| has been acked */
	OnPacketAcked(pn uint64)
	OnPacketLoss(lost_packets uint64)
	OnRetransmissionTimeoutVerified()
	bytesAllowedToSend() int

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
	//fmt.Printf("cc.OnPacketSent: bytes_sent: %v, bytes_in_flight: %v\n",
	//	bytes_sent, cc.bytes_in_flight)
}

/* Function to be called whenever a packet is acked.
 * Note that it is safe to call this function multiple times
 * on the same packet, only the first time cc.packets_in_flight[pn]
 * will be nonzero */
func (cc *CongestionControllerIetf) OnPacketAcked(pn uint64){
	cc.bytes_in_flight -= cc.packets_in_flight[pn]
	if bytes_acked:= cc.packets_in_flight[pn]; bytes_acked != 0 {
	//fmt.Printf("cc.OnPacketAcked: bytes_acked: %v, bytes_in_flight: %v\n",
	//	bytes_acked, cc.bytes_in_flight)
	}
	delete(cc.packets_in_flight, pn)
}

func (cc *CongestionControllerIetf) OnPacketLoss(pn uint64){
}

func (cc *CongestionControllerIetf) OnRetransmissionTimeoutVerified(){
}

func (cc *CongestionControllerIetf) bytesAllowedToSend() int {
	//fmt.Printf("cc.bytesAllowedToSend: Allowing %v bytes to be send\n", cc.congestion_window - cc.bytes_in_flight)
	return cc.congestion_window - cc.bytes_in_flight
}

func newCongestionControllerIetf() *CongestionControllerIetf{
	return &CongestionControllerIetf{
		0,
		kInitalWindow,
		0,
		math.MaxUint64,
		make(map[uint64]int),
	}
}

