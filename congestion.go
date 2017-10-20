/*
Package minq is a minimal implementation of QUIC, as documented at
https://quicwg.github.io/. Minq partly implements draft-04.

*/
package minq

import (
	"math"
	"time"
//	"fmt"
)



/* congestion controll related constants */
const (
	kDefaultMss            = 14600//1460  // bytes
	kInitalWindow          = 10 * kDefaultMss
	kMinimumWindow         =  2 * kDefaultMss
	kMaximumWindow         = kInitalWindow
	kLossReductionFactor   = 0.5
)

/* loss dectection related constants */
const (
	kMaxTLPs                 = 2
	kReorderingThreshold     = 3
	kTimeReorderingFraction  = 0.125
	kMinTLPTimeout           = 10   // ms
	kMinRTOTimeout           = 200  // ms
	kDelayedAckTimeout       = 25   // ms
//	kDefaultInitialRtt       = 100  // ms // already in connection.go
)

type CongestionController interface {
	//TODO(piet@devae.re) get acked only info
	onPacketSent(pn uint64, isAckOnly bool, sentBytes int)
	onAckReceived(acks ackRanges, delay time.Duration)
	/* Packet |pn| has been acked */
	onPacketAcked(pn uint64)
	bytesAllowedToSend() int

}

type CongestionControllerIetf struct {
	/* Congestion control related */
	bytesInFlight          int
	congestionWindow       int
	endOfRecovery          uint64
	sstresh                uint64

	/* Loss detection related */
	lossDetectionAlarm     int //TODO(ekr@rtfm.com) set this to the right type
	handshakeCount         int
	tlpCount               int
	rtoCount               int
	largestSendBeforeRto   uint64
	timeOfLastSentPacket   time.Time
	largestSendPacket      uint64
	largestAckedPacket     uint64
//	largestRtt             time.Duration
	smoothedRtt            time.Duration
	rttVar                 float32
	reorderingThreshold    int
	timeReorderingFraction float32
	lossTime               time.Time
	sentPackets            map[uint64]packetEntry
}

type packetEntry struct{
	pn         uint64
	txTime     time.Time
	bytes      int
}


func (cc *CongestionControllerIetf) onPacketSent(pn uint64, isAckOnly bool, sentBytes int){
	cc.timeOfLastSentPacket = time.Now()
	cc.largestSendPacket = pn
	packetData := packetEntry{pn, time.Now(), 0}
	if !isAckOnly{
		cc.onPacketSentCC(sentBytes)
		packetData.bytes = sentBytes
		cc.setLossDetectionAlarm()
	}
	cc.sentPackets[pn] = packetData
}

/* acks is received to be a sorted list, where the largest packet numbers are at the beginning */
func(cc *CongestionControllerIetf) onAckReceived(acks ackRanges, delay time.Duration){

	/* keep track of largest packet acked overall */
	if acks[0].lastPacket > cc.largestAckedPacket {
		cc.largestAckedPacket = acks[0].lastPacket
	}

	/* If the largest acked is newly acked update rtt */
	_, present := cc.sentPackets[acks[0].lastPacket]
	if present {
		//TODO(ekr@rtfm.com) RTT stuff
		//largestRtt = time.Now - cc.sentPackets[acks[0].lastPacket].txTime
		//if (latestRtt > delay){
		//	latestRtt -= delay
		//	cc.updateRtt(latestRtt)
	}

	/* find and proccess newly acked packets */
	for _, ackBlock := range acks{
		for pn := ackBlock.lastPacket; pn > ackBlock.lastPacket - ackBlock.count; pn-- {
			_, present := cc.sentPackets[pn]
			if present {
				cc.onPacketAcked(pn)
			}
		}
	}

	cc.detectLostPackets()
	cc.setLossDetectionAlarm()
}

func(cc *CongestionControllerIetf) updateRtt(latestRtt time.Duration){
	//TODO(ekr@rtfm.com)
}

func(cc *CongestionControllerIetf) onPacketAcked(pn uint64){
	cc.onPacketAckedCC(pn)
	//TODO(ekr@rtfm.com) some RTO stuff here
	delete(cc.sentPackets, pn)
}

func(cc *CongestionControllerIetf) setLossDetectionAlarm(){
	//TODO(ekr@rtfm.com)
}

func(cc *CongestionControllerIetf) onLossDetectionAlarm(){
	//TODO(ekr@rtfm.com)
}

func(cc *CongestionControllerIetf) detectLostPackets(){
	var lostPackets []packetEntry
	//TODO(ekr@rtfm.com) implement loss detection different from reorderingThreshold
	for _, packet := range cc.sentPackets {
		if cc.largestAckedPacket - packet.pn > uint64(cc.reorderingThreshold) {
			lostPackets = append(lostPackets, packet)
		}
	}

	if len(lostPackets) > 0{
		cc.onPacketsLost(lostPackets)
	}
	for _, packet := range lostPackets {
		delete(cc.sentPackets, packet.pn)
	}
}

func (cc *CongestionControllerIetf) onPacketSentCC(bytes_sent int){
	cc.bytesInFlight += bytes_sent
}

func (cc *CongestionControllerIetf) onPacketAckedCC(pn uint64){
	cc.bytesInFlight -= cc.sentPackets[pn].bytes
	//TODO(piet@devae.re) change window size
}

func (cc *CongestionControllerIetf) onPacketsLost(packets []packetEntry){
	//TODO(piet@devae.re)
}

func (cc *CongestionControllerIetf) bytesAllowedToSend() int {
	//fmt.Printf("cc.bytesAllowedToSend: Allowing %v bytes to be send\n", cc.congestionWindow - cc.bytesInFlight)
	return cc.congestionWindow - cc.bytesInFlight
}

func newCongestionControllerIetf() *CongestionControllerIetf{
	return &CongestionControllerIetf{
		0,                             // bytesInFlight
		kInitalWindow,                 // congestionWindow
		0,                             // endOfRecovery
		math.MaxUint64,                // sstresh
		0,                             // lossDetectionAlarm
		0,                             // handshakeCount
		0,                             // tlpCount
		0,                             // rtoCount
		0,                             // largestSendBeforeRto
		time.Unix(0,0),                // timeOfLastSentPacket
		0,                             // largestSendPacket
		0,                             // largestAckedPacket
		0,                             // smoothedRtt
		0,                             // rttVar
		kReorderingThreshold,          // reorderingThreshold
		math.MaxFloat32,               // timeReorderingFraction
		time.Unix(0,0),                // lossTime
		make(map[uint64]packetEntry),  // sentPackets
	}
}

