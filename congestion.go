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

// congestion control related constants
const (
	kDefaultMss          = 1460 // bytes
	kInitalWindow        = 10 * kDefaultMss
	kMinimumWindow       = 2 * kDefaultMss
	kMaximumWindow       = kInitalWindow
	kLossReductionFactor = 0.5
)

// loss dectection related constants
const (
	kMaxTLPs                = 2
	kReorderingThreshold    = 3
	kTimeReorderingFraction = 0.125
	kMinTLPTimeout          = 10 * time.Millisecond
	kMinRTOTimeout          = 200 * time.Millisecond
	kDelayedAckTimeout      = 25 * time.Millisecond
	kDefaultInitialRtt      = 100 * time.Millisecond
)

type CongestionController interface {
	onPacketSent(pn uint64, isAckOnly bool, sentBytes int)
	onAckReceived(acks ackRanges, delay time.Duration)
	bytesAllowedToSend() int
	setLostPacketHandler(handler func(pn uint64))
	rto() time.Duration
}

/*
 * DUMMY congestion controller
 */

type CongestionControllerDummy struct {
}

func (cc *CongestionControllerDummy) onPacketSent(pn uint64, isAckOnly bool, sentBytes int) {
}

func (cc *CongestionControllerDummy) onAckReceived(acks ackRanges, delay time.Duration) {
}

func (cc *CongestionControllerDummy) bytesAllowedToSend() int {
	/* return the the maximum int value */
	return int(^uint(0) >> 1)
}

func (cc *CongestionControllerDummy) setLostPacketHandler(handler func(pn uint64)) {
}

func (cc *CongestionControllerDummy) rto() time.Duration {
	return kMinRTOTimeout
}

/*
 * draft-ietf-quic-recovery congestion controller
 */

type CongestionControllerIetf struct {
	// Congestion control related
	bytesInFlight    int
	congestionWindow int
	endOfRecovery    uint64
	sstresh          int

	// Loss detection related
	lossDetectionAlarm   int //TODO(ekr@rtfm.com) set this to the right type
	handshakeCount       int
	tlpCount             int
	rtoCount             int
	largestSendBeforeRto uint64
	timeOfLastSentPacket time.Time
	largestSendPacket    uint64
	largestAckedPacket   uint64
	maxAckDelay          time.Duration
	minRtt               time.Duration
	//	largestRtt             time.Duration
	smoothedRtt            time.Duration
	rttVar                 time.Duration
	smoothedRttTcp         time.Duration
	rttVarTcp              time.Duration
	reorderingThreshold    int
	timeReorderingFraction float32
	lossTime               time.Time
	sentPackets            map[uint64]packetEntry

	// others
	lostPacketHandler func(pn uint64)
	conn              *Connection
}

type packetEntry struct {
	pn      uint64
	txTime  time.Time
	bytes   int
	ackOnly bool
}

func (cc *CongestionControllerIetf) onPacketSent(pn uint64, isAckOnly bool, sentBytes int) {
	cc.timeOfLastSentPacket = time.Now()
	cc.largestSendPacket = pn
	packetData := packetEntry{pn, time.Now(), 0, isAckOnly}
	cc.conn.log(logTypeCongestion, "Packet send pn: %d len:%d ackonly: %v\n", pn, sentBytes, isAckOnly)
	if !isAckOnly {
		cc.onPacketSentCC(sentBytes)
		packetData.bytes = sentBytes
		cc.setLossDetectionAlarm()
	}
	cc.sentPackets[pn] = packetData
}

// acks is received to be a sorted list, where the largest packet numbers are at the beginning
func (cc *CongestionControllerIetf) onAckReceived(acks ackRanges, ackDelay time.Duration) {

	// keep track of largest packet acked overall
	if acks[0].lastPacket > cc.largestAckedPacket {
		cc.largestAckedPacket = acks[0].lastPacket
	}

	// If the largest acked is newly acked update rtt
	lastPacket, present := cc.sentPackets[acks[0].lastPacket]
	if present {
		latestRtt := time.Since(cc.sentPackets[acks[0].lastPacket].txTime)
		cc.conn.log(logTypeCongestion, "latestRtt: %v, ackDelay: %v", latestRtt, ackDelay)
		cc.updateRttTcp(latestRtt)

		// Update the minRtt, but ignore ackDelay.
		if latestRtt < cc.minRtt {
			cc.minRtt = latestRtt
		}

		// Now reduce by ackDelay if it doesn't reduce the RTT below the minimum.
		if latestRtt-cc.minRtt > ackDelay {
			latestRtt -= ackDelay
			// And update the maximum observed ACK delay.
			if !lastPacket.ackOnly && ackDelay > cc.maxAckDelay {
				cc.maxAckDelay = ackDelay
			}
		}

		cc.updateRtt(latestRtt)
	}

	// find and proccess newly acked packets
	for _, ackBlock := range acks {
		for pn := ackBlock.lastPacket; pn > (ackBlock.lastPacket - ackBlock.count); pn-- {
			cc.conn.log(logTypeCongestion, "Ack for pn %d received", pn)
			_, present := cc.sentPackets[pn]
			if present {
				cc.conn.log(logTypeCongestion, "First ack for pn %d received", pn)
				cc.onPacketAcked(pn)
			}
		}
	}

	cc.detectLostPackets()
	cc.setLossDetectionAlarm()
}

func (cc *CongestionControllerIetf) setLostPacketHandler(handler func(pn uint64)) {
	cc.lostPacketHandler = handler
}

func (cc *CongestionControllerIetf) updateRtt(latestRtt time.Duration) {
	if cc.smoothedRtt == 0 {
		cc.smoothedRtt = latestRtt
		cc.rttVar = time.Duration(int64(latestRtt) / 2)
	} else {
		rttDelta := cc.smoothedRtt - latestRtt
		if rttDelta < 0 {
			rttDelta = -rttDelta
		}
		cc.rttVar = time.Duration(int64(cc.rttVar)*3/4 + int64(rttDelta)*1/4)
		cc.smoothedRtt = time.Duration(int64(cc.smoothedRtt)*7/8 + int64(latestRtt)*1/8)
	}
	cc.conn.log(logTypeCongestion, "New RTT estimate: %v, variance: %v", cc.smoothedRtt, cc.rttVar)
}

func (cc *CongestionControllerIetf) updateRttTcp(latestRtt time.Duration) {
	if cc.smoothedRttTcp == 0 {
		cc.smoothedRttTcp = latestRtt
		cc.rttVarTcp = time.Duration(int64(latestRtt) / 2)
	} else {
		rttDelta := cc.smoothedRttTcp - latestRtt
		if rttDelta < 0 {
			rttDelta = -rttDelta
		}
		cc.rttVarTcp = time.Duration(int64(cc.rttVarTcp)*3/4 + int64(rttDelta)*3/4)
		cc.smoothedRttTcp = time.Duration(int64(cc.smoothedRttTcp)*7/8 + int64(latestRtt)*1/8)
	}
	cc.conn.log(logTypeCongestion, "New RTT(TCP) estimate: %v, variance: %v", cc.smoothedRttTcp, cc.rttVarTcp)
}

func (cc *CongestionControllerIetf) rto() time.Duration {
	// max(SRTT + 4*RTTVAR + MaxAckDelay, minRTO)
	rto := cc.smoothedRtt + 4*cc.rttVar + cc.maxAckDelay
	if rto < kMinRTOTimeout {
		return kMinRTOTimeout
	}
	return rto
}

func (cc *CongestionControllerIetf) onPacketAcked(pn uint64) {
	cc.onPacketAckedCC(pn)
	//TODO(ekr@rtfm.com) some RTO stuff here
	delete(cc.sentPackets, pn)
}

func (cc *CongestionControllerIetf) setLossDetectionAlarm() {
	//TODO(ekr@rtfm.com)
}

func (cc *CongestionControllerIetf) onLossDetectionAlarm() {
	//TODO(ekr@rtfm.com)
}

func (cc *CongestionControllerIetf) detectLostPackets() {
	var lostPackets []packetEntry
	//TODO(ekr@rtfm.com) implement loss detection different from reorderingThreshold
	for _, packet := range cc.sentPackets {
		if (cc.largestAckedPacket > packet.pn) &&
			(cc.largestAckedPacket-packet.pn > uint64(cc.reorderingThreshold)) {
			lostPackets = append(lostPackets, packet)
		}
	}

	if len(lostPackets) > 0 {
		cc.onPacketsLost(lostPackets)
	}
	for _, packet := range lostPackets {
		delete(cc.sentPackets, packet.pn)
	}
}

func (cc *CongestionControllerIetf) onPacketSentCC(bytes_sent int) {
	cc.bytesInFlight += bytes_sent
	cc.conn.log(logTypeCongestion, "%d bytes added to bytesInFlight", bytes_sent)
}

func (cc *CongestionControllerIetf) onPacketAckedCC(pn uint64) {
	cc.bytesInFlight -= cc.sentPackets[pn].bytes
	cc.conn.log(logTypeCongestion, "%d bytes from packet %d removed from bytesInFlight", cc.sentPackets[pn].bytes, pn)

	if pn < cc.endOfRecovery {
		// Do not increase window size during recovery
		return
	}
	if cc.congestionWindow < cc.sstresh {
		// Slow start
		cc.congestionWindow += cc.sentPackets[pn].bytes
		cc.conn.log(logTypeCongestion, "PDV Slow Start: increasing window size with %d bytes to %d",
			cc.sentPackets[pn].bytes, cc.congestionWindow)
	} else {

		// Congestion avoidance
		cc.congestionWindow += kDefaultMss * cc.sentPackets[pn].bytes / cc.congestionWindow
		cc.conn.log(logTypeCongestion, "PDV Congestion Avoidance: increasing window size to %d",
			cc.congestionWindow)
	}
}

func (cc *CongestionControllerIetf) onPacketsLost(packets []packetEntry) {
	var largestLostPn uint64 = 0
	for _, packet := range packets {

		// First remove lost packets from bytesInFlight and inform the connection
		// of the loss
		cc.conn.log(logTypeCongestion, "Packet pn: %d len: %d is lost", packet.pn, packet.bytes)
		cc.bytesInFlight -= packet.bytes
		if cc.lostPacketHandler != nil {
			cc.lostPacketHandler(packet.pn)
		}

		// and keep track of the largest lost packet
		if packet.pn > largestLostPn {
			largestLostPn = packet.pn
		}
	}

	// Now start a new recovery epoch if the largest lost packet is larger than the
	// end of the previous recovery epoch
	if cc.endOfRecovery < largestLostPn {
		cc.endOfRecovery = cc.largestSendPacket
		cc.congestionWindow = int(float32(cc.congestionWindow) * kLossReductionFactor)
		if kMinimumWindow > cc.congestionWindow {
			cc.congestionWindow = kMinimumWindow
		}
		cc.sstresh = cc.congestionWindow
		cc.conn.log(logTypeCongestion, "PDV Recovery started. Window size: %d, sstresh: %d, endOfRecovery %d",
			cc.congestionWindow, cc.sstresh, cc.endOfRecovery)
	}
}

func (cc *CongestionControllerIetf) bytesAllowedToSend() int {
	cc.conn.log(logTypeCongestion, "Remaining congestion window size: %d", cc.congestionWindow-cc.bytesInFlight)
	return cc.congestionWindow - cc.bytesInFlight
}

func newCongestionControllerIetf(conn *Connection) *CongestionControllerIetf {
	return &CongestionControllerIetf{
		0,                            // bytesInFlight
		kInitalWindow,                // congestionWindow
		0,                            // endOfRecovery
		int(^uint(0) >> 1),           // sstresh
		0,                            // lossDetectionAlarm
		0,                            // handshakeCount
		0,                            // tlpCount
		0,                            // rtoCount
		0,                            // largestSendBeforeRto
		time.Unix(0, 0),              // timeOfLastSentPacket
		0,                            // largestSendPacket
		0,                            // largestAckedPacket
		0,                            // maxAckDelay
		100 * time.Second,            // minRtt
		0,                            // smoothedRtt
		0,                            // rttVar
		0,                            // smoothedRttTcp
		0,                            // rttVarTcp
		kReorderingThreshold,         // reorderingThreshold
		math.MaxFloat32,              // timeReorderingFraction
		time.Unix(0, 0),              // lossTime
		make(map[uint64]packetEntry), // sentPackets
		nil,  // lostPacketHandler
		conn, // conn
	}
}
