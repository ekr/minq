// Internal structure indicating packets we have
// received
package minq

import (
	"fmt"
	"github.com/bifurcation/mint"
	"time"
)

type packetData struct {
	protected bool
	nonAcks   bool
	pn        uint64
	t         time.Time
	acked2    bool
}

type recvdPackets struct {
	log          loggingFunction
	initted      bool
	minReceived  uint64
	maxReceived  uint64
	minNotAcked2 uint64
	packets      map[uint64]*packetData
	unacked      bool // Are there packets we haven't generated an ACK for
}

func newRecvdPackets(log loggingFunction) *recvdPackets {
	return &recvdPackets{
		log,   // loggingFunction
		false, // initted
		0,     // minReceived
		0,     // maxReceived
		0,     // minNotAcked2
		make(map[uint64]*packetData, 0), // packets
		false, // unacked
	}
}

func (p *recvdPackets) initialized() bool {
	return p.initted
}

func (p *recvdPackets) init(pn uint64) {
	p.log(logTypeAck, "Initializing received packet start=%x", pn)
	p.initted = true
	p.minReceived = pn
	p.maxReceived = pn
	p.minNotAcked2 = pn
}

func (p *recvdPackets) packetNotReceived(pn uint64) bool {
	if pn < p.minReceived {
		return false
	}
	_, found := p.packets[pn]
	return !found
}

func (p *recvdPackets) packetSetReceived(pn uint64, protected bool, nonAcks bool) {
	p.log(logTypeAck, "Setting packet received=%x", pn)
	if pn > p.maxReceived {
		p.maxReceived = pn
	}
	if pn < p.minNotAcked2 {
		p.minNotAcked2 = pn
	}
	p.log(logTypeAck, "Setting packet received=%x", pn)
	p.packets[pn] = &packetData{
		protected,
		nonAcks,
		pn,
		time.Now(),
		false,
	}
	p.unacked = true
}

func (p *recvdPackets) packetSetAcked2(pn uint64) {
	p.log(logTypeAck, "Setting packet acked2=%v", pn)
	if pn >= p.minNotAcked2 {
		pk, ok := p.packets[pn]
		if ok {
			pk.acked2 = true
		}
	}
}

func (r *ackRange) String() string {
	return fmt.Sprintf("%x(%d)", r.lastPacket, r.count)
}

func (r *ackRanges) String() string {
	rsp := ""
	for _, s := range *r {
		if rsp != "" {
			rsp += ", "
		}
		rsp += s.String()
	}
	return rsp
}

func (p *recvdPackets) needToAck() bool {
	return p.unacked
}

// Prepare a list of the ACK ranges, starting at the highest
func (p *recvdPackets) prepareAckRange(epoch mint.Epoch, allowAckOnly bool) ackRanges {
	p.log(logTypeAck, "Prepare ACK range epoch=%d", epoch)
	// Don't ACK if there's nothing new to ACK
	if !p.unacked {
		p.log(logTypeAck, "Nothing new to ACK")
		return nil
	}

	var last uint64
	var pn uint64
	inrange := false
	nonAcks := false

	ranges := make(ackRanges, 0)

	newMinNotAcked2 := p.maxReceived

	// TODO(ekr@rtfm.com): This is kind of a gross hack in case
	// someone sends us a 0 initial packet number.
	for pn = p.maxReceived; pn >= p.minNotAcked2 && pn > 0; pn-- {
		p.log(logTypeTrace, "Examining packet %x", pn)
		pk, ok := p.packets[pn]
		needs_ack := false

		// If we don't know about the packet, or if the ack has been
		// acked, we don't need to ack it.
		if ok && !pk.acked2 {
			needs_ack = true
			newMinNotAcked2 = pn
		}

		if ok && pk.acked2 {
			delete(p.packets, pn)
		}

		if needs_ack {
			p.log(logTypeTrace, "Acking packet %x", pn)
		}
		if needs_ack && pk.nonAcks {
			// Note if this is an ack of anything other than
			// acks.
			p.log(logTypeTrace, "Packet %x contains non-acks", pn)
			nonAcks = true
		}

		if inrange != needs_ack {
			if inrange {
				// This is the end of a range.
				ranges = append(ranges, ackRange{last, last - pn})
			} else {
				last = pn
			}
			inrange = needs_ack
		}
	}
	if inrange {
		p.log(logTypeTrace, "Appending final range %x-%x", last, pn+1)
		ranges = append(ranges, ackRange{last, last - pn})
	}

	p.minNotAcked2 = newMinNotAcked2

	p.log(logTypeAck, "%v ACK ranges to send", len(ranges))
	for i, r := range ranges {
		p.log(logTypeAck, "  %d = %v", i, r.String())
	}

	if !allowAckOnly && !nonAcks {
		p.log(logTypeAck, "No non-ack packets and this ack is not ack-only capable")
		return nil
	}

	p.unacked = false
	return ranges
}
