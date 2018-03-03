/*
Package minq is a minimal implementation of QUIC, as documented at
https://quicwg.github.io/. Minq partly implements draft-04.

*/
package minq

import (
	"crypto/rand"
	"encoding/hex"
	//"fmt"
	//	"github.com/bifurcation/mint"
	//	"github.com/bifurcation/mint/syntax"
	"time"
)

const (
	RoleClient = 1
	RoleServer = 2
)

// The state of a QUIC connection.
type State uint8

const (
	StateInit        = State(1)
	StateConnecting  = State(2)
	StateEstablished = State(3)
	StateClosed      = State(4)
	StateError       = State(5)
)

const (
	kMinimumClientInitialLength  = 1200 // draft-ietf-quic-transport S 9.0
	kLongHeaderLength            = 17
	kInitialIntegrityCheckLength = 16   // Overhead.
	kInitialMTU                  = 1252 // 1280 - UDP headers.
)

// The protocol version number.
type VersionNumber uint32

const (
	kQuicDraftVersion   = 8
	kQuicVersion        = VersionNumber(0xff000000 | kQuicDraftVersion)
	kQuicGreaseVersion1 = VersionNumber(0x1a1a1a1a)
	kQuicGreaseVersion2 = VersionNumber(0x2a2a2a2a)
)

const (
	kQuicALPNToken = "hq-08"
)

const (
	kDefaultInitialRtt = uint32(100)
)

// Interface for the handler object which the Connection will call
// to notify of events on the connection.
type ConnectionHandler interface {
	// The connection has changed state to state |s|
	StateChanged(s State)

	// A new stream has been created (by receiving a frame
	// from the other side. |s| contains the stream.
	NewStream(s *Stream)

	// Stream |s| is now readable.
	StreamReadable(s *Stream)
}

// Internal structures indicating ranges to ACK
type ackRange struct {
	lastPacket uint64 // Packet with highest pn in range
	count      uint64 // Total number of packets in range
}

type ackRanges []ackRange

/*
Connection represents a QUIC connection. Clients can make
connections directly but servers should create a minq.Server
object which creates Connections as a side effect.

The control discipline is entirely operated by the consuming
application. It has two major responsibilities:

  1. Deliver any incoming datagrams using Input()
  2. Periodically call CheckTimer(). In future there will be some
     way to know how often to call it, but right now it treats
     every call to CheckTimer() as timer expiry.

The application provides a handler object which the Connection
calls to notify it of various events.
*/
type Connection struct {
	handler            ConnectionHandler
	role               uint8
	state              State
	version            VersionNumber
	clientConnId       ConnectionId
	serverConnId       ConnectionId
	transport          Transport
	tls                *tlsConn
	nextSendPacket     uint64
	mtu                int
	streams            []*Stream
	maxStream          uint64
	outputClearQ       []frame // For stream 0
	outputProtectedQ   []frame // For stream >= 0
	clientInitial      []byte
	recvd              *recvdPackets
	sentAcks           map[uint64]ackRanges
	lastInput          time.Time
	idleTimeout        uint16
	tpHandler          *transportParametersHandler
	log                loggingFunction
	retransmitTime     uint32
	congestion         CongestionController
	lastSendQueuedTime time.Time
}

// Create a new QUIC connection. Should only be used with role=RoleClient,
// though we use it with RoleServer internally.
func NewConnection(trans Transport, role uint8, tls *TlsConfig, handler ConnectionHandler) *Connection {
	c := Connection{
		handler,
		role,
		StateInit,
		kQuicVersion,
		0,
		0,
		trans,
		newTlsConn(tls, role),
		uint64(0),
		kInitialMTU,
		nil,
		0,
		nil,
		nil,
		nil,
		nil,
		make(map[uint64]ackRanges, 0),
		time.Now(),
		10, // Very short idle timeout.
		nil,
		nil,
		kDefaultInitialRtt,
		nil,
		time.Now(),
	}

	c.log = newConnectionLogger(&c)

	//c.congestion = newCongestionControllerIetf(&c)
	c.congestion = &CongestionControllerDummy{}
	c.congestion.setLostPacketHandler(c.handleLostPacket)

	// TODO(ekr@rtfm.com): This isn't generic, but rather tied to
	// Mint.
	c.tpHandler = newTransportParametersHandler(c.log, role, kQuicVersion)
	c.tls.setTransportParametersHandler(c.tpHandler)

	c.recvd = newRecvdPackets(c.log)
	tmp, err := generateRand64()
	if err != nil {
		return nil
	}
	connId := ConnectionId(tmp)
	if role == RoleClient {
		c.clientConnId = connId
		c.setState(StateInit)
	} else {
		c.serverConnId = connId
		c.setState(StateConnecting)
	}

	tmp, err = generateRand64()
	if err != nil {
		return nil
	}
	s, newframe, _ := c.ensureStream(0, false)
	if newframe {
		s.setState(kStreamStateOpen)
	}
	return &c
}

func (c *Connection) start() error {
	return nil
}

func (c *Connection) label() string {
	if c.role == RoleClient {
		return "client"
	}
	return "server"
}

func (c *Connection) setState(state State) {
	if c.state == state {
		return
	}

	c.log(logTypeConnection, "%s: Connection state %s -> %v", c.label(), StateName(c.state), StateName(state))
	if c.handler != nil {
		c.handler.StateChanged(state)
	}
	c.state = state
}

func StateName(state State) string {
	// TODO(ekr@rtfm.com): is there a way to get the name from the
	// const value.
	switch state {
	case StateInit:
		return "StateInit"
	case StateConnecting:
		return "StateConnecting"
	case StateEstablished:
		return "StateEstablished"
	case StateClosed:
		return "StateClosed"
	case StateError:
		return "StateError"
	default:
		return "Unknown state"
	}
}

func (c *Connection) myStream(id uint64) bool {
	return id == 0 || (((id & 1) == 1) == (c.role == RoleServer))
}

func (c *Connection) sameTypeStream(id1 uint64, id2 uint64) bool {
	return (id1 & 0x3) == (id2 & 0x3)
}

func (c *Connection) streamSuffix(initiator uint8, bidi bool) uint64 {
	var suff uint64
	if bidi {
		suff |= 2
	}
	if initiator == RoleServer {
		suff |= 1
	}
	return suff
}

func (c *Connection) ensureStream(id uint64, remote bool) (*Stream, bool, error) {
	c.log(logTypeStream, "Ensuring stream %d exists", id)
	// TODO(ekr@rtfm.com): this is not really done, because we never clean up
	// Resize to fit.
	if uint64(len(c.streams)) >= id+1 {
		return c.streams[id], false, nil
	}

	// Don't create the stream if it's the wrong direction.
	if remote == c.myStream(id) {
		return nil, false, ErrorProtocolViolation
	}

	needed := id - uint64(len(c.streams)) + 1
	c.log(logTypeTrace, "Needed=%d", needed)
	c.streams = append(c.streams, make([]*Stream, needed)...)
	// Now make all the streams in the same direction
	i := id

	var initialMax uint64
	if c.tpHandler.peerParams != nil {
		initialMax = uint64(c.tpHandler.peerParams.maxStreamsData)
	} else {
		// assert(id == 0). TODO(ekr@rtfm.com): remember params for 0-RTT
		initialMax = 1280
	}

	for {
		if c.streams[i] != nil {
			break
		}

		if c.sameTypeStream(i, id) {
			s := newStream(c, i, initialMax, kStreamStateIdle)
			c.streams[i] = s
			if id != i {
				// Any lower-numbered streams start in open, so set the
				// state and notify.
				s.setState(kStreamStateOpen)
				if c.handler != nil {
					c.handler.NewStream(s)
				}
			}
		}

		if i == 0 {
			break
		}
		i--
	}
	if id > c.maxStream {
		c.maxStream = id
	}

	return c.streams[id], true, nil
}

// Send a packet with a specific PT.
func (c *Connection) sendPacket(pt uint8, tosend []frame, containsOnlyAcks bool) error {
	sent := 0

	payload := make([]byte, 0)

	for _, f := range tosend {
		_, err := f.length()
		if err != nil {
			return err
		}

		c.log(logTypeTrace, "Frame=%v", hex.EncodeToString(f.encoded))

		{
			msd, ok := f.f.(*maxStreamDataFrame)
			if ok {
				c.log(logTypeFlowControl, "EKR: PT=%x Sending maxStreamDate %v %v", c.nextSendPacket, msd.StreamId, msd.MaximumStreamData)
			}
		}
		payload = append(payload, f.encoded...)
		sent++
	}

	pn, packet, err := c.tls.sendPacket(payload)
	if err != nil {
		return err
	}
	c.log(logTypeTrace, "Sending packet: %x", packet)
	c.transport.Send(packet)

	c.congestion.onPacketSent(pn, false, len(payload)) //TODO(piet@devae.re) check isackonly

	return nil
}

func (c *Connection) sendOnStream(streamId uint64, data []byte) error {
	c.log(logTypeConnection, "%v: sending %v bytes on stream %v", c.label(), len(data), streamId)
	stream, newStream, _ := c.ensureStream(streamId, false)
	if newStream {
		stream.setState(kStreamStateOpen)
	}

	_, err := stream.Write(data)
	return err
}

func (c *Connection) makeAckFrame(acks ackRanges, left int) (*frame, int, error) {
	c.log(logTypeConnection, "Making ack frame, room=%d", left)
	af, rangesSent, err := newAckFrame(c.recvd, acks, left)
	if err != nil {
		c.log(logTypeConnection, "Couldn't prepare ACK frame %v", err)
		return nil, 0, err
	}

	return af, rangesSent, nil
}

func (c *Connection) sendQueued(bareAcks bool) (int, error) {
	c.log(logTypeConnection, "Calling sendQueued")

	c.lastSendQueuedTime = time.Now()

	if c.isClosed() {
		return 0, nil
	}

	if !c.Writable() {
		return 0, nil
	}

	sent := int(0)

	err := c.queueStreamFrames(true)
	if err != nil {
		return sent, err
	}

	s, err := c.sendQueuedFrames(packetTypeProtectedShort, true, bareAcks)
	if err != nil {
		return sent, err
	}

	sent += s

	return sent, nil
}

// Send a packet of stream frames, plus whatever acks fit.
func (c *Connection) sendCombinedPacket(pt uint8, frames []frame, acks ackRanges, left int) (int, error) {
	asent := int(0)
	var err error

	containsOnlyAcks := len(frames) == 0

	if len(acks) > 0 && (left-kMaxAckHeaderLength) >= 0 {
		var af *frame
		af, asent, err = c.makeAckFrame(acks, left)
		if err != nil {
			return 0, err
		}
		if af != nil {
			frames = append(frames, *af)
		}
	}
	// Record which packets we sent ACKs in.
	c.sentAcks[c.nextSendPacket] = acks[0:asent]

	err = c.sendPacket(pt, frames, containsOnlyAcks)
	if err != nil {
		return 0, err
	}

	return asent, nil
}

func (c *Connection) queueFrame(q *[]frame, f frame) {
	*q = append(*q, f)

}

// Send all the queued data on a set of streams with packet type |pt|
func (c *Connection) queueStreamFrames(protected bool) error {
	c.log(logTypeConnection, "%v: queueStreamFrames, protected=%v",
		c.label(), protected)

	var streams []*Stream
	var q *[]frame
	if !protected {
		streams = c.streams[0:1]
		q = &c.outputClearQ
	} else {
		streams = c.streams[1:]
		q = &c.outputProtectedQ
	}

	// Output all the stream frames that are now permitted by stream flow control
	for _, s := range streams {
		if s != nil {
			chunks, _ := s.outputWritable()
			for _, ch := range chunks {
				c.queueFrame(q, newStreamFrame(s.id, ch.offset, ch.data, ch.last))
			}
		}
	}

	return nil
}

/* Transmit all the frames permitted by connection level flow control and
* the congestion controller. We're going to need to be more sophisticated
* when we actually do connection level flow control. */
func (c *Connection) sendQueuedFrames(pt uint8, protected bool, bareAcks bool) (int, error) {
	c.log(logTypeConnection, "%v: sendQueuedFrames, pt=%v, protected=%v",
		c.label(), pt, protected)

	acks := c.recvd.prepareAckRange(protected, false)
	now := time.Now()
	txAge := time.Duration(c.retransmitTime) * time.Millisecond
	tlsOverhead := c.tls.overhead()
	sent := int(0)
	spaceInCongestionWindow := c.congestion.bytesAllowedToSend()

	// Select the queue we will send from
	var queue *[]frame
	if protected {
		queue = &c.outputProtectedQ
	} else {
		queue = &c.outputClearQ
	}

	// TODO(ekr@rtfm.com): Don't retransmit non-retransmittable.

	/* Iterate through the queue, and append frames to packet, sending
	 * packets when the maximum packet size is reached, or we are not
	 * allowed to send more from the congestion controller */

	// Store frames that will be sent in the next packet
	frames := make([]frame, 0)
	// The length of the next packet to be send
	spaceInPacket := c.mtu - tlsOverhead - kLongHeaderLength // TODO(ekr@rtfm.com): check header type
	spaceInCongestionWindow -= (tlsOverhead + kLongHeaderLength)

	for i, _ := range *queue {
		f := &((*queue)[i])
		// c.log(logTypeStream, "Examining frame=%v", f)

		frameLength, err := f.length()
		if err != nil {
			return 0, err
		}

		cAge := now.Sub(f.time)
		if f.needsTransmit {
			c.log(logTypeStream, "Frame %f requires transmission", f.String())
		} else if cAge < txAge {
			c.log(logTypeStream, "Skipping frame %f because sent too recently", f.String())
			continue
		}

		// if there is no more space in the congestion window, stop
		// trying to send stuff
		if spaceInCongestionWindow < frameLength {
			break
		}

		c.log(logTypeStream, "Sending frame %s, age = %v", f.String(), cAge)
		f.time = now
		f.needsTransmit = false

		// if there is no more space for the next frame in the packet,
		// send it and start forming a new packet
		if spaceInPacket < frameLength {
			asent, err := c.sendCombinedPacket(pt, frames, acks, spaceInPacket)
			if err != nil {
				return 0, err
			}
			sent++

			acks = acks[asent:]
			frames = make([]frame, 0)
			spaceInPacket = c.mtu - tlsOverhead - kLongHeaderLength // TODO(ekr@rtfm.com): check header type
			spaceInCongestionWindow -= (tlsOverhead + kLongHeaderLength)
		}

		// add the frame to the packet
		frames = append(frames, *f)
		spaceInPacket -= frameLength
		spaceInCongestionWindow -= frameLength
		// Record that we send this chunk in the current packet
		f.pns = append(f.pns, c.nextSendPacket)
		sf, ok := f.f.(*streamFrame)
		if ok && sf.hasFin() {
			c.streams[sf.StreamId].closeSend()
		}
	}

	// Send the remainder, plus any ACKs that are left.
	// TODO(piet@devae.re) This might push the outstanding data over the congestion window
	c.log(logTypeConnection, "%s: Remainder to send? sent=%v frames=%v acks=%v bareAcks=%v",
		c.label(), sent, len(frames), len(acks), bareAcks)
	if len(frames) > 0 || (len(acks) > 0 && bareAcks) {
		// TODO(ekr@rtfm.com): this may skip acks if there isn't
		// room, but hopefully we eventually catch up.
		_, err := c.sendCombinedPacket(pt, frames, acks, spaceInPacket)
		if err != nil {
			return 0, err
		}

		sent++
	} else if len(acks) > 0 {
		c.log(logTypeAck, "Acks to send, but suppressing bare acks")
	}

	return sent, nil
}

func (c *Connection) handleLostPacket(lostPn uint64) {
	queues := [...][]frame{c.outputClearQ, c.outputProtectedQ}
	for _, queue := range queues {
		for _, frame := range queue {
			for _, pn := range frame.pns {
				if pn == lostPn {
					/* If the packet is considered lost, remember that.
					 * Do *not* remove the PN from the list, because
					 * the packet might pop up later anyway, and then
					 * we want to mark this frame as received. */
					frame.lostPns = append(frame.lostPns, lostPn)
				}
				if len(frame.pns) == len(frame.lostPns) {
					/* if we consider all packets that this frame was send in as lost,
					 * we have to retransmit it. */
					frame.needsTransmit = true
					break
				}
			}
		}
	}
}

// Walk through all the streams and see how many bytes are outstanding.
// Right now this is very expensive.

func (c *Connection) outstandingQueuedBytes() (n int) {
	for _, s := range c.streams {
		n += s.outstandingQueuedBytes()
	}

	cd := func(frames []frame) int {
		ret := 0
		for _, f := range frames {
			sf, ok := f.f.(*streamFrame)
			if ok {
				ret += len(sf.Data)
			}
		}
		return ret
	}

	n += cd(c.outputClearQ)
	n += cd(c.outputProtectedQ)

	return
}

func (c *Connection) Start() error {
	if c.role == RoleServer {
		return nil
	}
	return c.Input([]byte{})
}

// Provide a packet to the connection.
//
// TODO(ekr@rtfm.com): when is error returned?

func (c *Connection) Input(p []byte) error {
	return c.handleError(c.input(p))
}

func (c *Connection) input(p []byte) error {
	c.log(logTypeTrace, "Input packet: %x", p)
	if c.isClosed() {
		return ErrorConnIsClosed
	}

	c.lastInput = time.Now()

	packetNumber, payload, output, err := c.tls.newBytes(p)
	if err != nil {
		return err
	}

	if c.tls.finished {
		c.setState(StateEstablished)
	}
	if !c.recvd.initialized() {
		c.recvd.init(packetNumber)
	}
	c.logPacket("Received", packetNumber, payload)

	naf := true
	err = c.processUnprotected(packetNumber, payload, &naf)

	c.recvd.packetSetReceived(packetNumber, true, naf)
	if err != nil {
		return err
	}

	lastSendQueuedTime := c.lastSendQueuedTime

	for _, stream := range c.streams {
		if stream != nil && stream.readable && c.handler != nil {
			c.handler.StreamReadable(stream)
			stream.readable = false
		}
	}

	// Check if c.SendQueued() has been called while we were handling
	// the (STREAM) frames. If it has not been called yet, we call it
	// because we might have to ack the current packet, and might
	// have data waiting in the tx queues.
	if lastSendQueuedTime == c.lastSendQueuedTime {
		// Now flush our output buffers.
		_, err = c.sendQueued(true)
		if err != nil {
			return err
		}
	}

	if output != nil {
		c.log(logTypeConnection, "Output packet len=%d", len(output))
		c.log(logTypeTrace, "Sending packet: %x", p)
		c.transport.Send(output)
	}

	return err
}

type frameFilterFunc func(*frame) bool

func filterFrames(in []frame, f frameFilterFunc) []frame {
	out := make([]frame, 0, len(in))
	for _, t := range in {
		if f(&t) {
			out = append(out, t)
		}
	}

	return out
}

func (c *Connection) issueStreamCredit(s *Stream, credit int) error {
	max := ^uint64(0)

	// Figure out how much credit to issue.
	if max-s.recv.maxStreamData > uint64(credit) {
		max = s.recv.maxStreamData + uint64(credit)
	}
	s.recv.maxStreamData = max

	// Now issue it.
	var q *[]frame
	if s.id == 0 {
		q = &c.outputClearQ
	} else {
		q = &c.outputProtectedQ
	}

	// Remove other MAX_STREAM_DATA frames so we don't retransmit them. This violates
	// the current spec, but offline we all agree it's silly. See:
	// https://github.com/quicwg/base-drafts/issues/806
	*q = filterFrames(*q, func(f *frame) bool {
		inner, ok := f.f.(*maxStreamDataFrame)
		if !ok {
			return true
		}
		return !(inner.StreamId == s.Id())
	})

	c.queueFrame(q, newMaxStreamData(s.Id(), max))
	c.log(logTypeFlowControl, "Issuing more stream credit for stream %d new offset=%d", s.Id(), max)

	// TODO(ekr@rtfm.com): We do need to do something to send this
	// immediately, because we don't always.
	return nil
}

func (c *Connection) processUnprotected(packetNumber uint64, payload []byte, naf *bool) error {
	c.log(logTypeHandshake, "Reading unprotected data in state %v", c.state)
	c.log(logTypeConnection, "Received Packet=%v", dumpPacket(payload))
	*naf = false
	for len(payload) > 0 {
		c.log(logTypeConnection, "%s: payload bytes left %d", c.label(), len(payload))
		n, f, err := decodeFrame(payload)
		if err != nil {
			c.log(logTypeConnection, "Couldn't decode frame %v", err)
			return err
		}
		c.log(logTypeConnection, "Frame type %v", f.f.getType())

		payload = payload[n:]
		nonAck := true
		switch inner := f.f.(type) {
		case *paddingFrame:
			// Skip.
		case *rstStreamFrame:
			// TODO(ekr@rtfm.com): Don't let the other side initiate
			// streams that are the wrong parity.
			c.log(logTypeStream, "Received RST_STREAM on stream %v", inner.StreamId)
			s, notifyCreated, err := c.ensureStream(inner.StreamId, true)
			if err != nil {
				return err
			}

			s.closeRecv()
			if notifyCreated && c.handler != nil {
				c.handler.NewStream(s)
			}
		case *connectionCloseFrame:
			c.setState(StateClosed)

		case *maxStreamDataFrame:
			s, notifyCreated, err := c.ensureStream(inner.StreamId, true)
			if err != nil {
				return err
			}
			if notifyCreated && c.handler != nil {
				s.setState(kStreamStateOpen)
				c.handler.NewStream(s)
			}
			err = s.processMaxStreamData(inner.MaximumStreamData)
			if err != nil {
				return err
			}

		case *ackFrame:
			//			c.log(logTypeConnection, "Received ACK, first range=%v-%v", inner.LargestAcknowledged-inner.AckBlockLength, inner.LargestAcknowledged)
			err = c.processAckFrame(inner, true)
			if err != nil {
				return err
			}
			nonAck = false

		case *streamBlockedFrame:
			s, notifyCreated, err := c.ensureStream(inner.StreamId, true)
			if err != nil {
				return err
			}
			if notifyCreated && c.handler != nil {
				s.setState(kStreamStateOpen)
				c.handler.NewStream(s)
			}

		case *streamFrame:
			c.log(logTypeTrace, "Received on stream %v %x", inner.StreamId, inner.Data)
			s, notifyCreated, err := c.ensureStream(inner.StreamId, true)
			if err != nil {
				return err
			}
			if notifyCreated && c.handler != nil {
				c.log(logTypeTrace, "Notifying of stream creation")
				s.setState(kStreamStateOpen)
				c.handler.NewStream(s)
			}

			err = c.newFrameData(s, inner)
			if err != nil {
				return err
			}

		default:
			c.log(logTypeConnection, "Received unexpected frame type")
		}
		if nonAck {
			*naf = true
		}
	}

	return nil
}

func (c *Connection) newFrameData(s *Stream, inner *streamFrame) error {
	if s.recv.maxStreamData-inner.Offset < uint64(len(inner.Data)) {
		return ErrorFrameFormatError
	}

	s.newFrameData(inner.Offset, inner.hasFin(), inner.Data)

	remaining := s.recv.maxStreamData - s.recv.lastReceivedByte()
	c.log(logTypeFlowControl, "Stream %d has %d bytes of credit remaining, last byte received was",
		s.Id(), remaining, s.recv.lastReceivedByte())
	if remaining < uint64(kInitialMaxStreamData) && s.Id() != 0 {
		c.issueStreamCredit(s, int(kInitialMaxStreamData))
	}
	return nil
}

func (c *Connection) removeAckedFrames(pn uint64, qp *[]frame) {
	q := *qp

	c.log(logTypeStream, "Removing ACKed chunks PN=%x, currently %v chunks", pn, len(q))

	for i := int(0); i < len(q); {
		remove := false
		f := q[i]
		// c.log(logTypeStream, "Examining frame %v PNs=%v", f, f.pns)
		for _, p := range f.pns {
			if pn == p {
				remove = true
				break
			}
		}

		if remove {
			c.log(logTypeStream, "Removing frame %v, sent in PN %v", f.f, pn)
			q = append(q[:i], q[i+1:]...)
		} else {
			i++
		}
	}
	c.log(logTypeStream, "Un-acked chunks remaining %v", len(q))
	*qp = q
}

func (c *Connection) processAckRange(start uint64, end uint64, protected bool) {
	assert(start <= end)
	c.log(logTypeConnection, "Process ACK range %v-%v", start, end)
	pn := start
	// Unusual loop structure to avoid weirdness at 2^64-1
	for {
		// TODO(ekr@rtfm.com): properly filter for ACKed packets which are in the
		// wrong key phase.
		c.log(logTypeConnection, "%s: processing ACK for PN=%x", c.label(), pn)

		// 1. Go through the outgoing queues and remove all the acked chunks.
		c.removeAckedFrames(pn, &c.outputClearQ)
		if protected {
			c.removeAckedFrames(pn, &c.outputProtectedQ)
		}

		// 2. Mark all the packets that were ACKed in this packet as double-acked.
		acks, ok := c.sentAcks[pn]
		if ok {
			for _, a := range acks {
				c.log(logTypeAck, "Ack2 for ack range last=%v len=%v", a.lastPacket, a.count)

				if a.lastPacket < c.recvd.minNotAcked2 {
					// if there is nothing unacked in the range, continue
					continue
				}

				for i := uint64(0); i < a.count; i++ {
					c.recvd.packetSetAcked2(a.lastPacket - i)
				}
			}
		}
		if pn == end {
			break
		}
		pn++
	}
}

func (c *Connection) processAckFrame(f *ackFrame, protected bool) error {
	var receivedAcks ackRanges
	c.log(logTypeAck, "%s: processing ACK last=%x first ack block=%d", c.label(), f.LargestAcknowledged, f.FirstAckBlock)
	end := f.LargestAcknowledged

	start := (end - f.FirstAckBlock)

	// Decode ACK Delay
	ackDelayMicros := QuicFloat16(f.AckDelay).Float32()
	ackDelay := time.Duration(ackDelayMicros * 1e3)

	// Process the First ACK Block
	c.log(logTypeAck, "%s: processing ACK range %x-%x", c.label(), start, end)
	c.processAckRange(start, end, protected)
	receivedAcks = append(receivedAcks, ackRange{end, end - start})

	// TODO(ekr@rtfm.com): Check for underflow.

	// Process aditional ACK Blocks
	last := start

	for _, block := range f.AckBlockSection {
		end = last - uint64(block.Gap) - 2
		start = end - block.Length

		// Not clear why the peer did this, but ignore.
		if block.Length == 0 {
			last -= uint64(block.Gap)
			c.log(logTypeAck, "%s: encountered empty ACK block", c.label())
			continue
		}

		last = start
		c.log(logTypeAck, "%s: processing ACK range %x-%x", c.label(), start, end)
		c.processAckRange(start, end, protected)
		receivedAcks = append(receivedAcks, ackRange{end, end - start})
	}

	c.congestion.onAckReceived(receivedAcks, ackDelay)

	return nil
}

// Check the connection's timer and process any events whose time has
// expired in the meantime. This includes sending retransmits, etc.
func (c *Connection) CheckTimer() (int, error) {
	if c.isClosed() {
		return 0, ErrorConnIsClosed
	}

	c.log(logTypeConnection, "Checking timer")

	if time.Now().After(c.lastInput.Add(time.Second * time.Duration(c.idleTimeout))) {
		c.log(logTypeConnection, "Connection is idle for more than %v", c.idleTimeout)
		return 0, ErrorConnectionTimedOut
	}

	// Right now just re-send everything we might need to send.

	// Special case the client's first message.
	if c.role == RoleClient && c.state == StateInit {
		err := c.startHandshake()
		return 1, err
	}

	n, err := c.sendQueued(false)
	return n, c.handleError(err)
}

func (c *Connection) startHandshake() error {
	err := c.input(nil)
	if err != nil {
		return err
	}
	c.setState(StateConnecting)
	return nil
}

func (c *Connection) setTransportParameters() {
	// TODO(ekr@rtfm.com): Process the others..
	_ = c.streams[0].processMaxStreamData(uint64(c.tpHandler.peerParams.maxStreamsData))
}

// Create a stream on a given connection. Returns the created
// stream.
func (c *Connection) CreateStream() *Stream {
	// First see if there is a stream that we haven't
	// created with this suffix.
	suff := c.streamSuffix(c.role, false)
	var i uint64
	for i = 0; i <= c.maxStream; i++ {
		if (i & 0x3) != suff {
			continue
		}
		if c.streams[i] == nil {
			s, _, _ := c.ensureStream(i, false)
			s.setState(kStreamStateOpen)
			return s
		}
	}

	// TODO(ekr@rtfm.com): Too tired to figure out the math here
	// for the same parity.
	for i = c.maxStream + 1; (i & 0x3) != suff; i++ {
	}

	c.log(logTypeStream, "Creating stream %v", i)
	s, _, _ := c.ensureStream(i, false)
	s.setState(kStreamStateOpen)
	return s
}

// Get the stream with stream id |id|. Returns nil if no such
// stream exists.
func (c *Connection) GetStream(id uint32) *Stream {
	iid := int(id)

	if iid >= len(c.streams) {
		return nil
	}

	return c.streams[iid]
}

func generateRand64() (uint64, error) {
	b := make([]byte, 8)

	_, err := rand.Read(b)
	if err != nil {
		return 0, err
	}

	ret := uint64(0)
	for _, c := range b {
		ret <<= 8
		ret |= uint64(c)
	}

	return ret, nil
}

// Set the handler class for a given connection.
func (c *Connection) SetHandler(h ConnectionHandler) {
	c.handler = h
}

func (c *Connection) close(code ErrorCode, reason string) {
	f := newConnectionCloseFrame(code, reason)
	c.sendPacket(packetTypeProtectedShort, []frame{f}, false)
}

// Close a connection.
func (c *Connection) Close() {
	c.log(logTypeConnection, "%v Close()", c.label())
	c.close(kQuicErrorNoError, "You don't have to go home but you can't stay here")
}

func (c *Connection) isDead() bool {
	return c.state == StateError
}

func (c *Connection) isClosed() bool {
	return c.state == StateError || c.state == StateClosed
}

// Get the current state of a connection.
func (c *Connection) GetState() State {
	return c.state
}

func (c *Connection) Writable() bool {
	return c.tls.writable()
}

// Get the connection ID for a connection. Returns 0 if
// you are a client and the first server packet hasn't
// been received.
func (c *Connection) Id() ConnectionId {
	return c.serverConnId
}

func (c *Connection) ClientId() ConnectionId {
	return c.clientConnId
}

func (c *Connection) handleError(e error) error {
	c.log(logTypeConnection, "Handling error: %v", e)
	if e == nil {
		return nil
	}

	if !isFatalError(e) {
		return nil
	}

	// Connection has failed.
	logf(logTypeConnection, "%v: failed with Error=%v", c.label(), e.Error())
	c.setState(StateError)

	return e
}

func (c *Connection) logPacket(dir string, pn uint64, payload []byte) {
	//l := fmt.Sprintf("Packet %s: PN=%x LEN=%d: %s", dir, pn, len(payload), dumpPacket(payload))
	//c.log(logTypePacket, l)
	//c.log(logTypeConnection, l)
}
