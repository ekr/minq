/*
Package minq is a minimal implementation of QUIC, as documented at
https://quicwg.github.io/. Minq partly implements draft-04.

*/
package minq

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/bifurcation/mint"
	//	"github.com/bifurcation/mint/syntax"
)

// Role determines whether an endpoint is client or server.
type Role uint8

// These are roles.
const (
	RoleClient = Role(1)
	RoleServer = Role(2)
)

var HsEpochs = []mint.Epoch{mint.EpochClear, mint.EpochHandshakeData}

// State is the state of a QUIC connection.
type State uint8

// These are connection states.
const (
	StateInit                   = State(1)
	StateWaitClientInitial      = State(2)
	StateWaitServerInitial      = State(3)
	StateWaitServerFirstFlight  = State(4)
	StateWaitClientSecondFlight = State(5)
	StateEstablished            = State(6)
	StateClosing                = State(7)
	StateClosed                 = State(8)
	StateError                  = State(9)
)

const (
	kMinimumClientInitialLength  = 1200 // draft-ietf-quic-transport S 9.0
	kLongHeaderLength            = 12   // omits connection ID lengths
	kInitialIntegrityCheckLength = 16   // Overhead.
	kInitialMTU                  = 1252 // 1280 - UDP headers.
)

// The protocol version number.
type VersionNumber uint32

const (
	kQuicDraftVersion   = 13
	kQuicVersion        = VersionNumber(0xff000000 | kQuicDraftVersion)
	kQuicGreaseVersion1 = VersionNumber(0x1a1a1a1a)
	kQuicGreaseVersion2 = VersionNumber(0x2a2a2a2a)
)

const (
	kQuicALPNToken = "hq-13"
)

// Interface for the handler object which the Connection will call
// to notify of events on the connection.
type ConnectionHandler interface {
	// The connection has changed state to state |s|
	StateChanged(s State)

	// NewRecvStream indicates that a new unidirectional stream has been
	// created by the remote peer. |s| contains the stream.
	NewRecvStream(s RecvStream)

	// NewStream indicates that a new bidirectional stream has been
	// created by the remote peer. |s| contains the stream.
	NewStream(s Stream)

	// StreamReadable indicates that |s| is now readable.
	StreamReadable(s RecvStream)
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

type encryptionLevel struct {
	epoch            mint.Epoch
	nextSendPacket   uint64
	sendCipher       *cryptoState
	recvCipher       *cryptoState
	sendCryptoStream SendStream
	recvCryptoStream RecvStream
	outputQ          []*frame
	recvd            *recvdPackets
}

func (el *encryptionLevel) packetType() packetType {
	return []packetType{
		packetTypeInitial,
		packetType0RTTProtected,
		packetTypeHandshake,
		packetTypeProtectedShort,
	}[el.epoch]
}

type Connection struct {
	handler            ConnectionHandler
	role               Role
	state              State
	version            VersionNumber
	clientConnectionId ConnectionId
	serverConnectionId ConnectionId
	transport          Transport
	tls                *tlsConn
	encryptionLevels   []*encryptionLevel
	recvCryptoEpoch    mint.Epoch
	mtu                int
	localBidiStreams   *streamSet
	remoteBidiStreams  *streamSet
	localUniStreams    *streamSet
	remoteUniStreams   *streamSet
	clientInitial      []byte
	sendFlowControl    flowControl
	recvFlowControl    flowControl
	amountRead         uint64
	sentAcks           map[uint64]ackRanges
	lastInput          time.Time
	idleTimeout        time.Duration
	tpHandler          *transportParametersHandler
	log                loggingFunction
	retransmitTime     time.Duration
	congestion         CongestionController
	lastSendQueuedTime time.Time
	closingEnd         time.Time
	closePacket        []byte
}

// Create a new QUIC connection. Should only be used with role=RoleClient,
// though we use it with RoleServer internally.
func NewConnection(trans Transport, role Role, tls *TlsConfig, handler ConnectionHandler) *Connection {
	mint.HkdfLabelPrefix = "quic "
	c := &Connection{
		handler:            handler,
		role:               role,
		state:              StateInit,
		version:            kQuicVersion,
		clientConnectionId: nil,
		serverConnectionId: nil,
		transport:          trans,
		tls:                nil,
		encryptionLevels:   make([]*encryptionLevel, 4),
		recvCryptoEpoch:    mint.EpochClear,
		mtu:                kInitialMTU,
		localBidiStreams:   newStreamSet(streamTypeBidirectionalLocal, role, 1),
		remoteBidiStreams:  newStreamSet(streamTypeBidirectionalRemote, role, kConcurrentStreamsBidi),
		localUniStreams:    newStreamSet(streamTypeUnidirectionalLocal, role, 0),
		remoteUniStreams:   newStreamSet(streamTypeUnidirectionalRemote, role, kConcurrentStreamsUni),
		clientInitial:      nil,
		sendFlowControl:    flowControl{false, 0, 0},
		recvFlowControl:    flowControl{false, kInitialMaxData, 0},
		amountRead:         0,
		sentAcks:           make(map[uint64]ackRanges, 0),
		lastInput:          time.Now(),
		idleTimeout:        time.Second * 5, // a pretty short time
		tpHandler:          nil,
		log:                nil,
		retransmitTime:     kDefaultInitialRtt,
		congestion:         nil,
		lastSendQueuedTime: time.Now(),
		closingEnd:         time.Time{}, // Zero time
		closePacket:        nil,
	}

	c.log = newConnectionLogger(c)

	c.tls = newTlsConn(c, tls, role)
	//c.congestion = newCongestionControllerIetf(c)
	c.congestion = &CongestionControllerDummy{}
	c.congestion.setLostPacketHandler(c.handleLostPacket)

	// TODO(ekr@rtfm.com): This isn't generic, but rather tied to
	// Mint.
	c.tpHandler = newTransportParametersHandler(c.log, role, kQuicVersion)
	c.tls.setTransportParametersHandler(c.tpHandler)

	for i := int(0); i < 4; i++ {
		el := encryptionLevel{
			nextSendPacket: 1,
			epoch:          mint.Epoch(i),
			sendCipher:     nil,
			recvCipher:     nil,
			// We are using the streams data structures, but without flow control
			sendCryptoStream: newSendStream(c, ^uint64(uint64(i)), ^uint64(0)),
			recvCryptoStream: newRecvStream(c, ^uint64(uint64(i)), ^uint64(0)),
		}
		// TODO(ekr@rtfm.com): 0-RTT and 1-RTT should share these somehow.
		el.outputQ = make([]*frame, 0)
		el.recvd = newRecvdPackets(c.log)

		c.encryptionLevels[i] = &el
	}

	var err error
	if role == RoleClient {
		c.serverConnectionId, err = c.randomConnectionId(8)
		if err != nil {
			return nil
		}
		c.clientConnectionId, err = c.randomConnectionId(kCidDefaultLength)
		if err != nil {
			return nil
		}
		err = c.setupAeadMasking(c.serverConnectionId)
		if err != nil {
			return nil
		}
	} else {
		c.serverConnectionId, err = c.randomConnectionId(kCidDefaultLength)
		if err != nil {
			return nil
		}
		c.setState(StateWaitClientInitial)
	}

	return c
}

func (c *Connection) String() string {
	return fmt.Sprintf("Conn: %v_%v: %s", c.clientConnectionId, c.serverConnectionId, c.role)
}

func (c *Connection) zeroRttAllowed() bool {
	// Placeholder
	return false
}

func (c *Connection) start() error {
	return nil
}

func (c *Connection) Role() Role {
	return c.role
}

func (r Role) String() string {
	switch r {
	case RoleClient:
		return "client"
	case RoleServer:
		return "server"
	default:
		panic("invalid role")
	}
}

func (c *Connection) setState(state State) {
	if c.state == state {
		return
	}

	c.log(logTypeConnection, "Connection state %v -> %v", c.state, state)
	if c.handler != nil {
		c.handler.StateChanged(state)
	}
	c.state = state
}

func (state State) String() string {
	// TODO(ekr@rtfm.com): is there a way to get the name from the
	// const value.
	switch state {
	case StateInit:
		return "StateInit"
	case StateWaitClientInitial:
		return "StateWaitClientInitial"
	case StateWaitServerInitial:
		return "StateWaitServerInitial"
	case StateWaitServerFirstFlight:
		return "StateWaitServerFirstFlight"
	case StateWaitClientSecondFlight:
		return "StateWaitClientSecondFlight"
	case StateEstablished:
		return "StateEstablished"
	case StateClosing:
		return "StateClosing"
	case StateClosed:
		return "StateClosed"
	case StateError:
		return "StateError"
	default:
		return "Unknown state"
	}
}

// ClientId returns the current identity, as dictated by the client.
func (c *Connection) ClientId() ConnectionId {
	return c.clientConnectionId
}

// ServerId returns the current identity, as dictated by the server.
func (c *Connection) ServerId() ConnectionId {
	return c.serverConnectionId
}

func (c *Connection) ensureRemoteBidi(id uint64) hasIdentity {
	return c.remoteBidiStreams.ensure(id, func(x uint64) hasIdentity {
		msd := uint64(c.tpHandler.peerParams.maxStreamsData)
		return newStream(c, x, kInitialMaxStreamData, msd)
	}, func(s hasIdentity) {
		if c.handler != nil {
			c.log(logTypeStream, "Created Stream %v", s.Id())
			c.handler.NewStream(s.(Stream))
		}
	})
}

// This manages the creation of local and remote bidirectional streams as well
// as remote unidirectional streams.
func (c *Connection) ensureSendStream(id uint64) sendStreamPrivate {
	var s hasIdentity
	switch streamTypeFromId(id, c.role) {
	case streamTypeBidirectionalLocal:
		s = c.localBidiStreams.get(id)
	case streamTypeBidirectionalRemote:
		s = c.ensureRemoteBidi(id)
	case streamTypeUnidirectionalLocal:
		s = c.localUniStreams.get(id)
	default:
		// Local unidirectional streams can't receive.
		return nil
	}
	if s == nil {
		return nil
	}
	return s.(sendStreamPrivate)
}

// This manages the creation of local and remote bidirectional streams as well
// as remote unidirectional streams.
func (c *Connection) ensureRecvStream(id uint64) recvStreamPrivate {
	var s hasIdentity
	switch streamTypeFromId(id, c.role) {
	case streamTypeBidirectionalLocal:
		s = c.localBidiStreams.get(id)
	case streamTypeBidirectionalRemote:
		s = c.ensureRemoteBidi(id)
	case streamTypeUnidirectionalRemote:
		s = c.remoteUniStreams.ensure(id, func(x uint64) hasIdentity {
			return newRecvStream(c, x, kInitialMaxStreamData)
		}, func(s hasIdentity) {
			if c.handler != nil {
				c.log(logTypeStream, "Created RecvStream %v", s.Id())
				c.handler.NewRecvStream(s.(RecvStream))
			}
		})
	default:
		// Local unidirectional streams can't receive.
		return nil
	}
	if s == nil {
		return nil
	}
	return s.(recvStreamPrivate)
}

func (c *Connection) forEachSend(f func(sendStreamPrivate)) {
	c.localBidiStreams.forEach(func(s hasIdentity) {
		f(s.(sendStreamPrivate))
	})
	c.remoteBidiStreams.forEach(func(s hasIdentity) {
		f(s.(sendStreamPrivate))
	})
	c.localUniStreams.forEach(func(s hasIdentity) {
		f(s.(sendStreamPrivate))
	})
}

func (c *Connection) forEachRecv(f func(recvStreamPrivate)) {
	c.localBidiStreams.forEach(func(s hasIdentity) {
		f(s.(recvStreamPrivate))
	})
	c.remoteBidiStreams.forEach(func(s hasIdentity) {
		f(s.(recvStreamPrivate))
	})
	c.remoteUniStreams.forEach(func(s hasIdentity) {
		f(s.(recvStreamPrivate))
	})
}

func (c *Connection) sendClientInitial() error {
	panic("sendClientInitial API no longer exists")
}

func (c *Connection) determineEpoch(pt packetType) mint.Epoch {
	switch pt {
	case packetTypeInitial:
		return mint.EpochClear
	case packetType0RTTProtected:
		return mint.EpochEarlyData
	case packetTypeHandshake:
		return mint.EpochHandshakeData
	case packetTypeProtectedShort:
		return mint.EpochApplicationData
	default:
		// TODO(ekr@rtfm.com)": Check that packet decoding checks the types
		panic("Internal error")
	}
}

func (c *Connection) getEncryptionLevel(epoch mint.Epoch) *encryptionLevel {
	if int(epoch) >= len(c.encryptionLevels) {
		return nil
	}
	return c.encryptionLevels[epoch]
}

func (c *Connection) sendPacketRaw(el *encryptionLevel, pt packetType, version VersionNumber, pn uint64, payload []byte, containsOnlyAcks bool) ([]byte, error) {
	c.log(logTypeConnection, "Sending packet PT=%v PN=%x: %s", pt, pn, dumpPacket(payload))
	left := c.mtu // track how much space is left for payload

	aead := el.sendCipher.aead
	left -= aead.Overhead()

	var destCid ConnectionId
	var srcCid ConnectionId
	if c.role == RoleClient {
		destCid = c.serverConnectionId
		srcCid = c.clientConnectionId
	} else {
		srcCid = c.serverConnectionId
		destCid = c.clientConnectionId
	}

	p := newPacket(pt, destCid, srcCid, version, pn, payload, aead.Overhead())
	c.logPacket("Sending", &p.packetHeader, pn, payload)

	// Encode the header so we know how long it is.
	// TODO(ekr@rtfm.com): this is gross.
	hdr, err := encode(&p.packetHeader)
	if err != nil {
		return nil, err
	}
	hdrx := append(hdr, encodePacketNumber(pn, 4)...) // Always use the 4-byte PN
	left -= len(hdrx)
	assert(left >= len(payload))

	p.payload = payload
	protected := aead.Seal(nil, c.packetNonce(p.PacketNumber), p.payload, hdrx)
	packet := append(hdrx, protected...)

	// Encrypt the packet number in place.
	err = xorPacketNumber(&p.packetHeader, len(hdr), packet[len(hdr):len(hdr)+4], packet, el.sendCipher.pne)
	assert(err == nil)

	c.log(logTypeTrace, "Sending packet len=%d, len=%v", len(packet), hex.EncodeToString(packet))
	c.congestion.onPacketSent(pn, containsOnlyAcks, len(packet)) //TODO(piet@devae.re) check isackonly
	c.transport.Send(packet)

	return packet, nil
}

// Send a packet with whatever PT seems appropriate now.
func (c *Connection) sendPacketNow(tosend []*frame, containsOnlyAcks bool) ([]byte, error) {
	return c.sendPacket(c.encryptionLevels[mint.EpochApplicationData], packetTypeProtectedShort, tosend, containsOnlyAcks)
}

// Send a packet with a specific PT.
func (c *Connection) sendPacket(el *encryptionLevel, pt packetType, tosend []*frame, containsOnlyAcks bool) ([]byte, error) {
	sent := 0

	payload := make([]byte, 0)

	for _, f := range tosend {
		_, err := f.length()
		if err != nil {
			return nil, err
		}

		c.log(logTypeTrace, "Frame=%v", hex.EncodeToString(f.encoded))

		{
			msd, ok := f.f.(*maxStreamDataFrame)
			if ok {
				c.log(logTypeFlowControl, "EKR: PT=%x Sending maxStreamDate %v %v", el.nextSendPacket, msd.StreamId, msd.MaximumStreamData)
			}

		}
		payload = append(payload, f.encoded...)
		sent++
	}

	// Pad out client Initial
	if pt == packetTypeInitial && c.role == RoleClient && !containsOnlyAcks {
		topad := kMinimumClientInitialLength - (len(payload) +
			c.packetOverhead(el))
		payload = append(payload, make([]byte, topad)...)
	}

	pn := el.nextSendPacket
	el.nextSendPacket++

	return c.sendPacketRaw(el, pt, c.version, pn, payload, containsOnlyAcks)
}

func (c *Connection) makeAckFrame(el *encryptionLevel, acks ackRanges, left int) (*frame, int, error) {
	c.log(logTypeConnection, "Making ack frame, room=%d", left)
	af, rangesSent, err := newAckFrame(el.recvd, acks, left)
	if err != nil {
		c.log(logTypeConnection, "Couldn't prepare ACK frame %v", err)
		return nil, 0, err
	}

	return af, rangesSent, nil
}

func (c *Connection) sendQueued(bareAcks bool) (int, error) {
	c.log(logTypeConnection, "Calling sendQueued state=%s", c.GetState())

	c.lastSendQueuedTime = time.Now()

	if c.state == StateInit {
		return 0, nil
	}

	sent := 0

	// Send CRYPTO_HS and associated
	for _, el := range c.encryptionLevels {
		if el.sendCipher != nil {
			s, err := c.sendCryptoFrames(el, bareAcks)
			if err != nil {
				return sent, err
			}
			sent += s
		}
	}

	// Send application data
	el := c.streamEncryptionLevel()
	if el != nil {
		err := c.queueStreamFrames(el)
		if err != nil {
			return sent, err
		}

		// Send enqueued data from protected streams
		s, err := c.sendQueuedFrames(el, bareAcks)
		if err != nil {
			return sent, err
		}
		sent += s
	}

	return sent, nil
}

// Send a packet of stream frames, plus whatever acks fit.
func (c *Connection) sendCombinedPacket(pt packetType, el *encryptionLevel, frames []*frame, acks ackRanges, left int) (int, error) {
	asent := int(0)
	var err error

	containsOnlyAcks := len(frames) == 0

	if len(acks) > 0 && (left-kMaxAckHeaderLength) >= 0 {
		var af *frame
		af, asent, err = c.makeAckFrame(el, acks, left)
		if err != nil {
			return 0, err
		}
		if af != nil {
			frames = append(frames, af)
		}
	}
	// Record which packets we sent ACKs in.
	c.sentAcks[el.nextSendPacket] = acks[0:asent]

	_, err = c.sendPacket(el, pt, frames, containsOnlyAcks)
	if err != nil {
		return 0, err
	}

	return asent, nil
}

func (c *Connection) queueFrame(q *[]*frame, f *frame) {
	*q = append(*q, f)
}

// TODO(ekr@rtfm.com): Coalesce the frames, either here or in Mint.
func (c *Connection) sendCryptoFrames(el *encryptionLevel, bareAcks bool) (int, error) {
	s := el.sendCryptoStream
	q := &el.outputQ
	for _, ch := range s.(sendStreamPrivate).outputWritable() {
		f := newCryptoHsFrame(ch.offset, ch.data)
		c.queueFrame(q, f)
	}
	n, err := c.sendQueuedFrames(el, bareAcks)
	if err != nil {
		return 0, err
	}
	return n, err
}

func (c *Connection) enqueueStreamFrames(s sendStreamPrivate, q *[]*frame) {
	logf(logTypeStream, "Stream %v: enqueueing", s.Id())
	if s == nil {
		return
	}
	for _, ch := range s.outputWritable() {
		logf(logTypeStream, "Stream %v is writable", s.Id())
		f := newStreamFrame(s.Id(), ch.offset, ch.data, ch.last)
		c.queueFrame(q, f)
	}
}

// Send all the queued data on a set of streams with the current app data encryption
// level.
func (c *Connection) queueStreamFrames(el *encryptionLevel) error {
	c.log(logTypeConnection, "%v: queueStreamFrames", c.role)

	// Output all the stream frames that are now permitted by stream flow control
	c.forEachSend(func(s sendStreamPrivate) {
		c.enqueueStreamFrames(s, &el.outputQ)
	})
	return nil
}

func (c *Connection) sendFrame(f *frame) error {
	if c.state != StateEstablished {
		return ErrorWouldBlock
	}
	c.queueFrame(&c.encryptionLevels[mint.EpochApplicationData].outputQ, f)
	_, err := c.sendQueued(false)
	return err
}

func (c *Connection) packetOverhead(el *encryptionLevel) int {
	overhead := el.sendCipher.aead.Overhead()

	if el.epoch < mint.EpochApplicationData {
		overhead += kLongHeaderLength
		if c.role == RoleClient {
			overhead += len(c.clientConnectionId)
		} else {
			overhead += len(c.serverConnectionId)
		}
	} else {
		overhead += 5
	}
	if c.role == RoleClient {
		overhead += len(c.serverConnectionId)
	} else {
		overhead += len(c.clientConnectionId)
	}
	return overhead
}

func (c *Connection) suppressRetransmission(f *frame) bool {
	switch inner := f.f.(type) {
	case *paddingFrame, *pathChallengeFrame, *pathResponseFrame:
		return true

	case *streamIdBlockedFrame:
		switch streamTypeFromId(inner.StreamId, c.role) {
		case streamTypeBidirectionalLocal:
			return c.localBidiStreams.nstreams > len(c.localBidiStreams.streams)
		case streamTypeUnidirectionalLocal:
			return c.localUniStreams.nstreams > len(c.localUniStreams.streams)
		default:
			panic("shouldn't be complaining about this")
		}

	case *blockedFrame:
		return c.sendFlowControl.max > inner.Offset

	case *streamBlockedFrame:
		fc := c.ensureSendStream(inner.StreamId).flowControl()
		return fc.max > inner.Offset

	default:
		return false
	}
}

// maybeRemoveFromQueue is run after a packet is sent.
// Here we assume that toRemove is in the same order as the queue.
func (c *Connection) maybeRemoveFromQueue(queue *[]*frame, toRemove []*frame) {
	q := make([]*frame, 0, len(*queue)-len(toRemove))
	next := 0
	for _, f := range *queue {
		maybeRemove := (next < len(toRemove)) && (f == toRemove[next])
		if maybeRemove && c.suppressRetransmission(f) {
			c.log(logTypeTrace, "frame sent, suppressing retransmission: %v", f)
		} else {
			q = append(q, f)
		}
		if maybeRemove {
			next++
		}
	}
	*queue = q
}

/* Transmit all the frames permitted by connection level flow control and
* the congestion controller. We're going to need to be more sophisticated
* when we actually do connection level flow control. */
func (c *Connection) sendQueuedFrames(el *encryptionLevel, bareAcks bool) (int, error) {
	pt := el.packetType()
	c.log(logTypeConnection, "sendQueuedFrames, pt=%v, epoch=%v", pt, el.epoch)

	acks := el.recvd.prepareAckRange(el.epoch, false)
	now := time.Now()
	txAge := c.retransmitTime
	sent := int(0)
	spaceInCongestionWindow := c.congestion.bytesAllowedToSend()

	// Select the queue we will send from
	queue := &el.outputQ

	/* Iterate through the queue, and append frames to packet, sending
	 * packets when the maximum packet size is reached, or we are not
	 * allowed to send more from the congestion controller */

	// Calculate available space in the next packet.
	overhead := c.packetOverhead(el)
	spaceInPacket := c.mtu - overhead
	spaceInCongestionWindow -= overhead

	// Save a copy of the queue because this removes frames if they don't
	// need be sent again.
	originalQueue := *queue
	congested := false

	for index := 0; index < len(originalQueue); {
		// Store frames that will be sent in the next packet
		toSend := make([]*frame, 0)
		toRemove := make([]*frame, 0)

		spaceInPacket = c.mtu - overhead
		spaceInCongestionWindow -= overhead
		c.log(logTypeStream, "Building packet with %d and %d octets left",
			spaceInPacket, spaceInCongestionWindow)

		for ; index < len(originalQueue); index++ {
			f := originalQueue[index]

			frameLength, err := f.length()
			if err != nil {
				return sent, err
			}

			cAge := now.Sub(f.time)
			if f.needsTransmit {
				c.log(logTypeStream, "Frame %v requires transmission", f)
			} else if cAge < txAge {
				c.log(logTypeStream, "Skipping frame %v because sent too recently (%v < %v)", f, cAge, txAge)
				continue
			}

			// if there is no more space in the congestion window, this frame
			// can't be sent.
			if spaceInCongestionWindow < frameLength {
				congested = true
				break
			}
			// if there is no more space for the next frame in the packet,
			// send what we have and start forming a new packet
			if spaceInPacket < frameLength {
				break
			}

			c.log(logTypeFrame, "Sending frame %v, age = %v", f, cAge)
			// add the frame to the packet
			toSend = append(toSend, f)
			toRemove = append(toRemove, f)
			spaceInPacket -= frameLength
			spaceInCongestionWindow -= frameLength
		}

		// Now send the packet if there is anything worth sending.
		if len(toSend) == 0 {
			break
		}

		acksSent, err := c.sendCombinedPacket(pt, el, toSend, acks, spaceInPacket)
		if err != nil {
			return sent, err
		}

		// Record what was sent.
		sent++
		acks = acks[acksSent:]
		for _, f := range toSend {
			f.time = now
			f.needsTransmit = false
			f.pns = append(f.pns, el.nextSendPacket-1)
		}
		c.maybeRemoveFromQueue(queue, toRemove)

		if congested {
			break
		}
	}

	// Now send any bare acks that didn't fit in earlier packets.
	if len(acks) > 0 {
		if bareAcks {
			_, err := c.sendCombinedPacket(pt, el, nil, acks, c.mtu-overhead)
			if err != nil {
				return sent, err
			}
			sent++
		} else {
			c.log(logTypeAck, "Acks to send, but suppressing bare acks")
			return sent, nil
		}
	}

	return sent, nil
}

func (c *Connection) handleLostPacket(lostPn uint64) {
	panic("Unimplemented")
	/*
		queues := [][]*frame{c.outputClearQ, c.outputProtectedQ}
		for _, queue := range queues {
			for _, frame := range queue {
				for _, pn := range frame.pns {
					if pn == lostPn {
						// If the packet is considered lost, remember that.
						// Do *not* remove the PN from the list, because
						// the packet might pop up later anyway, and then
						// we want to mark this frame as received.
						frame.lostPns = append(frame.lostPns, lostPn)
					}
					if len(frame.pns) == len(frame.lostPns) {
						// if we consider all packets that this frame was send in as lost,
						// we have to retransmit it.
						frame.needsTransmit = true
						break
					}
				}
			}
		}*/
}

// Walk through all the streams and see how many bytes are outstanding.
// Right now this is very expensive.

func (c *Connection) outstandingQueuedBytes() (n int) {
	c.forEachSend(func(s sendStreamPrivate) {
		n += s.outstandingQueuedBytes()
	})

	cd := func(frames []*frame) int {
		ret := 0
		for _, f := range frames {
			sf, ok := f.f.(*streamFrame)
			if ok {
				ret += len(sf.Data)
			}
		}
		return ret
	}

	for _, el := range c.encryptionLevels {
		n += cd(el.outputQ)
	}

	return
}

// Input provides a packet to the connection.
//
// TODO(ekr@rtfm.com): when is error returned?
func (c *Connection) Input(p []byte) error {
	return c.handleError(c.input(p))
}

func (c *Connection) fireReadable() {
	if c.handler == nil {
		return
	}

	c.forEachRecv(func(s recvStreamPrivate) {
		if s.clearReadable() {
			c.handler.StreamReadable(s)
		}
	})
}

func (c *Connection) input(payload []byte) error {
	c.log(logTypeTrace, "Input packet length=%d", len(payload))
	fullLength := len(payload)
	if c.isClosed() {
		return ErrorConnIsClosed
	}

	if c.state == StateClosing {
		c.log(logTypeConnection, "Discarding packet while closing (closePacket=%v)", c.closePacket != nil)
		if c.closePacket != nil {
			c.transport.Send(c.closePacket)
		}
		return ErrorConnIsClosing
	}

	c.lastInput = time.Now()

	hdr := packetHeader{shortCidLength: kCidDefaultLength}

	c.log(logTypeTrace, "Receiving packet len=%v %v", len(payload), hex.EncodeToString(payload))
	hdrlen, err := decode(&hdr, payload)
	if err != nil {
		c.log(logTypeConnection, "Could not decode packet: %v", hex.EncodeToString(payload))
		return wrapE(ErrorInvalidPacket, err)
	}
	assert(int(hdrlen) <= len(payload))
	hdrbytes := payload[:hdrlen]

	if hdr.Type.isLongHeader() && hdr.Version != c.version {
		if c.role == RoleServer {
			c.log(logTypeConnection, "Received unsupported version %v, expected %v", hdr.Version, c.version)
			err = c.sendVersionNegotiation(hdr)
			if err != nil {
				return err
			}
			if c.state == StateWaitClientInitial {
				return ErrorDestroyConnection
			}
			return nil
		} else {
			// If we're a client, choke on unknown versions, unless
			// they come in version negotiation packets.
			if hdr.Version != 0 {
				return fmt.Errorf("Received packet with unexpected version %v", hdr.Version)
			}
		}
	}

	typ := hdr.getHeaderType()
	c.log(logTypeConnection, "Packet header %v, %d", hdr, typ)

	if hdr.Type.isLongHeader() && hdr.Version == 0 {
		return c.processVersionNegotiation(&hdr, hdrbytes)
	}

	if c.state == StateWaitClientInitial {
		if typ != packetTypeInitial {
			c.log(logTypeConnection, "Received unexpected packet before client initial")
			return ErrorDestroyConnection
		}

		// Now check the size.
		if fullLength < kMinimumClientInitialLength {
			c.log(logTypeConnection, "Discarding too short client Initial")
			return nil
		}
		err := c.setupAeadMasking(hdr.DestinationConnectionID)
		if err != nil {
			return err
		}
		c.serverConnectionId, err = c.randomConnectionId(kCidDefaultLength)
		if err != nil {
			return err
		}
		c.clientConnectionId = hdr.SourceConnectionID
	}

	// Figure out the epoch
	epoch := c.determineEpoch(typ)
	el := c.getEncryptionLevel(epoch)
	if el == nil || el.recvCipher == nil {
		c.log(logTypeConnection, "Received protected data before crypto state is ready")
		return nil
	}

	// Finally, decrypt the PN into a max-size buffer
	dpn := make([]byte, 4)
	err = xorPacketNumber(&hdr, int(hdrlen), dpn, payload, el.recvCipher.pne)
	if err != nil {
		return err
	}

	// Now decode it, which gives us a length
	pn, pnl, err := decodePacketNumber(dpn)
	if err != nil {
		c.log(logTypeConnection, "Could not decode PN: %v", hex.EncodeToString(payload))
		return wrapE(ErrorInvalidPacket, err)
	}

	// Now break things apart.
	hdrbytes = append(hdrbytes, dpn[:pnl]...)
	payload = payload[len(hdrbytes):]
	payloadLen := int(hdr.PayloadLength) - pnl
	var remainder []byte
	thisPacketLen := int(hdrlen) + payloadLen
	if hdr.Type.isLongHeader() && thisPacketLen < len(payload) {
		c.log(logTypeTrace, "Compound packet first part=%d", len(payload)-thisPacketLen)
		remainder = payload[payloadLen:]
		payload = payload[:payloadLen]
		c.log(logTypeTrace, "Paylod = %x", payload)
		c.log(logTypeTrace, "Compound packet remainder=%d %x", len(remainder), remainder)
	}

	if c.state == StateWaitServerInitial {
		c.log(logTypeConnection, "Changing server CID from %x -> %x", c.serverConnectionId, hdr.SourceConnectionID)
		assert(typ == packetTypeInitial)
		// Set the server's connection ID now.
		// TODO: don't let the server change its mind.  This is complicated
		// because each flight is multiple packets, and Handshake and Retry
		// packets can each set a different value.
		c.serverConnectionId = hdr.SourceConnectionID
		c.setState(StateWaitServerFirstFlight)
	}

	// TODO(ekr@rtfm.com): this dup detection doesn't work right if you
	// get a cleartext packet that has the same PN as a ciphertext or vice versa.
	// Need to fix.
	c.log(logTypeConnection, "Received (unverified) packet with PN=%x PT=%v",
		pn, hdr.getHeaderType())

	packetNumber := pn
	if el.recvd.initialized() {
		packetNumber = c.expandPacketNumber(el, pn, pnl)
		c.log(logTypeConnection, "Reconstructed packet number %x", packetNumber)
	}
	c.log(logTypeTrace, "Determined PN=%v", packetNumber)

	if el.recvd.initialized() && !el.recvd.packetNotReceived(packetNumber) {
		c.log(logTypeConnection, "Discarding duplicate packet %x", packetNumber)
		return nonFatalError(fmt.Sprintf("Duplicate packet id %x", packetNumber))
	}

	plaintext, err := el.recvCipher.aead.Open(nil, c.packetNonce(packetNumber), payload, hdrbytes)
	if err != nil {
		c.log(logTypeConnection, "Could not unprotect packet %x", payload)
		c.log(logTypeTrace, "Packet %h", payload)
		return wrapE(ErrorInvalidPacket, err)
	}

	c.logPacket("Receiving", &hdr, packetNumber, plaintext)

	// Now that we know it's valid, process stateless retry.
	if typ == packetTypeRetry {
		return c.processStatelessRetry(&hdr, plaintext)
	}

	if !el.recvd.initialized() {
		el.recvd.init(packetNumber)
	}

	naf := true
	err = c.processUnprotected(&hdr, el, packetNumber, plaintext, &naf)
	if err != nil {
		return err
	}

	if c.state == StateWaitClientInitial {
		// TODO(ekr@rtfm.com): This isn't really right, we need to
		// check to see if it's a CH.
		c.setState(StateWaitClientSecondFlight)
	}

	el.recvd.packetSetReceived(packetNumber, hdr.Type.isProtected(), naf)
	if err != nil {
		return err
	}

	lastSendQueuedTime := c.lastSendQueuedTime

	c.fireReadable()

	// Check if c.SendQueued() has been called while we were handling
	// the (STREAM) frames. If it has not been called yet, we call it
	// because we might have to ack the current packet, and might
	// have data waiting in the tx queues.
	if lastSendQueuedTime == c.lastSendQueuedTime {
		// Now flush our output buffers.
		_, err = c.sendQueued(naf)
		if err != nil {
			return err
		}
	}

	if remainder == nil {
		return nil
	}

	return c.input(remainder)
}

func (c *Connection) sendVersionNegotiation(hdr packetHeader) error {
	vn := newVersionNegotiationPacket([]VersionNumber{
		c.version,
		kQuicGreaseVersion1,
	})
	payload, err := encode(vn)
	if err != nil {
		return err
	}
	if hdr.PayloadLength < uint64(len(payload)) {
		// The received packet was far to small to be considered valid.
		// Just drop it without sending anything.
		return nil
	}

	// Generate a random packet type.
	pt := []byte{0}
	_, err = rand.Read(pt)
	if err != nil {
		return err
	}

	c.log(logTypeConnection, "Sending version negotiation packet")
	p := newPacket(packetType(pt[0]&0x7f), hdr.SourceConnectionID, hdr.DestinationConnectionID,
		0, 0, payload, 0)

	header, err := encode(&p.packetHeader)
	if err != nil {
		return err
	}

	// Note: we don't have a PN here, per spec.
	packet := append(header, payload...)
	// Note that we do not update the congestion controller for this packet.
	// This connection is about to disappear anyway.  Our defense against being
	// used as an amplifier is the size check above.
	c.transport.Send(packet)
	return nil
}

func (c *Connection) processVersionNegotiation(hdr *packetHeader, payload []byte) error {
	c.log(logTypeConnection, "Processing version negotiation packet")
	if c.encryptionLevels[mint.EpochClear].recvd.initialized() {
		c.log(logTypeConnection, "Ignoring version negotiation after received another packet")
	}

	// TODO(ekr@rtfm.com): Check the version negotiation fields.
	// TODO(ekr@rtfm.com): Ignore version negotiation after receiving
	// a non-version-negotiation packet.
	rdr := bytes.NewReader(payload)

	for rdr.Len() > 0 {
		u, err := uintDecodeInt(rdr, 4)
		if err != nil {
			return err
		}
		// Ignore the version we are already speaking.
		if VersionNumber(u) == c.version {
			return nil
		}
	}

	return ErrorReceivedVersionNegotiation
}

// I assume here that Stateless Retry contains just a single stream frame,
// contra the spec but per https://github.com/quicwg/base-drafts/pull/817
func (c *Connection) processStatelessRetry(hdr *packetHeader, payload []byte) error {
	panic("Can't do stateless retry")
	/*	c.log(logTypeConnection, "Processing stateless retry packet %s", dumpPacket(payload))
		if c.recvd.initialized() {
			c.log(logTypeConnection, "Ignoring stateless retry after received another packet")
		}

		// Directly parse the Stateless Retry rather than inserting it into
		// the stream processor.
		var sf streamFrame

		n, err := syntax.Unmarshal(payload, &sf)
		if err != nil {
			c.log(logTypeConnection, "Failure decoding stream frame in Stateless Retry")
			return err
		}

		if int(n) != len(payload) {
			return nonFatalError("Extra stuff in Stateless Retry: (%d != %d) %v", n, len(payload), hex.EncodeToString(payload[n:]))
		}

		if sf.StreamId != 0 {
			return nonFatalError("Received ClientInitial with stream id != 0")
		}

		if sf.Offset != 0 {
			return nonFatalError("Received ClientInitial with offset != 0")
		}

		// TODO(ekr@rtfm.com): add some more state checks that we don't get
		// multiple SRs
		assert(c.tls.getHsState() == "Client WAIT_SH")

		// Pass this data to the TLS connection, which gets us another CH which
		// we insert in ClientInitial
		cflt, err := c.tls.handshake(sf.Data)
		if err != nil {
			c.log(logTypeConnection, "TLS connection error: %v", err)
			return err
		}
		c.log(logTypeTrace, "Output of client handshake: %v", hex.EncodeToString(cflt))

		c.clientInitial = cflt
		return c.sendClientInitial()*/
}

type frameFilterFunc func(*frame) bool

func filterFrames(in []*frame, f frameFilterFunc) []*frame {
	out := make([]*frame, 0, len(in))
	for _, t := range in {
		if f(t) {
			out = append(out, t)
		}
	}

	return out
}

func (c *Connection) issueCredit(force bool) {
	c.log(logTypeFlowControl, "connection flow control credit %v", &c.recvFlowControl)
	// Always ensure that there is at least half an initial *stream* flow control window available.
	if !force && c.recvFlowControl.remaining() > (kInitialMaxStreamData/2) {
		return
	}

	c.log(logTypeFlowControl, "connection flow control credit %v", &c.recvFlowControl)
	c.recvFlowControl.max = c.amountRead + kInitialMaxData
	c.encryptionLevels[mint.EpochApplicationData].outputQ =
		filterFrames(c.encryptionLevels[mint.EpochApplicationData].outputQ, func(f *frame) bool {
			_, ok := f.f.(*maxDataFrame)
			return !ok
		})

	_ = c.sendFrame(newMaxData(c.recvFlowControl.max))
	c.log(logTypeFlowControl, "connection flow control now %v",
		&c.recvFlowControl)
}

func (c *Connection) updateBlocked() {
	c.encryptionLevels[mint.EpochApplicationData].outputQ = filterFrames(c.encryptionLevels[mint.EpochApplicationData].outputQ, func(f *frame) bool {
		_, ok := f.f.(*blockedFrame)
		return !ok
	})
	if c.sendFlowControl.remaining() > 0 {
		return
	}
	f := newBlockedFrame(c.sendFlowControl.used)
	_ = c.sendFrame(f)
	c.log(logTypeFlowControl, "sending %v", f)
}

func (c *Connection) issueStreamCredit(s RecvStream, max uint64) {
	// Don't issue credit for stream 0 during the handshake.
	if s.Id() == 0 && c.state != StateEstablished {
		return
	}

	// Remove other MAX_STREAM_DATA frames so we don't retransmit them. This violates
	// the current spec, but offline we all agree it's silly. See:
	// https://github.com/quicwg/base-drafts/issues/806
	c.encryptionLevels[mint.EpochApplicationData].outputQ = filterFrames(c.encryptionLevels[mint.EpochApplicationData].outputQ, func(f *frame) bool {
		inner, ok := f.f.(*maxStreamDataFrame)
		if !ok {
			return true
		}
		return inner.StreamId != s.Id()
	})

	_ = c.sendFrame(newMaxStreamData(s.Id(), max))
	c.log(logTypeFlowControl, "Issuing stream credit for stream %d, now %v", s.Id(), max)
}

func (c *Connection) updateStreamBlocked(s sendStreamPrivate) {
	c.encryptionLevels[mint.EpochApplicationData].outputQ = filterFrames(c.encryptionLevels[mint.EpochApplicationData].outputQ, func(f *frame) bool {
		inner, ok := f.f.(*streamBlockedFrame)
		if !ok {
			return true
		}
		return inner.StreamId != s.Id()
	})
	fc := s.flowControl()
	if fc.remaining() > 0 {
		return
	}
	f := newStreamBlockedFrame(s.Id(), fc.used)
	_ = c.sendFrame(f)
	c.log(logTypeFlowControl, "sending %v", f)
}

func (c *Connection) issueStreamIdCredit(t streamType) {
	// TODO work out how to issue in more reasonable increments.
	var max uint64
	switch t {
	case streamTypeBidirectionalRemote:
		max = c.remoteBidiStreams.credit(1)
	case streamTypeUnidirectionalRemote:
		max = c.remoteUniStreams.credit(1)
	}
	c.encryptionLevels[mint.EpochApplicationData].outputQ = filterFrames(c.encryptionLevels[mint.EpochApplicationData].outputQ, func(f *frame) bool {
		_, ok := f.f.(*maxStreamIdFrame)
		return !ok
	})

	_ = c.sendFrame(newMaxStreamId(max))
	c.log(logTypeFlowControl, "Issuing more %v stream ID credit: %d", t, max)
}

func (c *Connection) isFramePermitted(el *encryptionLevel, f frameType) bool {
	switch f {
	case kFrameTypeCryptoHs, kFrameTypePadding, kFrameTypePing, kFrameTypeAck:
		return true
	case kFrameTypeConnectionClose:
		// TODO: also crypto_close
		return el.epoch != mint.EpochEarlyData
	case kFrameTypeStream:
		return el.epoch == mint.EpochEarlyData || el.epoch == mint.EpochApplicationData
	default:
		return el.epoch == mint.EpochApplicationData
	}
}

func (c *Connection) processUnprotected(hdr *packetHeader, el *encryptionLevel, packetNumber uint64, payload []byte, naf *bool) error {
	c.log(logTypeHandshake, "Reading unprotected data in state %v", c.state)
	c.log(logTypeConnection, "Received Packet=%v", dumpPacket(payload))
	*naf = false

	for len(payload) > 0 {
		c.log(logTypeConnection, "payload bytes left %d", len(payload))
		n, f, err := decodeFrame(payload)
		if err != nil {
			c.log(logTypeConnection, "Couldn't decode frame %v", err)
			return err
		}
		c.log(logTypeConnection, "Frame type %v", f.f.getType())

		payload = payload[n:]
		nonAck := true

		if !c.isFramePermitted(el, f.f.getType()) {
			c.log(logTypeConnection, "Illegal frame [%v] in epoch %v", f, el.epoch)
			return ErrorProtocolViolation
		}
		switch inner := f.f.(type) {
		case *paddingFrame:
			// Skip.
		case *rstStreamFrame:
			// TODO(ekr@rtfm.com): Don't let the other side initiate
			// streams that are the wrong parity.
			c.log(logTypeStream, "Received RST_STREAM on stream %v", inner.StreamId)
			s := c.ensureRecvStream(inner.StreamId)
			if s == nil {
				return ErrorProtocolViolation
			}

			err = s.handleReset(inner.FinalOffset)
			if err != nil {
				return err
			}
			c.issueStreamIdCredit(streamTypeFromId(inner.StreamId, c.role))

		case *stopSendingFrame:
			c.log(logTypeStream, "Received STOP_SENDING on stream %v", inner.StreamId)
			s := c.ensureSendStream(inner.StreamId)
			if s == nil {
				return ErrorProtocolViolation
			}

			err = s.Reset(0) // STOPPING
			if err != nil {
				return err
			}

		case *connectionCloseFrame, *applicationCloseFrame:
			c.log(logTypeConnection, "Received %v, closing", f.f.getType())
			// Don't save the packet, we should go straight to draining.
			// Note that we don't bother with the optional transition from draining to
			// closing because we don't bother to decrypt packets that are received while
			// closing.
			closeFrame := newConnectionCloseFrame(kQuicErrorNoError, "received close frame")
			c.close(closeFrame, false)
			// Stop processing any more frames.
			return nil

		case *maxDataFrame:
			c.sendFlowControl.update(inner.MaximumData)
			c.updateBlocked()

		case *blockedFrame:
			c.log(logTypeFlowControl, "peer is blocked at %v", inner.Offset)
			// We don't strictly have to issue credit here, but receiving
			// BLOCKED is a potential sign that a MAX_DATA frame was lost.
			// It's also potentially a sign that the amount we're crediting is
			// too little, but we aren't tuning this yet.
			// Instead, aggressively send more credit.
			c.issueCredit(true)

		case *maxStreamDataFrame:
			s := c.ensureSendStream(inner.StreamId)
			if s == nil {
				return ErrorProtocolViolation
			}
			s.processMaxStreamData(inner.MaximumStreamData)
			c.updateStreamBlocked(s)

		case *streamBlockedFrame:
			s := c.ensureRecvStream(inner.StreamId)
			if s == nil {
				return ErrorProtocolViolation
			}
			c.log(logTypeFlowControl, "peer stream %d is blocked at %v", s.Id(), inner.Offset)
			// Aggressively send credit.  See the comment on BLOCKED above.
			s.updateMaxStreamData(true)

		case *maxStreamIdFrame:
			switch streamTypeFromId(inner.MaximumStreamId, c.role) {
			case streamTypeBidirectionalLocal:
				c.localBidiStreams.updateMax(inner.MaximumStreamId)
			case streamTypeUnidirectionalLocal:
				c.localUniStreams.updateMax(inner.MaximumStreamId)
			default:
				return ErrorProtocolViolation
			}

		case *ackFrame:
			//			c.log(logTypeConnection, "Received ACK, first range=%v-%v", inner.LargestAcknowledged-inner.AckBlockLength, inner.LargestAcknowledged)
			err = c.processAckFrame(inner, el)
			if err != nil {
				return err
			}
			nonAck = false

		case *streamFrame:
			c.log(logTypeStream, "Received on stream %v", inner)
			s := c.ensureRecvStream(inner.StreamId)
			if s == nil {
				return ErrorProtocolViolation
			}

			err = s.newFrameData(inner.Offset, inner.hasFin(), inner.Data, &c.recvFlowControl)
			if err != nil {
				return err
			}

		case *cryptoHsFrame:
			// TODO(ekr@rtfm.com): Check for state changes after
			// processing these framee.
			c.log(logTypeStream, "Received crypto frame", inner)

			err = el.recvCryptoStream.(*recvStream).
				newFrameData(inner.Offset, false, inner.Data, nil)

			if !c.tls.finished {
				err := c.tls.handshake()
				// TODO(ekr@rtfm.com): Check for extra bytes.
				if err != nil {
					return err
				}

				if c.tls.finished {
					err = c.handshakeComplete()
					if err != nil {
						return err
					}
					// We did this on the server already.
					c.setTransportParameters()
				}
			} else {
				err := c.tls.postHandshake()
				if err != nil {
					return err
				}
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

func (c *Connection) removeAckedFrames(pn uint64, qp *[]*frame) {
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

func (c *Connection) processAckRange(start uint64, end uint64, el *encryptionLevel) {
	assert(start <= end)
	c.log(logTypeConnection, "Process ACK range %v-%v", start, end)
	pn := start
	// Unusual loop structure to avoid weirdness at 2^64-1
	for {
		c.log(logTypeAck, "processing ACK for PN=%x", pn)

		// 1. Go through the outgoing queues and remove all the acked chunks.
		c.removeAckedFrames(pn, &el.outputQ)

		// 2. Mark all the packets that were ACKed in this packet as double-acked.
		acks, ok := c.sentAcks[pn]
		if ok {
			for _, a := range acks {
				c.log(logTypeAck, "Ack2 for ack range last=%v len=%v", a.lastPacket, a.count)

				if a.lastPacket < el.recvd.minNotAcked2 {
					// if there is nothing unacked in the range, continue
					continue
				}

				for i := uint64(0); i < a.count; i++ {
					el.recvd.packetSetAcked2(a.lastPacket - i)
				}
			}
		}
		if pn == end {
			break
		}
		pn++
	}
}

func (c *Connection) processAckFrame(f *ackFrame, el *encryptionLevel) error {
	var receivedAcks ackRanges
	c.log(logTypeAck, "processing ACK last=%x first ack block=%d", f.LargestAcknowledged, f.FirstAckBlock)
	end := f.LargestAcknowledged

	start := (end - f.FirstAckBlock)

	// Decode ACK Delay
	ackExp := kTpDefaultAckDelayExponent
	if c.tpHandler.peerParams != nil {
		ackExp = c.tpHandler.peerParams.ackDelayExp
	}
	ackDelay := time.Microsecond * time.Duration(f.AckDelay<<ackExp)

	// Process the First ACK Block
	c.log(logTypeAck, "processing ACK range %x-%x", start, end)
	c.processAckRange(start, end, el)
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
			c.log(logTypeAck, "encountered empty ACK block")
			continue
		}

		last = start
		c.log(logTypeAck, "processing ACK range %x-%x", start, end)
		c.processAckRange(start, end, el)
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

	if c.state == StateInit {
		assert(c.role == RoleClient)

		err := c.tls.handshake()
		if err != nil {
			return 0, err
		}

		c.setState(StateWaitServerInitial)
		if c.streamEncryptionLevel() != nil {
			assert(c.streamEncryptionLevel().epoch == mint.EpochEarlyData)
			c.log(logTypeConnection, "0-RTT available")
			c.tpHandler.setDummyPeerParams()
			c.setTransportParameters()
		}
	} else {
		if c.state == StateClosing {
			if time.Now().After(c.closingEnd) {
				c.log(logTypeConnection, "End of draining period, closing")
				c.setState(StateClosed)
				return 0, ErrorConnIsClosed
			}
			return 0, ErrorConnIsClosing
		}

		if time.Now().After(c.lastInput.Add(c.idleTimeout)) {
			c.log(logTypeConnection, "Connection is idle for more than %v", c.idleTimeout)
			c.setState(StateClosing)
			c.closingEnd = time.Now()
			return 0, ErrorConnIsClosing
		}
	}

	n, err := c.sendQueued(false)
	return n, c.handleError(err)
}

func (c *Connection) setTransportParameters() {
	// TODO(ekr@rtfm.com): Process the others..
	c.sendFlowControl.update(uint64(c.tpHandler.peerParams.maxData))
	c.localBidiStreams.nstreams = c.tpHandler.peerParams.maxStreamsBidi
	c.localUniStreams.nstreams = c.tpHandler.peerParams.maxStreamsUni
}

func (c *Connection) setupAeadMasking(cid ConnectionId) (err error) {
	params := mint.CipherSuiteParams{
		Suite:  mint.TLS_AES_128_GCM_SHA256,
		Cipher: nil,
		Hash:   crypto.SHA256,
		KeyLen: 16,
		IvLen:  12,
	}

	var sendLabel, recvLabel string
	if c.role == RoleClient {
		sendLabel = clientCtSecretLabel
		recvLabel = serverCtSecretLabel
	} else {
		sendLabel = serverCtSecretLabel
		recvLabel = clientCtSecretLabel
	}

	ciph, err := generateCleartextKeys(cid, sendLabel, &params)
	if err != nil {
		return
	}
	c.encryptionLevels[0].sendCipher = ciph

	ciph, err = generateCleartextKeys(cid, recvLabel, &params)
	if err != nil {
		return
	}
	c.encryptionLevels[0].recvCipher = ciph

	return nil
}

// Called when the handshake is complete.
func (c *Connection) handshakeComplete() (err error) {
	c.setState(StateEstablished)

	if c.role == RoleClient && c.encryptionLevels[mint.EpochEarlyData].sendCipher != nil {
		c.log(logTypeConnection, "Converting outstanding 0-RTT data to 1-RTT data")
		c.encryptionLevels[mint.EpochApplicationData].outputQ =
			c.encryptionLevels[mint.EpochEarlyData].outputQ
		c.encryptionLevels[mint.EpochEarlyData].outputQ = nil
	}

	return nil
}

func (c *Connection) packetNonce(pn uint64) []byte {
	return encodeArgs(pn)
}

// CreateStream creates a stream that can send and receive.
func (c *Connection) CreateStream() Stream {
	c.log(logTypeStream, "Creating new Stream")
	if c.tpHandler.peerParams == nil {
		return nil
	}
	s := c.localBidiStreams.create(func(id uint64) hasIdentity {
		recvMax := uint64(c.tpHandler.peerParams.maxStreamsData)
		return newStream(c, id, kInitialMaxStreamData, recvMax)
	})
	if s != nil {
		c.log(logTypeStream, "Created Stream %v", s.Id())
		return s.(Stream)
	}
	nextStreamId := c.localBidiStreams.id(len(c.localBidiStreams.streams))
	c.sendFrame(newStreamIdBlockedFrame(nextStreamId))
	return nil
}

// CreateSendStream creates a stream that can send only.
func (c *Connection) CreateSendStream() SendStream {
	c.log(logTypeStream, "Creating new SendStream")
	s := c.localUniStreams.create(func(id uint64) hasIdentity {
		recvMax := uint64(c.tpHandler.peerParams.maxStreamsData)
		return newSendStream(c, id, recvMax)
	})
	if s != nil {
		c.log(logTypeStream, "Created SendStream %v", s.Id())
		return s.(SendStream)
	}
	return nil
}

// GetStream retrieves a stream with the given id. Returns nil if
// no such stream exists.
func (c *Connection) GetStream(id uint64) Stream {
	var s hasIdentity
	switch streamTypeFromId(id, c.role) {
	case streamTypeBidirectionalLocal:
		s = c.localBidiStreams.get(id)
	case streamTypeBidirectionalRemote:
		s = c.remoteBidiStreams.get(id)
	default:
		return nil
	}
	if s != nil {
		return s.(Stream)
	}
	return nil
}

// GetSendStream retrieves a stream with the given id. Returns
// nil if no such stream exists.
func (c *Connection) GetSendStream(id uint64) SendStream {
	s := c.localUniStreams.get(id)
	if s != nil {
		return s.(SendStream)
	}
	return nil
}

// GetRecvStream retrieves a stream with the given id. Returns
// nil if no such stream exists.
func (c *Connection) GetRecvStream(id uint64) RecvStream {
	s := c.remoteUniStreams.get(id)
	if s != nil {
		return s.(RecvStream)
	}
	return nil
}

func (c *Connection) randomConnectionId(size int) (ConnectionId, error) {
	assert(size == 0 || (size >= 4 && size <= 18))
	b := make([]byte, size)

	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return nil, err
	}

	return ConnectionId(b), nil
}

// Set the handler class for a given connection.
func (c *Connection) SetHandler(h ConnectionHandler) {
	c.handler = h
}

func (c *Connection) close(f *frame, savePacket bool) error {
	if c.isClosed() {
		return nil
	}
	if c.state == StateClosing {
		return nil
	}

	c.closingEnd = time.Now().Add(3 * c.congestion.rto())
	c.setState(StateClosing)
	closePacket, err := c.sendPacketNow([]*frame{f}, false)
	if err != nil {
		return err
	}
	if savePacket {
		c.closePacket = closePacket
	}
	return nil
}

// Close a connection.
func (c *Connection) Close() error {
	c.log(logTypeConnection, "Close()")
	f := newConnectionCloseFrame(kQuicErrorNoError, "You don't have to go home but you can't stay here")
	return c.close(f, true)
}

func (c *Connection) Error(appError uint16, reason string) error {
	c.log(logTypeConnection, "Close()")
	f := newApplicationCloseFrame(appError, reason)
	return c.close(f, true)
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

func (c *Connection) handleError(e error) error {
	c.log(logTypeConnection, "Handling error: %v", e)
	if e == nil {
		return nil
	}

	if !isFatalError(e) {
		return nil
	}

	// Connection has failed.
	logf(logTypeConnection, "failed with Error=%v", e.Error())
	c.setState(StateError)

	return e
}

func (c *Connection) logPacket(dir string, hdr *packetHeader, pn uint64, payload []byte) {
	l := fmt.Sprintf("Packet %s: PN=%x LEN=%d hdr[%s]: %s", dir, pn, len(payload), hdr.String(), dumpPacket(payload))
	c.log(logTypePacket, l)
	c.log(logTypeConnection, l)
}

// S 5.8:
//   A packet number is decoded by finding the packet number value that is
//   closest to the next expected packet.  The next expected packet is the
//   highest received packet number plus one.  For example, if the highest
//   successfully authenticated packet had a packet number of 0xaa82f30e,
//   then a packet containing a 16-bit value of 0x1f94 will be decoded as
//   0xaa831f94.
//
//
// The expected sequence number is composed of:
//   EHi || ELo
//
// We get |pn|, which is the same length as ELo, so the possible values
// are:
//
// if pn > ELo, then either EHi || pn  or  EHi - 1 || pn  (wrapped downward)
// if Pn == Elo then Ei || pn
// if Pn < Elo  then either EHi || on  or  EHi + 1 || pn  (wrapped upward)
func (c *Connection) expandPacketNumber(el *encryptionLevel, pn uint64, size int) uint64 {
	if size == 8 {
		return pn
	}

	expected := el.recvd.maxReceived + 1
	c.log(logTypeTrace, "Expanding packet number, pn=%x size=%d expected=%x", pn, size, expected)

	// Mask off the top of the expected sequence number
	mask := uint64(1)
	mask = (mask << (uint8(size) * 8)) - 1
	expectedLow := mask & expected
	high := ^mask & expected
	match := high | pn

	// Exact match
	if expectedLow == pn {
		return match
	}

	if pn > expectedLow {
		if high == 0 {
			return match
		}
		wrap := (high - 1) | pn
		if (expected - wrap) <= (match - expected) {
			return wrap
		}
		return match
	}

	// expectedLow > pn
	wrap := (high + 1) | pn
	if (expected - match) <= (wrap - expected) {
		return match
	}
	return wrap
}

func (c *Connection) streamEncryptionLevel() *encryptionLevel {
	if c.state == StateEstablished {
		return c.encryptionLevels[mint.EpochApplicationData]
	}

	if c.encryptionLevels[mint.EpochEarlyData].sendCipher != nil {
		return c.encryptionLevels[mint.EpochEarlyData]
	}

	return nil
}

func (c *Connection) Writable() bool {
	return c.streamEncryptionLevel() != nil
}
