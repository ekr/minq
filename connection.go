/*
Package minq is a minimal implementation of QUIC, as documented at
https://quicwg.github.io/. Minq partly implements draft-04.

*/
package minq

import (
	"bytes"
	"crypto"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/bifurcation/mint"
	"time"
)

const (
	RoleClient = 1
	RoleServer = 2
)

// The state of a QUIC connection.
type State uint8

const (
	StateInit                   = State(1)
	StateWaitClientInitial      = State(2)
	StateWaitServerFirstFlight  = State(3)
	StateWaitClientSecondFlight = State(4)
	StateEstablished            = State(5)
	StateClosed                 = State(6)
	StateError                  = State(7)
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
	kQuicDraftVersion   = 7
	kQuicVersion        = VersionNumber(0xff000000 | kQuicDraftVersion)
	kQuicGreaseVersion1 = VersionNumber(0x1a1a1a1a)
	kQuicGreaseVersion2 = VersionNumber(0x2a2a2a2a)
)

const (
	kQuicALPNToken = "hq-07"
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
	handler          ConnectionHandler
	role             uint8
	state            State
	version          VersionNumber
	clientConnId     ConnectionId
	serverConnId     ConnectionId
	transport        Transport
	tls              *tlsConn
	writeClear       *cryptoState
	readClear        *cryptoState
	writeProtected   *cryptoState
	readProtected    *cryptoState
	nextSendPacket   uint64
	mtu              int
	streams          []*Stream
	maxStream        uint32
	outputClearQ     []frame // For stream 0
	outputProtectedQ []frame // For stream >= 0
	clientInitial    []byte
	recvd            *recvdPackets
	sentAcks         map[uint64]ackRanges
	lastInput        time.Time
	idleTimeout      uint16
	tpHandler        *transportParametersHandler
	log              loggingFunction
	retransmitTime   uint32
}

// Create a new QUIC connection. Should only be used with role=RoleClient,
// though we use it with RoleServer internally.
func NewConnection(trans Transport, role uint8, tls TlsConfig, handler ConnectionHandler) *Connection {
	c := Connection{
		handler,
		role,
		StateInit,
		kQuicVersion,
		0,
		0,
		trans,
		newTlsConn(tls, role),
		nil,
		nil,
		nil,
		nil,
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
	}

	c.log = newConnectionLogger(&c)

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
		err = c.setupAeadMasking()
		if err != nil {
			return nil
		}
	} else {
		c.serverConnId = connId
		c.setState(StateWaitClientInitial)
	}
	tmp, err = generateRand64()
	if err != nil {
		return nil
	}
	c.nextSendPacket = tmp & 0x7fffffff
	s, newframe, _ := c.ensureStream(0, false)
	if newframe {
		s.setState(kStreamStateOpen)
	}
	return &c
}

func (c *Connection) zeroRttAllowed() bool {
	// Placeholder
	return false
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
	case StateWaitClientInitial:
		return "StateWaitClientInitial"
	case StateWaitServerFirstFlight:
		return "StateWaitServerFirstFlight"
	case StateWaitClientSecondFlight:
		return "StateWaitClientSecondFlight"
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

func (c *Connection) myStream(id uint32) bool {
	return id == 0 || (((id & 1) == 1) == (c.role == RoleClient))
}

func (c *Connection) ensureStream(id uint32, remote bool) (*Stream, bool, error) {
	c.log(logTypeTrace, "Ensuring stream %d exists", id)
	// TODO(ekr@rtfm.com): this is not really done, because we never clean up
	// Resize to fit.
	if uint32(len(c.streams)) >= id+1 {
		return c.streams[id], false, nil
	}

	// Don't create the stream if it's the wrong direction.
	if remote == c.myStream(id) {
		return nil, false, ErrorProtocolViolation
	}

	needed := id - uint32(len(c.streams)) + 1
	c.log(logTypeTrace, "Needed=%d", needed)
	c.streams = append(c.streams, make([]*Stream, needed)...)
	// Now make all the streams in the same direction
	i := id

	var initialMax uint64
	if c.tpHandler.peerParams != nil {
		initialMax = uint64(c.tpHandler.peerParams.maxStreamsData)
	} else {
		assert(id == 0)
		initialMax = 1280
	}

	for {
		if c.streams[i] != nil {
			break
		}

		if (i & 1) == (id & 1) {
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

func (c *Connection) sendClientInitial() error {
	queued := make([]frame, 0)
	var err error

	c.log(logTypeHandshake, "Sending client initial packet")
	if c.clientInitial == nil {
		c.clientInitial, err = c.tls.handshake(nil)
		if err != nil {
			return err
		}
	}

	f := newStreamFrame(0, 0, c.clientInitial, false)
	// Encode this so we know how much room it is going to take up.
	l, err := f.length()
	if err != nil {
		return err
	}

	/*
	   unless the client has a reasonable assurance that the PMTU is larger.
	   Sending a packet of this size ensures that the network path supports
	   an MTU of this size and helps reduce the amplitude of amplification
	   attacks caused by server responses toward an unverified client
	   address.
	*/
	topad := kMinimumClientInitialLength - (kLongHeaderLength + l + kInitialIntegrityCheckLength)
	c.log(logTypeHandshake, "Padding with %d padding frames", topad)

	// Enqueue the frame for transmission.
	queued = append(queued, f)

	c.streams[0].send.setOffset(uint64(len(c.clientInitial)))

	for i := 0; i < topad; i++ {
		queued = append(queued, newPaddingFrame(0))
	}

	c.setState(StateWaitServerFirstFlight)

	return c.sendPacket(packetTypeClientInitial, queued)
}

func (c *Connection) sendSpecialClearPacket(pt uint8, connId ConnectionId, pn uint64, version VersionNumber, payload []byte) error {
	c.log(logTypeConnection, "Sending special clear packet type=%v", pt)
	p := packet{
		packetHeader{
			pt | packetFlagLongHeader,
			connId,
			pn,
			version,
		},
		payload,
	}

	packet, err := encode(&p.packetHeader)
	if err != nil {
		return err
	}
	packet = append(packet, payload...)
	c.transport.Send(packet)
	return nil
}

func (c *Connection) determineAead(pt uint8) cipher.AEAD {
	var aead cipher.AEAD
	if c.writeProtected != nil {
		aead = c.writeProtected.aead
	}

	if c.role == RoleClient {
		switch {
		case pt == packetTypeClientInitial:
			aead = c.writeClear.aead
		case pt == packetTypeClientCleartext:
			aead = c.writeClear.aead
		case pt == packetType0RTTProtected:
			aead = nil // This will cause a crash b/c 0-RTT doesn't work yet
		}
	} else {
		if pt == packetTypeServerCleartext || pt == packetTypeServerStatelessRetry {
			aead = c.writeClear.aead
		}
	}

	return aead
}

func (c *Connection) sendPacketRaw(pt uint8, connId ConnectionId, pn uint64, version VersionNumber, payload []byte) error {
	c.log(logTypeConnection, "Sending packet PT=%v PN=%x: %s", pt, c.nextSendPacket, dumpPacket(payload))
	left := c.mtu // track how much space is left for payload

	aead := c.determineAead(pt)
	left -= aead.Overhead()

	// Horrible hack. Map phase0 -> short header.
	// TODO(ekr@rtfm.com): Fix this way above here.
	if pt == packetType1RTTProtectedPhase0 {
		pt = 3 | packetFlagC // 4-byte packet number
	} else {
		pt = pt | packetFlagLongHeader
	}
	p := packet{
		packetHeader{
			pt,
			connId,
			pn,
			version,
		},
		nil,
	}
	c.logPacket("Sent", &p.packetHeader, pn, payload)

	// Encode the header so we know how long it is.
	// TODO(ekr@rtfm.com): this is gross.
	hdr, err := encode(&p.packetHeader)
	if err != nil {
		return err
	}
	left -= len(hdr)
	assert(left >= len(payload))

	p.payload = payload
	protected := aead.Seal(nil, c.packetNonce(p.PacketNumber), p.payload, hdr)
	packet := append(hdr, protected...)

	c.log(logTypeTrace, "Sending packet len=%d, len=%v", len(packet), hex.EncodeToString(packet))
	c.transport.Send(packet)

	return nil
}

// Send a packet with whatever PT seems appropriate now.
func (c *Connection) sendPacketNow(tosend []frame) error {
	// Right now this is just 1-RTT 0-phase
	return c.sendPacket(packetType1RTTProtectedPhase0, tosend)
}

// Send a packet with a specific PT.
func (c *Connection) sendPacket(pt uint8, tosend []frame) error {
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

	connId := c.serverConnId
	if c.role == RoleClient {
		if pt == packetTypeClientInitial {
			connId = c.clientConnId
		}
	} else {
		if pt == packetTypeServerStatelessRetry {
			connId = c.clientConnId
		}
	}

	pn := c.nextSendPacket
	c.nextSendPacket++

	return c.sendPacketRaw(pt, connId, pn, c.version, payload)
}

func (c *Connection) sendFramesInPacket(pt uint8, tosend []frame) error {
	c.log(logTypeConnection, "%s: Sending packet of type %v. %v frames", c.label(), pt, len(tosend))
	c.log(logTypeTrace, "Sending packet of type %v. %v frames", pt, len(tosend))
	left := c.mtu

	var connId ConnectionId
	var aead cipher.AEAD
	if c.writeProtected != nil {
		aead = c.writeProtected.aead
	}
	connId = c.serverConnId

	longHeader := true
	if c.role == RoleClient {
		switch {
		case pt == packetTypeClientInitial:
			aead = c.writeClear.aead
			connId = c.clientConnId
		case pt == packetTypeClientCleartext:
			aead = c.writeClear.aead
		case pt == packetType0RTTProtected:
			connId = c.clientConnId
			aead = nil // This will cause a crash b/c 0-RTT doesn't work yet
		default:
			longHeader = false
		}
	} else {
		if pt == packetTypeServerCleartext {
			aead = c.writeClear.aead
		} else {
			longHeader = true
		}
	}

	left -= aead.Overhead()

	npt := pt
	if longHeader {
		npt |= packetFlagLongHeader
	}
	p := packet{
		packetHeader{
			npt,
			connId,
			c.nextSendPacket,
			c.version,
		},
		nil,
	}
	c.nextSendPacket++

	// Encode the header so we know how long it is.
	// TODO(ekr@rtfm.com): this is gross.
	hdr, err := encode(&p.packetHeader)
	if err != nil {
		return err
	}
	left -= len(hdr)

	sent := 0

	for _, f := range tosend {
		l, err := f.length()
		if err != nil {
			return err
		}

		assert(l <= left)

		c.log(logTypeTrace, "Frame=%v", hex.EncodeToString(f.encoded))
		p.payload = append(p.payload, f.encoded...)
		sent++
	}

	protected := aead.Seal(nil, c.packetNonce(p.PacketNumber), p.payload, hdr)
	packet := append(hdr, protected...)

	c.log(logTypeTrace, "Sending packet len=%d, len=%v", len(packet), hex.EncodeToString(packet))
	c.transport.Send(packet)

	return nil
}

func (c *Connection) sendOnStream(streamId uint32, data []byte) error {
	c.log(logTypeConnection, "%v: sending %v bytes on stream %v", c.label(), len(data), streamId)
	stream, newStream, _ := c.ensureStream(streamId, false)
	if newStream {
		stream.setState(kStreamStateOpen)
	}

	_, err := stream.Write(data)
	return err
}

func (c *Connection) makeAckFrame(acks ackRanges, left int) (*frame, int, error) {
	af, rangesSent, err := newAckFrame(acks, left)
	if err != nil {
		c.log(logTypeConnection, "Couldn't prepare ACK frame %v", err)
		return nil, 0, err
	}

	return af, rangesSent, nil
}

func (c *Connection) sendQueued(bareAcks bool) (int, error) {
	if c.state == StateInit || c.state == StateWaitClientInitial {
		return 0, nil
	}

	sent := int(0)

	// First send stream 0 if needed.
	pt := uint8(packetTypeClientCleartext)
	if c.role == RoleServer {
		pt = packetTypeServerCleartext
	}

	// Now send other streams if we are in encrypted mode.
	if c.state == StateEstablished {
		s, err := c.queueStreamFrames(packetType1RTTProtectedPhase0, true, bareAcks)
		if err != nil {
			return sent, err
		}
		sent += s
		bareAcks = false // We still want to send out data in unprotected mode but we don't need to just ACK stuff.

	}

	s, err := c.queueStreamFrames(pt, false, bareAcks)
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

	for _, f := range frames {
		l, err := f.length()
		if err != nil {
			return 0, err
		}
		left -= l
	}

	if len(acks) > 0 {
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

	err = c.sendPacket(pt, frames)
	if err != nil {
		return 0, err
	}

	return asent, nil
}

func (c *Connection) queueFrame(q *[]frame, f frame) {
	*q = append(*q, f)

}

// Send all the queued data on a set of streams with packet type |pt|
func (c *Connection) queueStreamFrames(pt uint8, protected bool, bareAcks bool) (int, error) {
	c.log(logTypeConnection, "%v: sendQueuedStreamData pt=%v, protected=%v",
		c.label(), pt, protected)
	frames := make([]frame, 0)
	sent := int(0)
	acks := c.recvd.prepareAckRange(protected, false)
	now := time.Now()
	txAge := time.Duration(c.retransmitTime) * time.Millisecond

	aeadOverhead := c.determineAead(pt).Overhead()

	leftInitial := c.mtu - aeadOverhead - kLongHeaderLength // TODO(ekr@rtfm.com): check header type
	left := leftInitial

	var streams []*Stream
	var q *[]frame
	if !protected {
		streams = c.streams[0:1]
		q = &c.outputClearQ
	} else {
		streams = c.streams[1:]
		q = &c.outputProtectedQ
	}

	// 1. Output all the stream frames that are now permitted by stream flow control
	//
	for _, s := range streams {
		if s != nil {
			chunks, _ := s.outputWritable()
			for _, ch := range chunks {
				c.queueFrame(q, newStreamFrame(s.id, ch.offset, ch.data, ch.last))
			}
		}
	}

	// 2. Now transmit all the frames permitted by connection level flow control.
	// We're going to need to be more sophisticated when we actually do connection
	// level flow control.
	// TODO(ekr@rtfm.com): Don't retransmit non-retransmittable.
	for i, _ := range *q {
		f := &((*q)[i])
		// c.log(logTypeStream, "Examining frame=%v", f)
		l, err := f.length()
		if err != nil {
			return 0, err
		}

		cAge := now.Sub(f.time)
		if cAge < txAge {
			c.log(logTypeStream, "Skipping frame %f because sent too recently", f.String())
			continue
		}

		c.log(logTypeStream, "Sending frame %s, age = %v", f.String(), cAge)
		f.time = now

		if left < l {
			asent, err := c.sendCombinedPacket(pt, frames, acks, left)
			if err != nil {
				return 0, err
			}
			sent++

			acks = acks[asent:]
			frames = make([]frame, 0)
			left = leftInitial
		}

		frames = append(frames, *f)
		left -= l
		// Record that we send this chunk in the current
		f.pns = append(f.pns, c.nextSendPacket)
		sf, ok := f.f.(*streamFrame)
		if ok && sf.hasFin() {
			c.streams[sf.StreamId].closeSend()
		}
	}

	// Send the remainder, plus any ACKs that are left.
	c.log(logTypeConnection, "%s: Remainder to send? sent=%v frames=%v acks=%v bareAcks=%v",
		c.label(), sent, len(frames), len(acks), bareAcks)
	if len(frames) > 0 || (len(acks) > 0 && bareAcks) {
		// TODO(ekr@rtfm.com): this may skip acks if there isn't
		// room, but hopefully we eventually catch up.
		_, err := c.sendCombinedPacket(pt, frames, acks, left)
		if err != nil {
			return 0, err
		}

		sent++
	} else if len(acks) > 0 {
		c.log(logTypeAck, "Acks to send, but suppressing bare acks")
	}

	return sent, nil
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

// Provide a packet to the connection.
//
// TODO(ekr@rtfm.com): when is error returned?

func (c *Connection) Input(p []byte) error {
	return c.handleError(c.input(p))
}

func (c *Connection) input(p []byte) error {
	if c.isClosed() {
		return ErrorConnIsClosed
	}

	c.lastInput = time.Now()

	var hdr packetHeader

	c.log(logTypeTrace, "Receiving packet len=%v %v", len(p), hex.EncodeToString(p))
	hdrlen, err := decode(&hdr, p)
	if err != nil {
		c.log(logTypeConnection, "Could not decode packetX: %v", hex.EncodeToString(p))
		return wrapE(ErrorInvalidPacket, err)
	}
	assert(int(hdrlen) <= len(p))

	if isLongHeader(&hdr) && hdr.Version != c.version {
		if c.role == RoleServer {
			c.log(logTypeConnection, "%s: Received unsupported version %v, expected %v", c.label(), hdr.Version, c.version)
			err = c.sendVersionNegotiation(hdr.ConnectionID, hdr.PacketNumber, hdr.Version)
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
			if hdr.getHeaderType() != packetTypeVersionNegotiation {
				return fmt.Errorf("Received packet with unexpected version %v", hdr.Version)
			}
		}
	}

	typ := hdr.getHeaderType()
	c.log(logTypeFlowControl, "EKR: Received packet %x len=%d", hdr.PacketNumber, len(p))
	c.log(logTypeConnection, "Packet header %v, %d", hdr, typ)

	if typ == packetTypeVersionNegotiation {
		return c.processVersionNegotiation(&hdr, p[hdrlen:])
	}

	if c.state == StateWaitClientInitial {
		if typ != packetTypeClientInitial {
			c.log(logTypeConnection, "Received unexpected packet before client initial")
			return nil
		}
		// TODO(ekr@rtfm.com): This will result in connection ID flap if we
		// receive a new connection from the same tuple with a different conn ID.
		c.clientConnId = hdr.ConnectionID
		err := c.setupAeadMasking()
		if err != nil {
			return err
		}
	}

	aead := c.readClear.aead
	if hdr.isProtected() {
		if c.readProtected == nil {
			c.log(logTypeConnection, "Received protected data before crypto state is ready")
			return nil
		}
		aead = c.readProtected.aead
	}

	// TODO(ekr@rtfm.com): this dup detection doesn't work right if you
	// get a cleartext packet that has the same PN as a ciphertext or vice versa.
	// Need to fix.
	c.log(logTypeConnection, "%s: Received (unverified) packet with PN=%x PT=%v",
		c.label(), hdr.PacketNumber, hdr.getHeaderType())

	packetNumber := hdr.PacketNumber
	if c.recvd.initialized() {
		packetNumber = c.expandPacketNumber(hdr.PacketNumber, int(hdr.PacketNumber__length()))
		c.log(logTypeConnection, "Reconstructed packet number %x", packetNumber)
	}

	if c.recvd.initialized() && !c.recvd.packetNotReceived(packetNumber) {
		c.log(logTypeConnection, "Discarding duplicate packet %x", packetNumber)
		return nonFatalError(fmt.Sprintf("Duplicate packet id %x", packetNumber))
	}

	payload, err := aead.Open(nil, c.packetNonce(packetNumber), p[hdrlen:], p[:hdrlen])
	if err != nil {
		c.log(logTypeConnection, "Could not unprotect packet")
		c.log(logTypeTrace, "Packet %h", p)
		return wrapE(ErrorInvalidPacket, err)
	}

	// Now that we know it's valid, process stateless retry.
	if typ == packetTypeServerStatelessRetry {
		return c.processStatelessRetry(&hdr, payload)
	}

	if !c.recvd.initialized() {
		c.recvd.init(packetNumber)
	}
	// TODO(ekr@rtfm.com): Reject unprotected packets once we are established.

	// We have now verified that this is a valid packet, so mark
	// it received.
	c.logPacket("Received", &hdr, packetNumber, payload)

	naf := true
	switch typ {
	case packetTypeClientInitial:
		err = c.processClientInitial(&hdr, payload)
	case packetTypeServerCleartext, packetTypeClientCleartext:
		err = c.processCleartext(&hdr, payload, &naf)
	case packetType1RTTProtectedPhase0, packetType1RTTProtectedPhase1:
		err = c.processUnprotected(&hdr, packetNumber, payload, &naf)
	default:
		c.log(logTypeConnection, "Unsupported packet type %v", typ)
		err = internalError("Unsupported packet type %v", typ)
	}
	c.recvd.packetSetReceived(packetNumber, hdr.isProtected(), naf)

	// TODO(ekr@rtfm.com): Check for more on stream 0, but we need to properly handle
	// encrypted NST.

	// Now flush our output buffers.
	_, err = c.sendQueued(true)
	if err != nil {
		return err
	}

	return err
}

func (c *Connection) processClientInitial(hdr *packetHeader, payload []byte) error {
	c.log(logTypeHandshake, "Handling client initial packet")

	// Directly parse the ClientInitial rather than inserting it into
	// the stream processor.
	var sf streamFrame

	// Strip off any initial leading bytes.
	i := int(0)
	var b byte

	for i, b = range payload {
		if b != 0 {
			break
		}
	}
	payload = payload[i:]

	n, err := decode(&sf, payload)
	if err != nil {
		c.log(logTypeConnection, "Failure decoding initial stream frame in ClientInitial")
		return err
	}

	if sf.StreamId != 0 {
		return nonFatalError("Received ClientInitial with stream id != 0")
	}

	if sf.Offset != 0 {
		return nonFatalError("Received ClientInitial with offset != 0")
	}

	if c.state != StateWaitClientInitial {
		if uint64(len(sf.Data)) > c.streams[0].recv.offset {
			return nonFatalError("Received second ClientInitial which seems to be too long, offset=%v len=%v", c.streams[0].recv.offset, n)
		}
		return nil
	}

	// TODO(ekr@rtfm.com): check that the length is long enough.
	// TODO(ekr@rtfm.com): check version, etc.
	payload = payload[n:]
	c.log(logTypeTrace, "Expecting %d bytes of padding", len(payload))
	for _, b := range payload {
		if b != 0 {
			return nonFatalError("ClientInitial has non-padding after ClientHello")
		}
	}

	c.logPacket("Received", hdr, hdr.PacketNumber, payload)
	sflt, err := c.tls.handshake(sf.Data)
	if err != nil {
		c.log(logTypeConnection, "TLS connection error: %v", err)
		return err
	}
	c.log(logTypeTrace, "Output of server handshake: %v", hex.EncodeToString(sflt))

	if c.tls.getHsState() == "ServerStateStart" {
		c.log(logTypeConnection, "Sending Stateless Retry")
		// We sent HRR
		sf := newStreamFrame(0, 0, sflt, false)
		err := sf.encode()
		if err != nil {
			return err
		}
		return c.sendPacketRaw(packetTypeServerStatelessRetry, hdr.ConnectionID, hdr.PacketNumber, kQuicVersion, sf.encoded)
	}

	assert(c.tls.getHsState() == "ServerStateWaitFinished")
	c.streams[0].recv.setOffset(uint64(len(sf.Data)))
	c.setTransportParameters()

	err = c.sendOnStream(0, sflt)
	if err != nil {
		return err
	}

	c.setState(StateWaitClientSecondFlight)

	_, err = c.sendQueued(false)
	return err
}

func (c *Connection) processCleartext(hdr *packetHeader, payload []byte, naf *bool) error {
	*naf = false
	c.log(logTypeHandshake, "Reading cleartext in state %v", c.state)
	// TODO(ekr@rtfm.com): Need clearer state checks.
	/*
		We should probably reinstate this once we have encrypted ACKs.

		if c.state != StateWaitServerFirstFlight && c.state != StateWaitClientSecondFlight {
			c.log(logTypeConnection, "Received cleartext packet in inappropriate state. Ignoring")
			return nil
		}*/

	for len(payload) > 0 {
		c.log(logTypeConnection, "%s: payload bytes left %d", c.label(), len(payload))
		n, f, err := decodeFrame(payload)
		if err != nil {
			c.log(logTypeConnection, "Couldn't decode frame %v", err)
			return wrapE(ErrorInvalidPacket, err)
		}
		c.log(logTypeHandshake, "Frame type %v", f.f.getType())

		payload = payload[n:]
		nonAck := true
		switch inner := f.f.(type) {
		case *paddingFrame:
			// Skip.

		case *maxStreamDataFrame:
			if inner.StreamId != 0 {
				return ErrorProtocolViolation
			}
			err := c.streams[0].processMaxStreamData(inner.MaximumStreamData)
			if err != nil {
				return err
			}

		case *streamFrame:
			// If this is duplicate data and if so early abort.
			if inner.Offset+uint64(len(inner.Data)) <= c.streams[0].recv.offset {
				continue
			}

			// This is fresh data so sanity check.
			if c.role == RoleClient {
				if c.state != StateWaitServerFirstFlight {
					// TODO(ekr@rtfm.com): Not clear what to do here. It's
					// clearly a protocol error, but also allows on-path
					// connection termination, so ust ignore the rest of the
					// packet.
					c.log(logTypeConnection, "Received ServerClearText after handshake finished")
					return nil
				}
				// This is the first packet from the server, so.
				//
				// 1. Remove the clientInitial packet.
				// 2. Set the outgoing stream offset accordingly
				// 3. Remember the connection ID
				if len(c.clientInitial) > 0 {
					c.streams[0].send.setOffset(uint64(len(c.clientInitial)))
					c.clientInitial = nil
					c.serverConnId = hdr.ConnectionID
				}
			} else {
				if c.state != StateWaitClientSecondFlight {
					// TODO(ekr@rtfm.com): Not clear what to do here. It's
					// clearly a protocol error, but also allows on-path
					// connection termination, so ust ignore the rest of the
					// packet.
					c.log(logTypeConnection, "Received ClientClearText after handshake finished")
					return nil
				}
			}

			if inner.StreamId != 0 {
				return nonFatalError("Received cleartext with stream id != 0")
			}

			err = c.newFrameData(c.streams[0], inner)
			if err != nil {
				return err
			}
			available := c.streams[0].readAll()
			// c.issueStreamCredit(c.streams[0], len(available))
			out, err := c.tls.handshake(available)
			if err != nil {
				return err
			}

			if c.tls.finished {
				err = c.handshakeComplete()
				if err != nil {
					return err
				}
				if c.role == RoleClient {
					// We did this on the server already.
					c.setTransportParameters()
				}
			}

			if len(out) > 0 {
				c.sendOnStream(0, out)
				if err != nil {
					return err
				}
				assert(c.tls.finished)
			}

		case *ackFrame:
			c.log(logTypeAck, "Received ACK, first range=%x-%x", inner.LargestAcknowledged-inner.AckBlockLength, inner.LargestAcknowledged)

			err = c.processAckFrame(inner, false)
			if err != nil {
				return err
			}
			nonAck = false
		case *connectionCloseFrame:
			c.log(logTypeConnection, "Received frame close")
			c.setState(StateClosed)
			return fatalError("Connection closed")

		default:
			c.log(logTypeConnection, "Received unexpected frame type")
			return fatalError("Unexpected frame type: %v", f.f.getType())
		}
		if nonAck {
			*naf = true
		}
	}

	return nil
}

func (c *Connection) sendVersionNegotiation(connId ConnectionId, pn uint64, version VersionNumber) error {
	p := newVersionNegotiationPacket([]VersionNumber{
		c.version,
		kQuicGreaseVersion1,
	})
	b, err := encode(p)
	if err != nil {
		return err
	}

	return c.sendSpecialClearPacket(packetTypeVersionNegotiation, connId, pn, version, b)
}

func (c *Connection) processVersionNegotiation(hdr *packetHeader, payload []byte) error {
	c.log(logTypeConnection, "%s: Processing version negotiation packet", c.label())
	if c.recvd.initialized() {
		c.log(logTypeConnection, "%s: Ignoring version negotiation after received another packet", c.label())
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
	c.log(logTypeConnection, "%s: Processing stateless retry packet %s", c.label(), dumpPacket(payload))
	if c.recvd.initialized() {
		c.log(logTypeConnection, "%s: Ignoring stateless retry after received another packet", c.label())
	}

	// Directly parse the Stateless Retry rather than inserting it into
	// the stream processor.
	var sf streamFrame

	n, err := decode(&sf, payload)
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
	assert(c.tls.getHsState() == "ClientStateWaitSH")

	// Pass this data to the TLS connection, which gets us another CH which
	// we insert in ClientInitial
	cflt, err := c.tls.handshake(sf.Data)
	if err != nil {
		c.log(logTypeConnection, "TLS connection error: %v", err)
		return err
	}
	c.log(logTypeTrace, "Output of client handshake: %v", hex.EncodeToString(cflt))

	c.clientInitial = cflt
	return c.sendClientInitial()
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

func (c *Connection) processUnprotected(hdr *packetHeader, packetNumber uint64, payload []byte, naf *bool) error {
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
			c.log(logTypeConnection, "Received ACK, first range=%v-%v", inner.LargestAcknowledged-inner.AckBlockLength, inner.LargestAcknowledged)
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

	if s.newFrameData(inner.Offset, inner.hasFin(), inner.Data) && s.id > 0 &&
		c.handler != nil {
		c.handler.StreamReadable(s)
	}

	remaining := s.recv.maxStreamData - s.recv.lastReceivedByte()
	c.log(logTypeFlowControl, "Stream %d has %d bytes of credit remaining, last byte received was", s.Id(), remaining, s.recv.lastReceivedByte())
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
	end := f.LargestAcknowledged
	start := end - f.AckBlockLength

	// Process the First ACK Block
	c.log(logTypeAck, "%s: processing ACK range %x-%x", c.label(), start, end)
	c.processAckRange(start, end, protected)

	// Process aditional ACK Blocks
	last := start
	rawAckBlocks := f.AckBlockSection
	for i := uint8(0); i < f.NumBlocks; i++ {
		var decoded ackBlock
		bytesread, err := decode(&decoded, rawAckBlocks)
		if err != nil {
			return err
		}
		rawAckBlocks = rawAckBlocks[bytesread:]

		end = last - uint64(decoded.Gap) - 1
		start = end - decoded.Length + 1

		// This happens if a gap is larger than 255
		if decoded.Length == 0 {
			last -= uint64(decoded.Gap)
			c.log(logTypeAck, "%s: encountered empty ACK block", c.label())
			continue
		}

		last = start
		c.log(logTypeAck, "%s: processing ACK range %x-%x", c.label(), start, end)
		c.processAckRange(start, end, protected)
	}
	// TODO(ekr@rtfm.com): Process the ACK timestamps.
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
	if c.role == RoleClient && (c.state == StateInit ||
		c.state == StateWaitServerFirstFlight) {
		err := c.sendClientInitial()
		return 1, err
	}

	n, err := c.sendQueued(false)
	return n, c.handleError(err)
}

func (c *Connection) setTransportParameters() {
	// TODO(ekr@rtfm.com): Process the others..
	_ = c.streams[0].processMaxStreamData(uint64(c.tpHandler.peerParams.maxStreamsData))
}

func (c *Connection) setupAeadMasking() (err error) {
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
	connId := encodeArgs(c.clientConnId)
	c.writeClear, err = newCryptoStateFromSecret(connId, sendLabel, &params)
	if err != nil {
		return
	}
	c.readClear, err = newCryptoStateFromSecret(connId, recvLabel, &params)
	if err != nil {
		return
	}

	return nil
}

// Called when the handshake is complete.
func (c *Connection) handshakeComplete() (err error) {
	var sendLabel, recvLabel string
	if c.role == RoleClient {
		sendLabel = clientPpSecretLabel
		recvLabel = serverPpSecretLabel
	} else {
		sendLabel = serverPpSecretLabel
		recvLabel = clientPpSecretLabel
	}

	c.writeProtected, err = newCryptoStateFromTls(c.tls, sendLabel)
	if err != nil {
		return
	}
	c.readProtected, err = newCryptoStateFromTls(c.tls, recvLabel)
	if err != nil {
		return
	}
	c.setState(StateEstablished)

	return nil
}

func (c *Connection) packetNonce(pn uint64) []byte {
	return encodeArgs(pn)
}

// Create a stream on a given connection. Returns the created
// stream.
func (c *Connection) CreateStream() *Stream {
	nextStream := c.maxStream + 1

	// Client opens odd streams
	if c.role == RoleClient {
		if (nextStream & 1) == 0 {
			nextStream++
		}
	} else {
		if (nextStream & 1) == 1 {
			nextStream++
		}
	}

	s, _, _ := c.ensureStream(nextStream, false)
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
	c.sendPacket(packetType1RTTProtectedPhase0, []frame{f})
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
	if e == nil {
		return nil
	}

	if !isFatalError(e) {
		return e
	}

	// Connection has failed.
	logf(logTypeConnection, "%v: failed with Error=%v", c.label(), e.Error())
	c.setState(StateError)

	return e
}

func (c *Connection) logPacket(dir string, hdr *packetHeader, pn uint64, payload []byte) {
	l := fmt.Sprintf("Packet %s: PN=%x hdr[%s]: %s", dir, pn, hdr.String(), dumpPacket(payload))
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
func (c *Connection) expandPacketNumber(pn uint64, size int) uint64 {
	if size == 8 {
		return pn
	}

	expected := c.recvd.maxReceived + 1
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
