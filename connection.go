/*
Package minq is a minimal implementation of QUIC, as documented at
https://quicwg.github.io/. Minq partly implements draft-04.

*/
package minq

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
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
	kMinimumClientInitialLength  = 1252 // draft-ietf-quic-transport S 9.8
	kLongHeaderLength            = 17
	kInitialIntegrityCheckLength = 8    // FNV-1a 64
	kInitialMTU                  = 1252 // 1280 - UDP headers.
)

// The protocol version number.
type VersionNumber uint32

const (
	kQuicDraftVersion   = 5
	kQuicVersion        = VersionNumber(0xff000000 | kQuicDraftVersion)
	kQuicGreaseVersion1 = VersionNumber(0x1a1a1a1a)
	kQuicGreaseVersion2 = VersionNumber(0x2a2a2a2a)
)

const (
	kQuicALPNToken = "hq-05"
)

const (
	kDefaultInitialRtt = uint32(100)
)

// Internal structures indicating ranges to ACK
type ackRange struct {
	lastPacket uint64
	count      uint64
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
	writeClear       cipher.AEAD
	readClear        cipher.AEAD
	writeProtected   *cryptoState
	readProtected    *cryptoState
	nextSendPacket   uint64
	mtu              int
	sstreams         []*SendStream
	rstreams         []*RecvStream
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
		&aeadFNV{},
		&aeadFNV{},
		nil,
		nil,
		uint64(0),
		kInitialMTU,
		nil,
		nil,
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
	} else {
		c.serverConnId = connId
		c.setState(StateWaitClientInitial)
	}
	tmp, err = generateRand64()
	if err != nil {
		return nil
	}
	c.nextSendPacket = tmp & 0x7fffffff

	// Make streams 0
	c.CreateSendStream()
	c.ensureRecvStream(0)

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

	c.log(logTypeConnection, "%s: Connection state %s -> %v", c.label(), stateName(c.state), stateName(state))
	if c.handler != nil {
		c.handler.StateChanged(state)
	}
	c.state = state
}

func stateName(state State) string {
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

func (c *Connection) ensureRecvStream(id uint32) (*RecvStream, bool, error) {
	c.log(logTypeTrace, "Ensuring stream %d exists", id)
	// TODO(ekr@rtfm.com): this is not really done, because we never clean up
	// Resize to fit.
	if uint32(len(c.rstreams)) >= id+1 {
		return c.rstreams[id], false, nil
	}

	// Make all streams up this one.
	i := uint32(len(c.rstreams))
	needed := id - uint32(len(c.rstreams)) + 1
	c.rstreams = append(c.rstreams, make([]*RecvStream, needed)...)
	c.log(logTypeTrace, "Needed=%d", needed)
	for ; i <= id; i++ {
		s := newRecvStream(c, i, uint64(kInitialMaxStreamData))
		c.rstreams[i] = s
		if id != i {
			// Any lower-numbered streams start in open, so set the
			// state and notify.
			s.setState(kStreamStateOpen)
			if c.handler != nil {
				c.handler.NewRecvStream(s)
			}
		}
	}

	return c.rstreams[id], true, nil
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
			 * draft-ietf-quic-transport S 9.8;
			 *
			 * Clients MUST ensure that the first packet in a connection, and any
		         * etransmissions of those octets, has a QUIC packet size of least 1232
			 * octets for an IPv6 packet and 1252 octets for an IPv4 packet.  In the
			 * absence of extensions to the IP header, padding to exactly these
			 * values will result in an IP packet that is 1280 octets. */
	topad := kMinimumClientInitialLength - (kLongHeaderLength + l + kInitialIntegrityCheckLength)
	c.log(logTypeHandshake, "Padding with %d padding frames", topad)

	// Enqueue the frame for transmission.
	queued = append(queued, f)

	c.sstreams[0].setOffset(uint64(len(c.clientInitial)))

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

func (c *Connection) sendPacketRaw(pt uint8, payload []byte) error {
	c.log(logTypeConnection, "Sending packet PT=%v PN=%x: %s", pt, c.nextSendPacket, dumpPacket(payload))
	left := c.mtu

	var connId ConnectionId
	var aead cipher.AEAD
	if c.writeProtected != nil {
		aead = c.writeProtected.aead
	}
	connId = c.serverConnId

	if c.role == RoleClient {
		switch {
		case pt == packetTypeClientInitial:
			aead = c.writeClear
			connId = c.clientConnId
		case pt == packetTypeClientCleartext:
			aead = c.writeClear
		case pt == packetType0RTTProtected:
			connId = c.clientConnId
			aead = nil // This will cause a crash b/c 0-RTT doesn't work yet
		}
	} else {
		if pt == packetTypeServerCleartext || pt == packetTypeVersionNegotiation {
			aead = c.writeClear
		}
	}

	left -= aead.Overhead()

	// For now, just do the long header.
	p := packet{
		packetHeader{
			pt | packetFlagLongHeader,
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
		c.log(logTypeConnection, "Packet =%v %d", f, f.f.getType())
		_, err := f.length()
		if err != nil {
			return err
		}

		c.log(logTypeTrace, "Frame=%v", hex.EncodeToString(f.encoded))

		{
			msd, ok := f.f.(*maxStreamDataFrame)
			if ok {
				c.log(logTypeFlowControl, "PT=%x Sending maxStreamData %v %v", c.nextSendPacket, msd.StreamId, msd.MaximumStreamData)
			}

		}
		payload = append(payload, f.encoded...)
		sent++
	}

	return c.sendPacketRaw(pt, payload)
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

	if c.role == RoleClient {
		switch {
		case pt == packetTypeClientInitial:
			aead = c.writeClear
			connId = c.clientConnId
		case pt == packetTypeClientCleartext:
			aead = c.writeClear
		case pt == packetType0RTTProtected:
			connId = c.clientConnId
			aead = nil // This will cause a crash b/c 0-RTT doesn't work yet
		}
	} else {
		if pt == packetTypeServerCleartext {
			aead = c.writeClear
		}
	}

	left -= aead.Overhead()

	// For now, just do the long header.
	p := packet{
		packetHeader{
			pt | packetFlagLongHeader,
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

func (c *Connection) makeAckFrame(acks ackRanges, maxlength int) (*frame, int, error) {
	maxacks := (maxlength - 16) / 5 // We are using 32-byte values for all the variable-lengths

	if len(acks) > maxacks {
		acks = acks[:maxacks]
	}

	af, err := newAckFrame(acks)
	if err != nil {
		c.log(logTypeConnection, "Couldn't prepare ACK frame %v", err)
		return nil, 0, err
	}

	return af, len(acks), nil
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
func (c *Connection) sendCombinedPacket(pt uint8, frames []frame, acks ackRanges) (int, error) {
	left := c.mtu
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
		frames = append(frames, *af)
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
	left := c.mtu
	frames := make([]frame, 0)
	sent := int(0)
	acks := c.recvd.prepareAckRange(protected, false)
	now := time.Now()
	txAge := time.Duration(c.retransmitTime) * time.Millisecond

	var streams []*SendStream
	var q *[]frame
	if !protected {
		streams = c.sstreams[0:1]
		q = &c.outputClearQ
	} else {
		streams = c.sstreams[1:]
		q = &c.outputProtectedQ
	}

	// 1. Output all the stream frames that are now permitted by stream flow control
	//
	for _, s := range streams {
		chunks, _ := s.outputWritable()
		for _, ch := range chunks {
			sf := newStreamFrame(s.id, ch.offset, ch.data, ch.last)
			if s.isRelated {
				sf.f.(*streamFrame).setRelated(s.related)
			}
			c.queueFrame(q, sf)
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
			asent, err := c.sendCombinedPacket(pt, frames, acks)
			if err != nil {
				return 0, err
			}
			sent++

			acks = acks[asent:]
			frames = make([]frame, 0)
			left = c.mtu
		}

		frames = append(frames, *f)
		left -= l
		// Record that we send this chunk in the current
		f.pns = append(f.pns, c.nextSendPacket)
		sf, ok := f.f.(*streamFrame)
		if ok && sf.hasFin() {
			c.sstreams[sf.StreamId].close()
		}
	}

	// Send the remainder, plus any ACKs that are left.
	c.log(logTypeConnection, "%s: Remainder to send? sent=%v frames=%v acks=%v bareAcks=%v",
		c.label(), sent, len(frames), len(acks), bareAcks)
	if len(frames) > 0 || (len(acks) > 0 && bareAcks) {
		// TODO(ekr@rtfm.com): this may skip acks if there isn't
		// room, but hopefully we eventually catch up.
		_, err := c.sendCombinedPacket(pt, frames, acks)
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
	for _, s := range c.sstreams {
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
		c.log(logTypeConnection, "Could not decode packet")
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
	c.log(logTypeConnection, "Packet header %v, %d", hdr, typ)

	// Process messages from the server that don't set up the connection
	// first.
	switch typ {
	case packetTypeVersionNegotiation:
		return c.processVersionNegotiation(&hdr, p[hdrlen:])
	case packetTypeServerStatelessRetry:
		c.log(logTypeConnection, "Unsupported packet type %v", typ)
		return fmt.Errorf("Unsupported packet type %v", typ)
	}

	aead := c.readClear
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

	packetNumber := c.expandPacketNumber(hdr.PacketNumber, int(hdr.PacketNumber__length()))
	c.log(logTypeConnection, "Reconstructed packet number %x", packetNumber)

	if c.recvd.initialized() && !c.recvd.packetNotReceived(packetNumber) {
		c.log(logTypeConnection, "Discarding duplicate packet %x", packetNumber)
		return nonFatalError("Duplicate packet")
	}

	payload, err := aead.Open(nil, c.packetNonce(packetNumber), p[hdrlen:], p[:hdrlen])
	if err != nil {
		c.log(logTypeConnection, "Could not unprotect packet")
		c.log(logTypeTrace, "Packet %h", p)
		return wrapE(ErrorInvalidPacket, err)
	}

	if !c.recvd.initialized() {
		c.recvd.init(packetNumber)
	}
	// TODO(ekr@rtfm.com): Reject unprotected packets once we are established.

	// We have now verified that this is a valid packet, so mark
	// it received.

	c.log(logTypeConnection, "Processing packet PT=%v PN=%x: %s", hdr.Type, hdr.PacketNumber, dumpPacket(payload))
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
		if uint64(len(sf.Data)) > c.rstreams[0].offset {
			return nonFatalError("Received second ClientInitial which seems to be too long, offset=%v len=%v", c.rstreams[0].offset, n)
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

	c.rstreams[0].setOffset(uint64(len(sf.Data)))
	sflt, err := c.tls.handshake(sf.Data)
	if err != nil {
		c.log(logTypeConnection, "TLS connection error: %v", err)
		return err
	}

	c.log(logTypeTrace, "Output of server handshake: %v", hex.EncodeToString(sflt))

	c.setTransportParameters()

	err = c.sstreams[0].write(sflt)
	if err != nil {
		return err
	}

	c.setState(StateWaitClientSecondFlight)

	_, err = c.sendQueued(false)
	return err
}

func (c *Connection) processCleartext(hdr *packetHeader, payload []byte, naf *bool) error {
	*naf = false
	c.log(logTypeHandshake, "Reading cleartext in state %s", stateName(c.state))
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
			err := c.sstreams[0].processMaxStreamData(inner.MaximumStreamData)
			if err != nil {
				return err
			}

		case *streamFrame:
			// If this is duplicate data and if so early abort.
			if inner.Offset+uint64(len(inner.Data)) <= c.rstreams[0].offset {
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

			err = c.newFrameData(c.rstreams[0], inner)
			if err != nil {
				return err
			}
			available := c.rstreams[0].readAll()
			c.issueStreamCredit(c.rstreams[0], len(available))
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
				err := c.sstreams[0].write(out)
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

func (c *Connection) issueStreamCredit(s *RecvStream, credit int) error {
	max := ^uint64(0)

	// Figure out how much credit to issue.
	if max-s.maxStreamData > uint64(credit) {
		max = s.maxStreamData + uint64(credit)
	}
	s.maxStreamData = max

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
			return false
		}
		return inner.StreamId == s.Id()
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
			s, notifyCreated, err := c.ensureRecvStream(inner.StreamId)
			if err != nil {
				return err
			}

			// TODO(ekr@rtfm.com): What about close on sending streams?
			s.close()
			if notifyCreated && c.handler != nil {
				c.handler.NewRecvStream(s)
			}
		case *connectionCloseFrame:
			c.setState(StateClosed)

		case *maxStreamDataFrame:
			s := c.GetSendStream(inner.StreamId)
			if s == nil {
				return ErrorProtocolViolation
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
			s, notifyCreated, err := c.ensureRecvStream(inner.StreamId)
			if err != nil {
				return err
			}
			if notifyCreated && c.handler != nil {
				s.setState(kStreamStateOpen)
				c.handler.NewRecvStream(s)
			}

		case *streamFrame:
			c.log(logTypeTrace, "Received on stream %v %x", inner.StreamId, inner.Data)
			relatedId, related := inner.isRelated()
			var relatedStream *SendStream
			if related {
				// Check to see if the related stream is real
				relatedStream = c.GetSendStream(relatedId)
				if relatedStream == nil {
					c.log(logTypeConnection, "Packet claims to be related to nonexistent stream %d", relatedId)
					return ErrorInvalidRelatedStream
				}
			}
			s, notifyCreated, err := c.ensureRecvStream(inner.StreamId)
			if err != nil {
				return err
			}
			// TODO(ekr@rtfm.com): Check for related consistency.
			if related {
				s.isRelated = true
				s.related = relatedId
			}
			if notifyCreated && c.handler != nil {
				c.log(logTypeTrace, "Notifying of stream creation")
				s.setState(kStreamStateOpen)
				c.handler.NewRecvStream(s)
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

func (c *Connection) newFrameData(s *RecvStream, inner *streamFrame) error {
	c.log(logTypeConnection, "New frame data %v", *inner)
	if s.maxStreamData-inner.Offset < uint64(len(inner.Data)) {
		return ErrorFrameFormatError
	}

	if s.newFrameData(inner.Offset, inner.hasFin(), inner.Data) && s.id > 0 &&
		c.handler != nil {
		c.handler.StreamReadable(s)
	}

	remaining := s.maxStreamData - s.lastReceivedByte()
	c.log(logTypeFlowControl, "Stream %d has %d bytes of credit remaining, last byte received was", s.Id(), remaining, s.lastReceivedByte())
	if remaining < uint64(kInitialMaxStreamData) {
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

func (c *Connection) processAckFrame(f *ackFrame, protected bool) error {
	end := f.LargestAcknowledged
	start := end - f.AckBlockLength

	// Go through all the ACK blocks and process everything.
	for {
		c.log(logTypeAck, "%s: processing ACK range %x-%x", c.label(), start, end)
		// Unusual loop structure to avoid weirdness at 2^64-1
		pn := start
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

		// TODO(ekr@rtfm.com): Process subsequent ACK blocks.
		break
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
	_ = c.sstreams[0].processMaxStreamData(uint64(c.tpHandler.peerParams.maxStreamsData))
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

	c.writeProtected, err = newCryptoState(c.tls, sendLabel)
	if err != nil {
		return
	}
	c.readProtected, err = newCryptoState(c.tls, recvLabel)
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
func (c *Connection) createSendStream(related *RecvStream) *SendStream {
	nextStream := uint32(len(c.sstreams))

	var initialMax uint64
	if c.tpHandler.peerParams != nil {
		initialMax = uint64(c.tpHandler.peerParams.maxStreamsData)
	} else {
		assert(len(c.sstreams) == 0)
		initialMax = 1280
	}

	relatedId := uint32(0)
	if related != nil {
		relatedId = related.id
	}
	s := newSendStream(c, nextStream, initialMax, relatedId)
	c.sstreams = append(c.sstreams, s)
	s.setState(kStreamStateOpen)
	return s
}

func (c *Connection) CreateSendStream() *SendStream {
	return c.createSendStream(nil)
}

func (c *Connection) CreateRelatedSendStream(related *RecvStream) *SendStream {
	return c.createSendStream(related)
}

// Get the stream with stream id |id|. Returns nil if no such
// stream exists.
func (c *Connection) GetSendStream(id uint32) *SendStream {
	iid := int(id)

	if iid >= len(c.sstreams) {
		return nil
	}

	return c.sstreams[iid]
}

func (c *Connection) GetRecvStream(id uint32) *RecvStream {
	iid := int(id)

	if iid >= len(c.rstreams) {
		return nil
	}

	return c.rstreams[iid]
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
