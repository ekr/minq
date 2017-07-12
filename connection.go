/*

Package minq is a minimal implementation of QUIC, as documented at
https://quicwg.github.io/. Minq partly implements draft-04.

*/
package minq

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
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
	kQuicVersion = VersionNumber(0xff000004)
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

// Internal structure indicating ranges to ACK
type ackRange struct {
	lastPacket uint64
	count      uint64
}

// Internal structure indicating packets we have
// received
type recvdPacketsInt struct {
	r   []bool
	min uint64
}

type recvdPackets struct {
	clear  recvdPacketsInt
	all    recvdPacketsInt
	acked2 recvdPacketsInt // Acks that have been ACKed.
}

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
	handler        ConnectionHandler
	role           uint8
	state          State
	version        VersionNumber
	clientConnId   ConnectionId
	serverConnId   ConnectionId
	transport      Transport
	tls            *tlsConn
	writeClear     cipher.AEAD
	readClear      cipher.AEAD
	writeProtected *cryptoState
	readProtected  *cryptoState
	nextSendPacket uint64
	mtu            int
	streams        []Stream
	maxStream      uint32
	clientInitial  []byte
	recvd          recvdPackets
	sentAcks       map[uint64][]ackRange
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
		0,
		nil,
		newRecvdPackets(),
		make(map[uint64][]ackRange, 0),
	}

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
	c.ensureStream(0)
	return &c
}

func (c *Connection) zeroRttAllowed() bool {
	// Placeholder
	return false
}

func (c *Connection) expandPacketNumber(pn uint64) uint64 {
	// Placeholder
	return pn
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

	logf(logTypeConnection, "%s: Connection state %s -> %v", c.label(), stateName(c.state), stateName(state))
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
	default:
		return "Unknown state"
	}
}

func (c *Connection) ensureStream(id uint32) *Stream {
	// TODO(ekr@rtfm.com): this is not really done, because we never clean up
	// TODO(ekr@rtfm.com): Only create streams with the same parity.
	for i := uint32(len(c.streams)); i <= id; i++ {
		c.streams = append(c.streams, Stream{id: id, c: c})
	}
	return &c.streams[id]
}

func (c *Connection) sendClientInitial() error {
	queued := make([]frame, 0)
	var err error

	logf(logTypeHandshake, "Sending client initial packet")
	if c.clientInitial == nil {
		c.clientInitial, err = c.tls.handshake(nil)
		if err != nil {
			return err
		}
	}

	f := newStreamFrame(0, 0, c.clientInitial)
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
	logf(logTypeHandshake, "Padding with %d padding frames", topad)

	// Enqueue the frame for transmission.
	queued = append(queued, f)

	c.streams[0].writeOffset = uint64(len(c.clientInitial))

	for i := 0; i < topad; i++ {
		queued = append(queued, newPaddingFrame(0))
	}

	c.setState(StateWaitServerFirstFlight)

	return c.sendPacket(packetTypeClientInitial, queued)
}

func (c *Connection) sendPacket(pt uint8, tosend []frame) error {
	logf(logTypeConnection, "Sending packet of type %v. %v frames", pt, len(tosend))
	logf(logTypeTrace, "Sending packet of type %v. %v frames", pt, len(tosend))
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

		logf(logTypeTrace, "Frame=%v", hex.EncodeToString(f.encoded))
		p.payload = append(p.payload, f.encoded...)
		sent++
	}

	protected := aead.Seal(nil, c.packetNonce(p.PacketNumber), p.payload, hdr)
	packet := append(hdr, protected...)

	logf(logTypeTrace, "Sending packet len=%d, len=%v", len(packet), hex.EncodeToString(packet))
	c.transport.Send(packet)

	return nil
}

func (c *Connection) sendOnStream(streamId uint32, data []byte) error {
	logf(logTypeConnection, "%v: sending %v bytes on stream %v", c.label(), len(data), streamId)
	stream := c.ensureStream(streamId)

	for len(data) > 0 {
		tocpy := 1024
		if tocpy > len(data) {
			tocpy = len(data)
		}
		stream.send(data[:tocpy])

		data = data[tocpy:]
	}

	return nil
}

func (c *Connection) makeAckFrame(acks []ackRange, maxlength int) (*frame, int, error) {
	maxacks := (maxlength - 16) / 5 // We are using 32-byte values for all the variable-lengths

	if len(acks) > maxacks {
		acks = acks[:maxacks]
	}

	af, err := newAckFrame(acks)
	if err != nil {
		logf(logTypeConnection, "Couldn't prepare ACK frame %v", err)
		return nil, 0, err
	}

	return af, len(acks), nil
}

func (c *Connection) sendQueued() (int, error) {
	if c.state == StateInit || c.state == StateWaitClientInitial {
		return 0, nil
	}

	sent := int(0)

	// First send stream 0 if needed.
	pt := uint8(packetTypeClientCleartext)
	if c.role == RoleServer {
		pt = packetTypeServerCleartext
	}

	s, err := c.sendQueuedStreams(pt, c.streams[0:1], false)
	if err != nil {
		return sent, err
	}
	sent += s

	// Now send other streams if we are in encrypted mode.
	// TODO(ekr@rtfm.com): In the special case where there
	// is no data and the ACK is a duplicate, just don't send
	// it.
	if c.state == StateEstablished {
		s, err := c.sendQueuedStreams(packetType1RTTProtectedPhase0, c.streams[1:], true)
		if err != nil {
			return sent, err
		}
		sent += s
	}

	return sent, nil
}

// Send a packet of stream frames, plus whatever acks fit.
func (c *Connection) sendStreamPacket(pt uint8, frames []frame, acks []ackRange) (int, error) {
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

// Send all the queued data on a set of streams with packet type |pt|
func (c *Connection) sendQueuedStreams(pt uint8, streams []Stream, protected bool) (int, error) {
	left := c.mtu
	frames := make([]frame, 0)
	sent := int(0)
	acks := c.recvd.prepareAckRange(protected)

	for _, str := range streams {
		for i, chunk := range str.out {
			logf(logTypeConnection, "Sending chunk of offset=%v len %v", chunk.offset, len(chunk.data))
			f := newStreamFrame(str.id, chunk.offset, chunk.data)
			l, err := f.length()
			if err != nil {
				return 0, err
			}

			if left < l {
				asent, err := c.sendStreamPacket(pt, frames, acks)
				if err != nil {
					return 0, err
				}
				sent++

				acks = acks[asent:]
				frames = make([]frame, 0)
				left = c.mtu
			}

			frames = append(frames, f)
			left -= l
			// Record that we send this chunk in the current
			str.out[i].pns = append(str.out[i].pns, c.nextSendPacket)
		}
	}

	// Send the remainder.
	if len(acks) > 0 || len(frames) > 0 {
		_, err := c.sendStreamPacket(pt, frames, acks)
		if err != nil {
			return 0, err
		}

		sent++
	}

	return sent, nil
}

// Walk through all the streams and see how many bytes are outstanding.
// Right now this is very expensive.

func (c *Connection) outstandingQueuedBytes() (n int) {
	for _, s := range c.streams {
		n += s.outstandingQueuedBytes()
	}

	return
}

// Provide a packet to the connection.
//
// TODO(ekr@rtfm.com): when is error returned?
func (c *Connection) Input(p []byte) error {
	if c.isClosed() {
		return fmt.Errorf("Connection is closed")
	}

	var hdr packetHeader

	logf(logTypeTrace, "Receiving packet len=%v %v", len(p), hex.EncodeToString(p))
	hdrlen, err := decode(&hdr, p)
	if err != nil {
		logf(logTypeConnection, "Could not decode packet")
		return err
	}
	assert(int(hdrlen) <= len(p))

	aead := c.readClear
	if hdr.isProtected() {
		if c.readProtected == nil {
			logf(logTypeConnection, "Received protected data before crypto state is ready")
			return nil
		}
		aead = c.readProtected.aead
	}

	// TODO(ekr@rtfm.com): Reconstruct the packet number
	// TODO(ekr@rtfm.com): this dup detection doesn't work right if you
	// get a cleartext packet that has the same PN as a ciphertext or vice versa.
	// Need to fix.
	logf(logTypeConnection, "Received (unverified) packet with PN=%v", hdr.PacketNumber)
	if c.recvd.initialized() && !c.recvd.packetNotReceived(hdr.PacketNumber) {
		logf(logTypeConnection, "Discarding duplicate packet")
		return fmt.Errorf("Duplicate packet")
	}

	payload, err := aead.Open(nil, c.packetNonce(hdr.PacketNumber), p[hdrlen:], p[:hdrlen])
	if err != nil {
		logf(logTypeConnection, "Could not unprotect packet")
		return err
	}

	if !c.recvd.initialized() {
		c.recvd.init(hdr.PacketNumber)
	}
	// TODO(ekr@rtfm.com): Reject unprotected packets once we are established.

	// We have now verified that this is a valid packet, so mark
	// it received.

	c.recvd.packetSetReceived(hdr.PacketNumber, hdr.isProtected())
	typ := hdr.getHeaderType()
	if !isLongHeader(&hdr) {
		// TODO(ekr@rtfm.com): We are using this for both types.
		typ = packetType1RTTProtectedPhase0
	}
	logf(logTypeConnection, "Packet header %v, %d", hdr, typ)
	switch typ {
	case packetTypeClientInitial:
		err = c.processClientInitial(&hdr, payload)
	case packetTypeServerCleartext, packetTypeClientCleartext:
		err = c.processCleartext(&hdr, payload)
	case packetType1RTTProtectedPhase0, packetType1RTTProtectedPhase1:
		err = c.processUnprotected(&hdr, payload)
	default:
		logf(logTypeConnection, "Unsupported packet type %v", typ)
		err = fmt.Errorf("Unsupported packet type %v", typ)
	}

	return err
}

func (c *Connection) processClientInitial(hdr *packetHeader, payload []byte) error {
	logf(logTypeHandshake, "Handling client initial packet")

	if c.state != StateWaitClientInitial {
		// TODO(ekr@rtfm.com): Distinguish from retransmission.
		return fmt.Errorf("Received repeat Client Initial")
	}

	// Directly parse the ClientInitial rather than inserting it into
	// the stream processor.
	var sf streamFrame

	n, err := decode(&sf, payload)
	if err != nil {
		logf(logTypeConnection, "Failure decoding initial stream frame in ClientInitial")
		return err
	}

	if sf.StreamId != 0 {
		return fmt.Errorf("Received ClientInitial with stream id != 0")
	}

	if sf.Offset != 0 {
		return fmt.Errorf("Received ClientInitial with offset != 0")
	}

	// TODO(ekr@rtfm.com): check that the length is long enough.
	// TODO(ekr@rtfm.com): check version, etc.
	payload = payload[n:]
	logf(logTypeTrace, "Expecting %d bytes of padding", len(payload))
	for _, b := range payload {
		if b != 0 {
			return fmt.Errorf("ClientInitial has non-padding after ClientHello")
		}
	}

	c.streams[0].readOffset = uint64(len(sf.Data))
	sflt, err := c.tls.handshake(sf.Data)
	if err != nil {
		return err
	}

	logf(logTypeTrace, "Output of server handshake: %v", hex.EncodeToString(sflt))

	err = c.sendOnStream(0, sflt)
	if err != nil {
		return err
	}

	c.setState(StateWaitClientSecondFlight)

	_, err = c.sendQueued()
	return err
}

func (c *Connection) processCleartext(hdr *packetHeader, payload []byte) error {
	logf(logTypeHandshake, "Reading cleartext in state %v", c.state)
	// TODO(ekr@rtfm.com): Need clearer state checks.
	/*
		We should probably reinstate this once we have encrypted ACKs.

		if c.state != StateWaitServerFirstFlight && c.state != StateWaitClientSecondFlight {
			logf(logTypeConnection, "Received cleartext packet in inappropriate state. Ignoring")
			return nil
		}*/

	otherThanAck := false
	for len(payload) > 0 {
		logf(logTypeConnection, "%s: payload bytes left %d", c.label(), len(payload))
		n, f, err := decodeFrame(payload)
		if err != nil {
			logf(logTypeConnection, "Couldn't decode frame %v", err)
			return err
		}
		logf(logTypeHandshake, "Frame type %v", f.f.getType())

		payload = payload[n:]
		nonAck := true
		switch inner := f.f.(type) {
		case *streamFrame:
			// If this is duplicate data and if so early abort.
			if inner.Offset+uint64(len(inner.Data)) <= c.streams[0].readOffset {
				continue
			}

			// This is fresh data so sanity check.
			if c.role == RoleClient {
				if c.state != StateWaitServerFirstFlight {
					// TODO(ekr@rtfm.com): Not clear what to do here. It's
					// clearly a protocol error, but also allows on-path
					// connection termination, so ust ignore the rest of the
					// packet.
					logf(logTypeConnection, "Received ServerClearText after handshake finished")
					return nil
				}
				// This is the first packet from the server, so.
				//
				// 1. Remove the clientInitial packet.
				// 2. Set the outgoing stream offset accordingly
				// 3. Remember the connection ID
				if len(c.clientInitial) > 0 {
					c.streams[0].writeOffset = uint64(len(c.clientInitial))
					c.clientInitial = nil
					c.serverConnId = hdr.ConnectionID
				}
			} else {
				if c.state != StateWaitClientSecondFlight {
					// TODO(ekr@rtfm.com): Not clear what to do here. It's
					// clearly a protocol error, but also allows on-path
					// connection termination, so ust ignore the rest of the
					// packet.
					logf(logTypeConnection, "Received ClientClearText after handshake finished")
					return nil
				}
			}

			if inner.StreamId != 0 {
				return fmt.Errorf("Received cleartext with stream id != 0")
			}

			c.streams[0].newFrameData(inner.Offset, inner.Data)
			available := c.streams[0].readAll()
			out, err := c.tls.handshake(available)
			if err != nil {
				return err
			}

			if c.tls.finished {
				err = c.handshakeComplete()
				if err != nil {
					return err
				}
			}

			if len(out) > 0 {
				c.sendOnStream(0, out)
				_, err = c.sendQueued()
				if err != nil {
					return err
				}
				assert(c.tls.finished)
			}

		case *ackFrame:
			logf(logTypeConnection, "Received ACK, first range=%v-%v", inner.LargestAcknowledged-inner.FirstAckBlockLength, inner.LargestAcknowledged)

			err = c.processAckFrame(inner)
			if err != nil {
				return err
			}
			nonAck = false
		case *connectionCloseFrame:
			logf(logTypeConnection, "Received frame close")
			c.setState(StateClosed)

		default:
			logf(logTypeConnection, "Received unexpected frame type")
			fmt.Errorf("Unexpected frame type")
		}
		if nonAck {
			otherThanAck = true
		}
	}

	// If this is just an ACK packet, set it as if it was
	// double-acked so we don't send ACKs for it.
	if !otherThanAck {
		logf(logTypeAck, "Packet just contained ACKs")
		c.recvd.packetSetAcked2(hdr.PacketNumber)
	}

	// TODO(ekr@rtfm.com): Check for more on stream 0, but we need to properly handle
	// encrypted NST.

	return nil
}

func (c *Connection) processUnprotected(hdr *packetHeader, payload []byte) error {
	logf(logTypeHandshake, "Reading unprotected data in state %v", c.state)
	otherThanAck := false
	for len(payload) > 0 {
		logf(logTypeConnection, "%s: payload bytes left %d", c.label(), len(payload))
		n, f, err := decodeFrame(payload)
		if err != nil {
			logf(logTypeConnection, "Couldn't decode frame %v", err)
			return err
		}
		logf(logTypeHandshake, "Frame type %v", f.f.getType())

		payload = payload[n:]
		nonAck := true
		switch inner := f.f.(type) {
		case *streamFrame:
			logf(logTypeConnection, "Received data on stream %v len=%v", inner.StreamId, len(inner.Data))
			logf(logTypeTrace, "Received on stream %v %x", inner.StreamId, inner.Data)

			notifyCreated := false
			s := c.GetStream(inner.StreamId)
			if s == nil {
				notifyCreated = true
			}
			s = c.ensureStream(inner.StreamId)
			if notifyCreated && c.handler != nil {
				c.handler.NewStream(s)
			}
			if s.newFrameData(inner.Offset, inner.Data) && c.handler != nil {
				c.handler.StreamReadable(s)
			}
		case *ackFrame:
			logf(logTypeConnection, "Received ACK, first range=%v-%v", inner.LargestAcknowledged-inner.FirstAckBlockLength, inner.LargestAcknowledged)

			err = c.processAckFrame(inner)
			if err != nil {
				return err
			}
			nonAck = false
		case *connectionCloseFrame:
			logf(logTypeConnection, "Received close frame")
			c.setState(StateClosed)
		default:
			logf(logTypeConnection, "Received unexpected frame type")
		}
		if nonAck {
			otherThanAck = true
		}
	}

	// If this is just an ACK packet, set it as if it was
	// double-acked so we don't send ACKs for it.
	if !otherThanAck {
		logf(logTypeAck, "Packet just contained ACKs")
		c.recvd.packetSetAcked2(hdr.PacketNumber)
	}

	return nil
}

func (c *Connection) processAckFrame(f *ackFrame) error {
	end := f.LargestAcknowledged
	start := end - f.FirstAckBlockLength

	// Go through all the ACK blocks and process everything.
	for {
		logf(logTypeAck, "%s: processing ACK range %v-%v", c.label(), start, end)
		// Unusual loop structure to avoid weirdness at 2^64-1
		pn := start
		for {
			// TODO(ekr@rtfm.com): properly filter for ACKed packets which are in the
			// wrong key phase.
			logf(logTypeConnection, "%s: processing ACK for PN=%v", c.label(), pn)

			// 1. Go through each stream and remove the chunks. This is not
			//    efficient but fine for now. Note, use of array index
			//    rather than the iterator because we want to modify
			//    the stream.
			for i, _ := range c.streams {
				st := &(c.streams[i])
				st.removeAckedChunks(pn)
			}

			// 2. Mark all the packets that were ACKed in this packet as double-acked.
			acks, ok := c.sentAcks[pn]
			if ok {
				for _, a := range acks {
					logf(logTypeAck, "Ack2 for ack range last=%v len=%v", a.lastPacket, a.count)
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

func newRecvdPacketsInt() recvdPacketsInt {
	return recvdPacketsInt{nil, 0}
}

func (p *recvdPacketsInt) initialized() bool {
	return p.r != nil
}

func (p *recvdPacketsInt) init(min uint64) {
	p.min = min
	p.r = make([]bool, 10)
}

func (p *recvdPacketsInt) packetNotReceived(pn uint64) bool {
	if pn < p.min {
		logf(logTypeTrace, "Packet %v < min=%v", pn, p.min)
		return false // We're not sure.
	}

	if pn >= p.min+uint64(len(p.r)) {
		return true // We extend forward as needed.
	}

	return !p.r[pn-p.min]
}

func (p *recvdPacketsInt) packetSetReceived(pn uint64) {
	assert(pn >= p.min)
	logf(logTypeAck, "Setting received for pn=%v min=%v", pn, p.min)
	if pn >= p.min+uint64(len(p.r)) {
		grow := (pn - p.min) - uint64(len(p.r))
		if grow < 10 {
			grow = 10
		}

		logf(logTypeAck, "Growing received packet window by %v", grow)
		p.r = append(p.r, make([]bool, grow)...)
	}
	p.r[pn-p.min] = true
}

func newRecvdPackets() recvdPackets {
	return recvdPackets{
		newRecvdPacketsInt(),
		newRecvdPacketsInt(),
		newRecvdPacketsInt()}
}

func (p *recvdPackets) initialized() bool {
	return p.clear.initialized()
}

func (p *recvdPackets) init(pn uint64) {
	logf(logTypeAck, "Initializing received packet start=%v", pn)
	p.clear.init(pn)
	p.all.init(pn)
	p.acked2.init(pn)
}

func (p *recvdPackets) packetNotReceived(pn uint64) bool {
	return p.clear.packetNotReceived(pn) && p.all.packetNotReceived(pn)
}

func (p *recvdPackets) packetSetReceived(pn uint64, protected bool) {
	logf(logTypeAck, "Setting packet received=%v", pn)
	if !protected {
		p.clear.packetSetReceived(pn)
	}
	p.all.packetSetReceived(pn)
}

func (p *recvdPackets) packetSetAcked2(pn uint64) {
	logf(logTypeAck, "Setting packet acked2=%v", pn)
	p.acked2.packetSetReceived(pn)
}

// Prepare a list of the ACK ranges, starting at the highest
func (p *recvdPackets) prepareAckRange(protected bool) []ackRange {
	var inrange = false
	var last uint64
	var pn uint64
	ps := &p.all
	if !protected {
		ps = &p.clear
	}
	logf(logTypeAck, "Preparing ACK range recvd=%v acked2=%v protected=%v", ps, p.acked2, protected)
	ranges := make([]ackRange, 0)
	for i := len(ps.r) - 1; i >= 0; i-- {
		pn = uint64(i) + ps.min
		needs_ack := ps.r[i] && !p.acked2.r[i]
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
		logf(logTypeTrace, "EKR: appending final range")
		ranges = append(ranges, ackRange{last, last - pn + 1})
	}

	logf(logTypeAck, "%v ACK ranges to send", len(ranges))
	logf(logTypeAck, "ACK ranges = %v", ranges)
	return ranges
}

// Check the connection's timer and process any events whose time has
// expired in the meantime. This includes sending retransmits, etc.
func (c *Connection) CheckTimer() (int, error) {
	// Right now just re-send everything we might need to send.

	// Special case the client's first message.
	if c.role == RoleClient && (c.state == StateInit ||
		c.state == StateWaitServerFirstFlight) {
		err := c.sendClientInitial()
		return 1, err
	}

	return c.sendQueued()
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

	return c.ensureStream(nextStream)
}

// Get the stream with stream id |id|. Returns nil if no such
// stream exists.
func (c *Connection) GetStream(id uint32) *Stream {
	iid := int(id)

	if iid >= len(c.streams) {
		return nil
	}

	return &c.streams[iid]
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

// Close a connection.
func (c *Connection) Close() {
	logf(logTypeConnection, "%v Close()", c.label())
	f := newConnectionCloseFrame(0, "You don't have to go home but you can't stay here")
	c.sendPacket(packetType1RTTProtectedPhase0, []frame{f})
}

func (c *Connection) isClosed() bool {
	return c.state == StateClosed
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
