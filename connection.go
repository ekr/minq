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

type connState uint8

const (
	kStateInit                   = connState(1)
	kStateWaitClientInitial      = connState(2)
	kStateWaitServerFirstFlight  = connState(3)
	kStateWaitClientSecondFlight = connState(4)
	kStateEstablished            = connState(5)
)

const (
	kMinimumClientInitialLength  = 1252 // draft-ietf-quic-transport S 9.8
	kLongHeaderLength            = 17
	kInitialIntegrityCheckLength = 8    // FNV-1a 64
	kInitialMTU                  = 1252 // 1280 - UDP headers.
)

type VersionNumber uint32

const (
	kQuicVersion = VersionNumber(0xff000004)
)

type ConnectionState interface {
	established() bool
	zeroRttAllowed() bool
	expandPacketNumber(pn uint64) uint64
}

// Internal structure indicating ranges to ACK
type ackRange struct {
	lastPacket uint64
	count      uint64
}

// Internal structure indicating packets we have
// received
type recvdPackets struct {
	r   []bool
	min uint64
}

type Connection struct {
	role           uint8
	state          connState
	version        VersionNumber
	clientConnId   connectionId
	serverConnId   connectionId
	transport      Transport
	tls            *TlsConn
	writeClear     cipher.AEAD
	readClear      cipher.AEAD
	writeProtected *cryptoState
	readProtected  *cryptoState
	nextSendPacket uint64
	mtu            int
	streams        []Stream
	maxStream      uint32
	clientInitial  []byte
	recvdClear     recvdPackets
	recvdProtected recvdPackets
}

func NewConnection(trans Transport, role uint8, tls TlsConfig) *Connection {
	c := Connection{
		role,
		kStateInit,
		kQuicVersion,
		0,
		0,
		trans,
		newTlsConn(tls, role),
		&AeadFNV{},
		&AeadFNV{},
		nil,
		nil,
		uint64(0),
		kInitialMTU,
		nil,
		0,
		nil,
		newRecvdPackets(),
		newRecvdPackets(),
	}

	tmp, err := generateRand64()
	if err != nil {
		return nil
	}
	connId := connectionId(tmp)
	if role == RoleClient {
		c.clientConnId = connId
	} else {
		c.serverConnId = connId
		c.setState(kStateWaitClientInitial)
	}
	tmp, err = generateRand64()
	if err != nil {
		return nil
	}
	c.nextSendPacket = tmp & 0xffffffff
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

func (c *Connection) setState(state connState) {
	if c.state == state {
		return
	}

	logf(logTypeConnection, "%s: Connection state %s -> %v", c.label(), stateName(c.state), stateName(state))
	c.state = state
}

func stateName(state connState) string {
	// TODO(ekr@rtfm.com): is there a way to get the name from the
	// const value.
	switch state {
	case kStateInit:
		return "kStateInit"
	case kStateWaitClientInitial:
		return "kStateWaitClientInitial"
	case kStateWaitServerFirstFlight:
		return "kStateWaitServerFirstFlight"
	case kStateWaitClientSecondFlight:
		return "kStateWaitClientSecondFlight"
	case kStateEstablished:
		return "kStateEstablished"
	default:
		return "Unknown state"
	}
}

func (c *Connection) ensureStream(id uint32) *Stream {
	// TODO(ekr@rtfm.com): this is not really done, because we never clean up
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

	c.setState(kStateWaitServerFirstFlight)

	return c.sendPacket(PacketTypeClientInitial, queued)
}

func (c *Connection) sendPacket(pt uint8, tosend []frame) error {
	logf(logTypeConnection, "Sending packet of type %v. %v frames", pt, len(tosend))
	logf(logTypeTrace, "Sending packet of type %v. %v frames", pt, len(tosend))
	left := c.mtu

	var connId connectionId
	var aead cipher.AEAD
	if c.writeProtected != nil {
		aead = c.writeProtected.aead
	}
	connId = c.serverConnId

	if c.role == RoleClient {
		switch {
		case pt == PacketTypeClientInitial:
			aead = c.writeClear
			connId = c.clientConnId
		case pt == PacketTypeClientCleartext:
			aead = c.writeClear
		case pt == PacketType0RTTProtected:
			connId = c.clientConnId
			aead = nil // This will cause a crash b/c 0-RTT doesn't work yet
		}
	} else {
		if pt == PacketTypeServerCleartext {
			aead = c.writeClear
		}
	}

	left -= aead.Overhead()

	// For now, just do the long header.
	p := Packet{
		PacketHeader{
			pt | PacketFlagLongHeader,
			connId,
			c.nextSendPacket,
			c.version,
		},
		nil,
	}
	c.nextSendPacket++

	// Encode the header so we know how long it is.
	// TODO(ekr@rtfm.com): this is gross.
	hdr, err := encode(&p.PacketHeader)
	if err != nil {
		return err
	}
	left -= len(hdr)

	sent := 0

	// TODO(ekr@rtfm.com): Need to filter which frames can be sent in
	// which packet.
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

	protected := aead.Seal(nil, c.packetNonce(true, p.PacketNumber), p.payload, hdr)
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
	if c.state == kStateInit || c.state == kStateWaitClientInitial {
		return 0, nil
	}

	sent := int(0)

	// First send stream 0 if needed.
	pt := uint8(PacketTypeClientCleartext)
	if c.role == RoleServer {
		pt = PacketTypeServerCleartext
	}

	s, err := c.sendQueuedStreams(pt, c.streams[0:1], &c.recvdClear)
	if err != nil {
		return sent, err
	}
	sent += s

	// Now send other streams if we are in encrypted mode.
	if c.state == kStateEstablished {
		s, err := c.sendQueuedStreams(PacketType1RTTProtectedPhase0, c.streams[1:], &c.recvdProtected)
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

	err = c.sendPacket(pt, frames)
	if err != nil {
		return 0, err
	}

	return asent, nil
}

// Send all the queued data on a set of streams with packet type |pt|
func (c *Connection) sendQueuedStreams(pt uint8, streams []Stream, recvd *recvdPackets) (int, error) {
	left := c.mtu
	frames := make([]frame, 0)
	sent := int(0)
	acks := recvd.prepareAckRange()

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

func (c *Connection) Input(p []byte) error {
	var hdr PacketHeader

	logf(logTypeTrace, "Receiving packet len=%v %v", len(p), hex.EncodeToString(p))
	hdrlen, err := decode(&hdr, p)
	if err != nil {
		logf(logTypeConnection, "Could not decode packet")
		return err
	}
	assert(int(hdrlen) <= len(p))

	recvd := &c.recvdClear
	aead := c.readClear
	if hdr.isProtected() {
		if c.readProtected == nil {
			logf(logTypeConnection, "Received protected data before crypto state is ready")
			return nil
		}
		recvd = &c.recvdProtected
		aead = c.readProtected.aead
	}

	// TODO(ekr@rtfm.com): Reconstruct the packet number
	// TODO(ekr@rtfm.com): this dup detection doesn't work right if you
	// get a cleartext packet that has the same PN as a ciphertext or vice versa.
	// Need to fix.
	logf(logTypeConnection, "Received (unverified) packet with PN=%v", hdr.PacketNumber)
	if recvd.initialized() && !recvd.packetNotReceived(hdr.PacketNumber) {
		logf(logTypeConnection, "Discarding duplicate packet")
		return fmt.Errorf("Duplicate packet")
	}

	payload, err := aead.Open(nil, c.packetNonce(false, hdr.PacketNumber), p[hdrlen:], p[:hdrlen])
	if err != nil {
		logf(logTypeConnection, "Could not unprotect packet")
		return err
	}

	if !recvd.initialized() {
		c.recvdClear.init(hdr.PacketNumber)
		c.recvdProtected.init(hdr.PacketNumber) // Ridiculous.
	}
	// TODO(ekr@rtfm.com): Reject unprotected packets once we are established.

	// We have now verified that this is a valid packet, so mark
	// it received.
	recvd.packetSetReceived(hdr.PacketNumber)
	typ := hdr.getHeaderType()
	if !isLongHeader(&hdr) {
		// TODO(ekr@rtfm.com): We are using this for both types.
		typ = PacketType1RTTProtectedPhase0
	}
	logf(logTypeConnection, "Packet header %v, %d", hdr, typ)
	switch typ {
	case PacketTypeClientInitial:
		err = c.processClientInitial(&hdr, payload)
	case PacketTypeServerCleartext, PacketTypeClientCleartext:
		err = c.processCleartext(&hdr, payload)
	case PacketType1RTTProtectedPhase0, PacketType1RTTProtectedPhase1:
		err = c.processUnprotected(&hdr, payload)
	default:
		logf(logTypeConnection, "Unsupported packet type %v", typ)
		err = fmt.Errorf("Unsupported packet type %v", typ)
	}

	return err
}

func (c *Connection) processClientInitial(hdr *PacketHeader, payload []byte) error {
	logf(logTypeHandshake, "Handling client initial packet")

	if c.state != kStateWaitClientInitial {
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

	c.setState(kStateWaitClientSecondFlight)

	_, err = c.sendQueued()
	return err
}

func (c *Connection) processCleartext(hdr *PacketHeader, payload []byte) error {
	logf(logTypeHandshake, "Reading cleartext in state %v", c.state)
	// TODO(ekr@rtfm.com): Need clearer state checks.
	/*
		We should probably reinstate this once we have encrypted ACKs.

		if c.state != kStateWaitServerFirstFlight && c.state != kStateWaitClientSecondFlight {
			logf(logTypeConnection, "Received cleartext packet in inappropriate state. Ignoring")
			return nil
		}*/

	for len(payload) > 0 {
		logf(logTypeConnection, "%s: payload bytes left %d", c.label(), len(payload))
		n, f, err := decodeFrame(payload)
		if err != nil {
			logf(logTypeConnection, "Couldn't decode frame %v", err)
			return err
		}
		logf(logTypeHandshake, "Frame type %v", f.f.getType())

		payload = payload[n:]
		switch inner := f.f.(type) {
		case *streamFrame:
			// If this is duplicate data and if so early abort.
			if inner.Offset+uint64(len(inner.Data)) <= c.streams[0].readOffset {
				continue
			}

			// This is fresh data so sanity check.
			if c.role == RoleClient {
				if c.state != kStateWaitServerFirstFlight {
					return fmt.Errorf("Received ServerClearText after handshake finished")
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
				if c.state != kStateWaitClientSecondFlight {
					return fmt.Errorf("Received ClientClearText after handshake finished")
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

		default:
			logf(logTypeConnection, "Received unexpected frame type")
			fmt.Errorf("Unexpected frame type")
		}
	}

	// TODO(ekr@rtfm.com): Check for more on stream 0, but we need to properly handle
	// encrypted NST.

	return nil
}

func (c *Connection) processUnprotected(hdr *PacketHeader, payload []byte) error {
	logf(logTypeHandshake, "Reading unprotected data in state %v", c.state)
	for len(payload) > 0 {
		logf(logTypeConnection, "%s: payload bytes left %d", c.label(), len(payload))
		n, f, err := decodeFrame(payload)
		if err != nil {
			logf(logTypeConnection, "Couldn't decode frame %v", err)
			return err
		}
		logf(logTypeHandshake, "Frame type %v", f.f.getType())

		payload = payload[n:]
		switch inner := f.f.(type) {
		case *streamFrame:
			logf(logTypeConnection, "Received data on stream %v len=%v", inner.StreamId, len(inner.Data))
			logf(logTypeTrace, "Received on stream %v %x", inner.StreamId, inner.Data)
			s := c.ensureStream(inner.StreamId)
			s.newFrameData(inner.Offset, inner.Data)
		case *ackFrame:
			logf(logTypeConnection, "Received ACK, first range=%v-%v", inner.LargestAcknowledged-inner.FirstAckBlockLength, inner.LargestAcknowledged)

			err = c.processAckFrame(inner)
			if err != nil {
				return err
			}

		default:
			logf(logTypeConnection, "Received unexpected frame type")
			fmt.Errorf("Unexpected frame type")
		}
	}

	return nil
}

func (c *Connection) processAckFrame(f *ackFrame) error {
	end := f.LargestAcknowledged
	start := end - f.FirstAckBlockLength

	// Go through all the ACK blocks and process everything.
	for {
		logf(logTypeConnection, "%s: processing ACK range %v-%v", c.label(), start, end)
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

			// 2. Remove all our ACKed acks TODO(ekr@rtfm.com)

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

func newRecvdPackets() recvdPackets {
	return recvdPackets{nil, 0}
}

func (p *recvdPackets) initialized() bool {
	return p.r != nil
}

func (p *recvdPackets) init(min uint64) {
	p.min = min
	p.r = make([]bool, 10)
}

func (p *recvdPackets) packetNotReceived(pn uint64) bool {
	if pn < p.min {
		logf(logTypeTrace, "Packet %v < min=%v", pn, p.min)
		return false // We're not sure.
	}

	if pn >= p.min+uint64(len(p.r)) {
		return true // We extend forward as needed.
	}

	return !p.r[pn-p.min]
}

func (p *recvdPackets) packetSetReceived(pn uint64) {
	assert(pn >= p.min)
	if pn >= p.min+uint64(len(p.r)) {
		grow := uint64(len(p.r)) - (pn - p.min)
		if grow < 10 {
			grow = 10
		}

		p.r = append(p.r, make([]bool, grow)...)
	}
	p.r[pn-p.min] = true
}

func (p *recvdPackets) prepareAckRange() []ackRange {
	var inrange = false
	var last uint64
	var pn uint64
	ranges := make([]ackRange, 0)

	for i := len(p.r) - 1; i >= 0; i-- {
		pn = uint64(i) + p.min
		if inrange != p.r[i] {
			if inrange {
				// This is the end of a range.
				ranges = append(ranges, ackRange{last, last - pn})
			} else {
				last = pn
			}
			inrange = p.r[i]
		}
	}
	if inrange {
		ranges = append(ranges, ackRange{last, last - pn + 1})
	}

	logf(logTypeConnection, "%v ACK ranges to send", len(ranges))
	logf(logTypeTrace, "ACK ranges = %v", ranges)
	return ranges
}

func (p *recvdPackets) packetsToAck() int {
	toack := int(0)

	for _, b := range p.r {
		if b {
			toack++
		}
	}
	return toack
}

func (c *Connection) CheckTimer() (int, error) {
	// Right now just re-send everything we might need to send.

	// Special case the client's first message.
	if c.role == RoleClient && (c.state == kStateInit ||
		c.state == kStateWaitServerFirstFlight) {
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
	c.setState(kStateEstablished)

	return nil
}

func (c *Connection) Established() bool {
	return c.state == kStateEstablished
}

func (c *Connection) packetNonce(send bool, pn uint64) []byte {
	// TODO(ekr@rtfm.com): Implement this once we have keys.
	return encodeArgs(pn)
}

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

func (c *Connection) GetStream(id uint32) *Stream {
	iid := int(id)

	if id < id {
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
