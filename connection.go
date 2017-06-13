package minq

import (
	"encoding/hex"
	"fmt"
)

const (
	kRoleClient = 1
	kRoleServer = 2
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

type Connection struct {
	role           uint8
	state          connState
	version        VersionNumber
	clientConnId   connectionId
	serverConnId   connectionId
	transport      Transport
	tls            *TlsConn
	writeClear     Aead
	readClear      Aead
	writeProtected Aead
	readProtected  Aead
	nextSendPacket uint64
	mtu            int
	streams        []stream
	clientInitial  []byte
	recvdPackets   []bool
	recvdPacketMin uint64 // Unused, but there for when we want to shift the window.
}

func NewConnection(trans Transport, role uint8, tls TlsConfig) *Connection {
	initState := kStateInit
	if role == kRoleServer {
		initState = kStateWaitClientInitial
	}
	c := Connection{
		role,
		initState,
		kQuicVersion,
		0, // TODO(ekr@rtfm.com): generate
		0, // TODO(ekr@rtfm.com): generate
		trans,
		newTlsConn(tls, role),
		&AeadFNV{},
		&AeadFNV{},
		nil,
		nil,
		uint64(0),
		kInitialMTU,
		nil,
		nil,
		make([]bool, 1024),
		0,
	}
	c.ensureStream(0)
	return &c
}

func (c *Connection) established() bool {
	return c.state == kStateEstablished
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
	if c.role == kRoleClient {
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

func (c *Connection) ensureStream(id uint32) *stream {
	// TODO(ekr@rtfm.com): this is not really done, because we never clean up
	for i := uint32(len(c.streams)); i <= id; i++ {
		c.streams = append(c.streams, stream{})
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
	topad := kMinimumClientInitialLength - (kInitialIntegrityCheckLength + l + kInitialIntegrityCheckLength)
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
	var aead Aead
	aead = c.writeProtected
	connId = c.serverConnId

	if c.role == kRoleClient {
		if pt == PacketTypeClientInitial || pt == PacketTypeClientCleartext {
			aead = c.writeClear
			connId = c.clientConnId
		} else if pt == PacketType0RTTProtected {
			connId = c.clientConnId
		}
	} else {
		if pt == PacketTypeServerCleartext {
			aead = c.writeClear
		}
	}

	left -= aead.expansion()

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

	protected, err := aead.protect(p.PacketNumber, hdr, p.payload)
	if err != nil {
		return err
	}

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

// TODO(ekr@rtfm.com): Write this properly.
func (c *Connection) sendQueued() (int, error) {
	// Right now, just send everything we have on stream 0
	// as one packet per chunk. TODO(ekr@rtfm.com)
	stream := &c.streams[0]
	logf(logTypeConnection, "%v: processing outgoing queue #chunks=%v", c.label(), len(stream.out))
	sent := 0

	// Figure out all the ACKs we might send
	acks := c.prepareAckRange()
	acksSent := int(0)

	// And the packet type we want.
	pt := PacketTypeServerCleartext
	if c.role == kRoleClient {
		pt = PacketTypeClientCleartext
	}

	for i, chunk := range stream.out {
		left := c.mtu
		frames := make([]frame, 0)
		logf(logTypeConnection, "Sending chunk of offset=%v len %v", chunk.offset, len(chunk.data))
		f := newStreamFrame(0, chunk.offset, chunk.data)

		frames = append(frames, f)
		l, err := f.length()
		if err != nil {
			return 0, err
		}
		left -= l

		// Record that we send this chunk in this packet
		stream.out[i].pns = append(stream.out[i].pns, c.nextSendPacket)

		// Now send as many acks as we can.
		af, asent, err := c.makeAckFrame(acks, left)
		if err != nil {
			return 0, err
		}

		if asent > acksSent {
			acksSent = asent
		}

		frames = append(frames, *af)
		err = c.sendPacket(uint8(pt), frames)
		sent++

		if err != nil {
			return 0, err
		}
	}

	// Last ditch, make an ACK-only frame if we know there are ACKs that
	// didn't get sent.
	if len(stream.out) == 0 || acksSent < len(acks) {
		logf(logTypeConnection, "Sending backup ACK frame")
		af, _, err := c.makeAckFrame(acks, c.mtu)
		err = c.sendPacket(uint8(pt), []frame{*af})
		if err != nil {
			return 0, err
		}

		sent++
	}

	return sent, nil
}

func (c *Connection) input() error {
	// TODO(ekr@rtfm.com): Do something smarter.
	logf(logTypeConnection, "Connection.input()")
	for {
		p, err := c.transport.Recv()
		if err == WouldBlock {
			logf(logTypeConnection, "Read would have blocked")
			return nil
		}

		if err != nil {
			logf(logTypeConnection, "Error reading")
			return err
		}

		logf(logTypeTrace, "Read packet %v", hex.EncodeToString(p))

		err = c.recvPacket(p)
		if err != nil {
			logf(logTypeConnection, "Error processing packet", err)
		}
	}
}

// Walk through all the streams and see how many bytes are outstanding.
// Right now this is very expensive.

func (c *Connection) outstandingQueuedBytes() (n int) {
	for _, s := range c.streams {
		n += s.outstandingQueuedBytes()
	}

	return
}

func (c *Connection) recvPacket(p []byte) error {
	var hdr PacketHeader

	logf(logTypeTrace, "Receiving packet len=%v %v", len(p), hex.EncodeToString(p))
	hdrlen, err := decode(&hdr, p)
	if err != nil {
		logf(logTypeConnection, "Could not decode packet")
		return err
	}
	assert(int(hdrlen) <= len(p))

	// TODO(ekr@rtfm.com): Reconstruct the packet number
	logf(logTypeConnection, "Received (unverified) packet with PN=%v", hdr.PacketNumber)
	if !c.packetNotReceived(hdr.PacketNumber) {
		logf(logTypeConnection, "Discarding duplicate packet")
		return fmt.Errorf("Duplicate packet")
	}

	// TODO(ekr@rtfm.com): Figure out which aead we need.
	payload, err := c.readClear.unprotect(hdr.PacketNumber, p[:hdrlen], p[hdrlen:])
	if err != nil {
		logf(logTypeConnection, "Could not unprotect packet")
		return err
	}

	// We have now verified that this is a valid packet, so mark
	// it received.
	c.packetSetReceived(hdr.PacketNumber)
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
	for len(payload) > 0 {

		n, f, err := decodeFrame(payload)
		if err != nil {
			logf(logTypeConnection, "Couldn't decode frame %v", err)
			return err
		}
		logf(logTypeHandshake, "Frame type %v", f.f.getType())

		payload = payload[n:]
		switch inner := f.f.(type) {
		case *streamFrame:
			if c.role == kRoleClient {
				if c.state != kStateWaitServerFirstFlight {
					return fmt.Errorf("Received ServerClearText after handshake finished")
				}
				// Ignore ACKs, so:
				// 1. Remove the clientInitial packet.
				// 2. Set the outgoing stream offset accordingly
				if len(c.clientInitial) > 0 {
					c.streams[0].writeOffset = uint64(len(c.clientInitial))
					c.clientInitial = nil
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
				c.setState(kStateEstablished)
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

func (c *Connection) packetNotReceived(pn uint64) bool {
	if pn < c.recvdPacketMin {
		logf(logTypeTrace, "Packet %v < min=%v", pn, c.recvdPacketMin)
		return false // We're not sure.
	}

	if pn >= c.recvdPacketMin+uint64(len(c.recvdPackets)) {
		return true // We extend forward as needed.
	}

	return !c.recvdPackets[pn-c.recvdPacketMin]
}

func (c *Connection) packetSetReceived(pn uint64) {
	assert(pn >= c.recvdPacketMin)
	if pn >= c.recvdPacketMin+uint64(len(c.recvdPackets)) {
		grow := uint64(len(c.recvdPackets)) - (pn - c.recvdPacketMin)
		if grow < 10 {
			grow = 10
		}

		c.recvdPackets = append(c.recvdPackets, make([]bool, grow)...)
	}
	c.recvdPackets[pn-c.recvdPacketMin] = true
}

func (c *Connection) prepareAckRange() []ackRange {
	var inrange = false
	var last uint64
	var pn uint64
	ranges := make([]ackRange, 0)

	for i := len(c.recvdPackets) - 1; i >= 0; i-- {
		pn = uint64(i) + c.recvdPacketMin
		if inrange != c.recvdPackets[i] {
			if inrange {
				// This is the end of a range.
				ranges = append(ranges, ackRange{last, last - pn})
			} else {
				last = pn
			}
			inrange = c.recvdPackets[i]
		}
	}
	if inrange {
		ranges = append(ranges, ackRange{last, last - pn + 1})
	}

	logf(logTypeConnection, "%s: %v ACK ranges to send", c.label(), len(ranges))
	logf(logTypeTrace, "%s: ACK ranges = %v", c.label(), ranges)
	return ranges
}

func (c *Connection) checkTimer() (int, error) {
	// Right now just re-send everything we might need to send.

	// Special case the client's first message.
	if c.state == kStateWaitServerFirstFlight {
		err := c.sendClientInitial()
		return 0, err
	}

	return c.sendQueued()
}
