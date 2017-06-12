package chip

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
	kStateInit = connState(1)
	kStateWaitClientInitial = connState(2)
	kStateWaitServerFirstFlight = connState(3)
	kStateWaitClientSecondFlight = connState(4)
	kStateEstablished = connState(5)
)

const (
	kMinimumClientInitialLength = 1252  // draft-ietf-quic-transport S 9.8
	kLongHeaderLength = 17
	kInitialIntegrityCheckLength = 8    // FNV-1a 64
	kInitialMTU = 1252 // 1280 - UDP headers.
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

type Connection struct {
	role uint8
	state connState
	version VersionNumber
	clientConnId connectionId
	serverConnId connectionId
	transport Transport
	tls *TlsConn
	writeClear Aead
	readClear Aead
	writeProtected Aead
	readProtected Aead
	nextSendPacket uint64
	queuedFrames []frame
	mtu int
	streams []stream
}

func NewConnection(trans Transport, role uint8, tls TlsConfig) *Connection{
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
		[]frame{},
		kInitialMTU,
		nil,
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
	
	logf(logTypeConnection, "Connection setting state to %v", state)
	c.state = state
}

func (c *Connection) ensureStream(id uint32) *stream {
	// TODO(ekr@rtfm.com): this is not really done, because we never clean up
	for i := uint32(len(c.streams)); i <= id; i++ {
		c.streams = append(c.streams, stream{})
	}
	return &c.streams[id]
}

func (c *Connection) sendClientInitial() error {
	logf(logTypeHandshake, "Sending client initial packet")
	ch, err := c.tls.handshake(nil)
	if err != nil {
		return err
	}
	f := newStreamFrame(0, 0, ch)
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
	c.enqueueFrame(f)
	c.streams[0].writeOffset = uint64(len(ch))
	
	for i :=0; i < topad; i++ {
		c.enqueueFrame(newPaddingFrame(0))
	}

	c.setState(kStateWaitServerFirstFlight)
	return err
}

func (c *Connection) enqueueFrame(f frame) error {
	c.queuedFrames = append(c.queuedFrames, f)
	return nil
}

func (c *Connection) sendPacket(pt uint8) (int, error) {
	tosend := c.queuedFrames
	logf(logTypeConnection, "Sending packet of type %v. %v eligible frames", pt, len(tosend))
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
		return 0, err
	}
	left -= len(hdr)

	sent := 0

	// TODO(ekr@rtfm.com): Need to filter which frames can be sent in
	// which packet.
	for _, f := range tosend {
		l, err := f.length()
		logf(logTypeConnection, "%s: Adding frame of type %v len=%v", c.label(), f.f.getType(), l)
		if err != nil {
			return 0, err
		}
		if l > left {
			break
		}

		p.payload = append(p.payload, f.encoded...)
		sent++
	}

	protected, err := aead.protect(p.PacketNumber, hdr, p.payload)
	if err != nil {
		return 0, err
	}

	packet := append(hdr, protected...)

	logf(logTypeTrace, "Sending packet len=%d, len=%v", len(packet), hex.EncodeToString(packet))
	c.transport.Send(packet)
	
	return sent, nil
}

func (c *Connection) sendOnStream(streamId uint32, data []byte) error {
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

// TODO(ekr@rtfm.com): Write this properly.
func (c *Connection) sendQueued() error {
	// Right now, just send everything we have on stream 0
	// as one packet per chunk. TODO(ekr@rtfm.com)
	for _, chunk := range(c.streams[0].out) {
		logf(logTypeConnection, "Sending chunk of len %v", len(chunk.data))
		f := newStreamFrame(0, chunk.offset, chunk.data)
		c.enqueueFrame(f)

		pt := PacketTypeServerCleartext
		if c.role == kRoleClient {
			pt = PacketTypeClientCleartext
		}
		_, err := c.sendPacket(uint8(pt))
		if err != nil {
			return err
		}
	}

	return nil
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

func (c *Connection) recvPacket(p []byte) error {
	var hdr PacketHeader

	logf(logTypeTrace, "Receiving packet len=%v %v", len(p), hex.EncodeToString(p))
	hdrlen, err := decode(&hdr, p)
	if err != nil {
		logf(logTypeConnection, "Could not decode packet")
		return err
	}
	assert(int(hdrlen) <= len(p))

	// TODO(ekr@rtfm.com): Figure out which aead we need.
	payload, err := c.readClear.unprotect(hdr.PacketNumber, p[:hdrlen], p[hdrlen:])
	if err != nil {
		logf(logTypeConnection, "Could not unprotect packet")
		return err
	}

	typ := hdr.getHeaderType()
	if !isLongHeader(&hdr) {
		// TODO(ekr@rtfm.com): We are using this for both types.
		typ = PacketType1RTTProtectedPhase0
	}
	logf(logTypeConnection, "Packet header %v, %d", hdr, typ)
	switch (typ) {
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

	if (c.state != kStateWaitClientInitial) {
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
	return c.sendQueued()
}

func (c *Connection) processCleartext(hdr *PacketHeader, payload []byte) error {
	logf(logTypeHandshake, "Reading cleartext in state %v", c.state)
	for len(payload) > 0 {
		if c.role == kRoleClient {
			if (c.state != kStateWaitServerFirstFlight) {
				return fmt.Errorf("Received ServerClearText after handshake finished")
			}
			// TODO(ekr@rtfm.com): Cheat by clearig the client's outgoing queue.
			// When we have ACKs here we won't need to do this.
			c.queuedFrames = nil
			
		} else {
			if (c.state != kStateWaitClientSecondFlight) {
				return fmt.Errorf("Received ClientClearText after handshake finished")
			}
		}

		var sf streamFrame
		
		n, err := decode(&sf, payload)
		if err != nil {
			logf(logTypeConnection, "Failure decoding stream frame in stream 0")
			return err
		}
		payload = payload[n:]
		
		if sf.StreamId != 0 {
			return fmt.Errorf("Received cleartext with stream id != 0")
		}

		c.streams[0].newFrameData(sf.Offset, sf.Data)
		available := c.streams[0].readAll()
		out, err := c.tls.handshake(available)
		if err != nil {
			return err
		}

		if len(out) > 0 {
			c.sendOnStream(0, out)
			err = c.sendQueued()
			if err != nil {
				return err
			}
			assert(c.tls.finished)
			c.setState(kStateEstablished)
		}
	}
	// TODO(ekr@rtfm.com): Check for more on stream 0, but we need to properly handle
	// encrypted NST.

	
	return nil
}


