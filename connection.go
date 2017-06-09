package chip

import (
	"encoding/hex"
	"fmt"
)

const (
	kRoleClient = 1
	kRoleServer = 2
)

const (
	kStateInit = 1
	kStateWaitClientInitial = 2
	kStateWaitServerFirstFlight = 3
	kStateWaitClientSecondFlight = 4
	kEstablished = 5
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
	state uint8
	version VersionNumber
	clientConnId connectionId
	serverConnId connectionId
	transport Transport
	tls *TlsConn
	writeClear Aead
	writeProtected Aead
	readProtected Aead
	nextSendPacket uint64
	queuedFrames []frame
	mtu int
}

func NewConnection(trans Transport, role uint8, tls TlsConfig) *Connection{
	return &Connection{
		role,
		kStateInit,
		kQuicVersion,
		0, // TODO(ekr@rtfm.com): generate
		0, // TODO(ekr@rtfm.com): generate
		trans,
		newTlsConn(tls, role),
		&AeadFNV{},
		nil,
		nil,
		uint64(0),
		[]frame{},
		kInitialMTU,
	}
}

func (c *Connection) established() bool {
	return c.state == kEstablished
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

func (c *Connection) sendClientInitial() error {
	logf(logTypeHandshake, "Sending client initial packet")
	ch, err := c.tls.handshake()
	if err != nil {
		return err
	}
	f := newStreamFrame(0, 0, ch)
	fmt.Println("EKR: Stream frame=%v", f)
	// Encode this so we know how much room it is going to take up.
	l, err := f.length()
	logf(logTypeHandshake, "Length of client hello stream frame=%d", l)	
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

	
	for i :=0; i < topad; i++ {
		c.enqueueFrame(newPaddingFrame(0))
	}
	return err
}

func (c *Connection) enqueueFrame(f frame) error {
	c.queuedFrames = append(c.queuedFrames, f)
	return nil
}

func (c *Connection) sendQueued(pt uint8) (int, error) {
	left := c.mtu

	var connId connectionId
	var aead Aead
	aead = c.writeProtected
	connId = c.serverConnId
	
	if c.role == kRoleClient {
		if pt == PacketTypeClientInitial {
			aead = c.writeClear
			connId = c.clientConnId
		} else if pt == PacketType0RTTProtected {
			connId = c.clientConnId
		}
	}

	left -= aead.expansion()
	
	// For now, just do the long header.
	p := Packet{
		PacketHeader{
			pt,
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
	
	for _, f := range c.queuedFrames {
		l, err := f.length()
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

	logf(logTypeTrace, "Sending packet len=%d, len=%v", len(protected), hex.EncodeToString(protected))

	return sent, nil
}
