package chip

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

type ConnectionState interface {
	established() bool
	zeroRttAllowed() bool
	expandPacketNumber(pn uint64) uint64
}

type Connection struct {
	role uint8
	state uint8
	transport Transport
	tls *TlsConn
	nextSendPacket uint64
	queuedFrames []*Frame
}

func NewConnection(trans Transport, role uint8, tls TlsConfig) *Connection{
	return &Connection{
		role,
		kStateInit,
		trans,
		NewTlsConn(tls, role),
		uint64(0),
		[]*Frame{},
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

