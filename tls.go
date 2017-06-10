package chip

import (
	"fmt"
	"github.com/bifurcation/mint"
)

type TlsConfig struct {
}

func (c TlsConfig) toMint() *mint.Config {
	// TODO(ekr@rtfm.com): Provide a real config
	return &mint.Config{ServerName: "example.com", NonBlocking: true}
}

type TlsConn struct {
	conn *connBuffer
	tls *mint.Conn
}

func newTlsConn(conf TlsConfig, role uint8) *TlsConn {
	isClient := true
	if role == kRoleServer {
		isClient = false
	}

	c := newConnBuffer()
	
	return &TlsConn{
		c,
		mint.NewConn(c, conf.toMint(), isClient),
	}
}

func (c *TlsConn) handshake(input []byte) ([]byte, error) {
	if input != nil {
		err := c.conn.input(input)
		if err != nil {
			return nil, err
		}
	}
	assert(c.conn.OutputLen() == 0)
	alert := c.tls.Handshake()
	if alert != mint.AlertNoAlert && alert != mint.AlertWouldBlock {
		return nil, fmt.Errorf("TLS sent an alert")
	}
	logf(logTypeTls, "TLS wrote %d bytes", c.conn.OutputLen())
	
	return c.conn.getOutput(), nil
}
