package chip

import (
	"encoding/hex"
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
	finished bool
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
		false,
	}
}

func (c *TlsConn) handshake(input []byte) ([]byte, error) {
	logf(logTypeTls, "TLS handshake input len=%v", len(input))
	logf(logTypeTrace, "TLS handshake input = %v", hex.EncodeToString(input))
	if input != nil {
		err := c.conn.input(input)
		if err != nil {
			return nil, err
		}
	}
	assert(c.conn.OutputLen() == 0)
	alert := c.tls.Handshake()

	switch alert {
	case mint.AlertNoAlert:
		logf(logTypeTls, "TLS handshake complete")
		c.finished = true
	case mint.AlertWouldBlock:
		logf(logTypeTls, "TLS would have blocked")
	default:
		return nil, fmt.Errorf("TLS sent an alert %v", alert)
	}
	logf(logTypeTls, "TLS wrote %d bytes", c.conn.OutputLen())

	return c.conn.getOutput(), nil
}

