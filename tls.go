package chip

import (
	"github.com/bifurcation/mint"
)

type TlsConfig struct {
}

func (c TlsConfig) toMint() *mint.Config {
	// TODO(ekr@rtfm.com): Provide a real config
	return &mint.Config{ServerName: "example.com"}
}

type TlsConn struct {
	conn *connBuffer
	tls *mint.Conn
}

func NewTlsConn(conf TlsConfig, role uint8) *TlsConn {
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

