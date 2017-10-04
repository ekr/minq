package minq

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"github.com/bifurcation/mint"
)

type TlsConfig struct {
	ServerName       string
	CertificateChain []*x509.Certificate
	Key              crypto.Signer
	mintConfig       *mint.Config
	ForceHrr         bool
}

func (c *TlsConfig) init() {
	_ = c.toMint()
}

func (c *TlsConfig) toMint() *mint.Config {
	if c.mintConfig == nil {
		// TODO(ekr@rtfm.com): Provide a real config
		config := mint.Config{
			ServerName:         c.ServerName,
			NonBlocking:        true,
			NextProtos:         []string{kQuicALPNToken},
			SendSessionTickets: true,
		}

		if c.ForceHrr {
			config.RequireCookie = true
		}

		if c.CertificateChain != nil && c.Key != nil {
			config.Certificates =
				[]*mint.Certificate{
					&mint.Certificate{
						Chain:      c.CertificateChain,
						PrivateKey: c.Key,
					},
				}
		}
		config.Init(false)
		c.mintConfig = &config
	}
	return c.mintConfig
}

func NewTlsConfig(serverName string) TlsConfig {
	return TlsConfig{
		ServerName: serverName,
	}
}

type tlsConn struct {
	conn     *connBuffer
	tls      *mint.Conn
	finished bool
	cs       *mint.CipherSuiteParams
}

func newTlsConn(conf TlsConfig, role uint8) *tlsConn {
	isClient := true
	if role == RoleServer {
		isClient = false
	}

	c := newConnBuffer()

	return &tlsConn{
		c,
		mint.NewConn(c, conf.toMint(), isClient),
		false,
		nil,
	}
}

func (c *tlsConn) setTransportParametersHandler(h *transportParametersHandler) {
	c.tls.SetExtensionHandler(h)
}

func (c *tlsConn) handshake(input []byte) ([]byte, error) {
	logf(logTypeTls, "TLS handshake input len=%v", len(input))
	logf(logTypeTrace, "TLS handshake input = %v", hex.EncodeToString(input))
	if input != nil {
		err := c.conn.input(input)
		if err != nil {
			return nil, err
		}
	}
	alert := c.tls.Handshake()

	switch alert {
	case mint.AlertNoAlert:
		logf(logTypeTls, "TLS handshake complete")
		st := c.tls.State()
		logf(logTypeTls, "Negotiated ALPN = %v", st.NextProto)
		// TODO(ekr@rtfm.com): Abort on ALPN mismatch when others do.
		if st.NextProto != kQuicALPNToken {
			logf(logTypeTls, "ALPN mismatch %v != %v", st.NextProto, kQuicALPNToken)
		}
		cs := st.CipherSuite
		c.cs = &cs
		c.finished = true
	case mint.AlertWouldBlock:
		logf(logTypeTls, "TLS would have blocked")
	default:
		return nil, fmt.Errorf("TLS sent an alert %v", alert)
	}
	logf(logTypeTls, "TLS wrote %d bytes", c.conn.OutputLen())

	return c.conn.getOutput(), nil
}

func (c *tlsConn) computeExporter(label string) ([]byte, error) {
	return c.tls.ComputeExporter(label, []byte{}, c.cs.Hash.Size())
}

func (c *tlsConn) getHsState() string {
	return c.tls.GetHsState()
}
