package minq

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"

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

		config.CookieProtector, _ = mint.NewDefaultCookieProtector()
		config.InsecureSkipVerify = true // TODO(ekr@rtfm.com): This is horribly insecure, but Minq is right now for testing

		if c.CertificateChain != nil && c.Key != nil {
			config.Certificates =
				[]*mint.Certificate{
					&mint.Certificate{
						Chain:      c.CertificateChain,
						PrivateKey: c.Key,
					},
				}
		} else {
			priv, cert, err := mint.MakeNewSelfSignedCert(c.ServerName, mint.ECDSA_P256_SHA256)
			if err != nil {
				log.Fatalf("Couldn't make self-signed cert %v", err)
			}
			config.Certificates = []*mint.Certificate{
				{
					Chain:      []*x509.Certificate{cert},
					PrivateKey: priv,
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
	config   *TlsConfig
	conn     *connBuffer
	tls      *mint.Conn
	finished bool
	cs       *mint.CipherSuiteParams
}

func newTlsConn(conf *TlsConfig, role Role) *tlsConn {
	isClient := true
	if role == RoleServer {
		isClient = false
	}

	c := newConnBuffer()

	conf2 := *conf
	return &tlsConn{
		&conf2,
		c,
		mint.NewConn(c, conf2.toMint(), isClient),
		false,
		nil,
	}
}

func (c *tlsConn) setTransportParametersHandler(h *transportParametersHandler) {
	c.config.mintConfig.ExtensionHandler = h
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

outer:
	for {
		logf(logTypeTls, "Calling Mint handshake")
		alert := c.tls.Handshake()
		hst := c.tls.GetHsState()
		switch alert {
		case mint.AlertNoAlert, mint.AlertStatelessRetry:
			if hst == mint.StateServerConnected || hst == mint.StateClientConnected {
				st := c.tls.ConnectionState()

				logf(logTypeTls, "TLS handshake complete")
				logf(logTypeTls, "Negotiated ALPN = %v", st.NextProto)
				// TODO(ekr@rtfm.com): Abort on ALPN mismatch when others do.
				if st.NextProto != kQuicALPNToken {
					logf(logTypeTls, "ALPN mismatch %v != %v", st.NextProto, kQuicALPNToken)
				}
				cs := st.CipherSuite
				c.cs = &cs
				c.finished = true

				break outer
			}
			// Loop
		case mint.AlertWouldBlock:
			logf(logTypeTls, "TLS would have blocked")
			break outer
		default:
			return nil, fmt.Errorf("TLS sent an alert %v", alert)
		}
	}

	logf(logTypeTls, "TLS wrote %d bytes", c.conn.OutputLen())

	return c.conn.getOutput(), nil
}

func (c *tlsConn) readPostHandshake(input []byte) error {
	logf(logTypeTls, "TLS post-handshake input len=%v", len(input))
	if input != nil {
		err := c.conn.input(input)
		if err != nil {
			return err
		}
	}

	buf := make([]byte, 1)
	n, err := c.tls.Read(buf)
	if n != 0 {
		return fmt.Errorf("Received TLS application data")
	}
	if err != mint.AlertWouldBlock {
		return err
	}
	return nil
}

func (c *tlsConn) computeExporter(label string) ([]byte, error) {
	return c.tls.ComputeExporter(label, []byte{}, c.cs.Hash.Size())
}

func (c *tlsConn) getHsState() string {
	return c.tls.GetHsState().String()
}
