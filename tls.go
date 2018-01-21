package minq

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"github.com/bifurcation/mint"
	"log"
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
			UseDTLS:            true,
			AllowEarlyData:     true,
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

func newTlsConn(conf *TlsConfig, role uint8) *tlsConn {
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

func (c *tlsConn) isConnected() bool {
	hst := c.tls.GetHsState()
	return hst == mint.StateServerConnected || hst == mint.StateClientConnected
}

func (c *tlsConn) newBytes(input []byte) (uint64, []byte, []byte, error) {
	logf(logTypeTls, "TLS input [%v] = %x", len(input), input)
	logf(logTypeTrace, "TLS input = %v", hex.EncodeToString(input))

	if input != nil {
		err := c.conn.input(input)
		if err != nil {
			return 0, nil, nil, err
		}
	}

	if !c.isConnected() {
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
				return 0, nil, nil, fmt.Errorf("TLS sent an alert %v", alert)
			}

		}
		logf(logTypeTls, "TLS wrote %d bytes", c.conn.OutputLen())
		return 0, nil, c.conn.getOutput(), nil
	}

	// Otherwise, we are complete and try to read the application data.
	buf := make([]byte, len(input))
	n, err := c.tls.Read(buf)
	if err == mint.AlertWouldBlock {
		return 0, nil, nil, ErrorWouldBlock
	}
	if err != nil {
		return 0, nil, nil, err
	}
	buf = buf[:n]
	logf(logTypeTls, "Read bytes from peer: %x", buf)

	// TODO(ekr@rtfm.com): return output
	return 0, buf, nil, nil // TODO(ekr@rtfm.com): return packet number
}

func (c *tlsConn) sendPacket(p []byte) (uint64, []byte, error) {
	logf(logTypeTls, "Writing bytes to peer: %x", p)
	n, err := c.tls.Write(p)
	assert(n == len(p))
	if err != nil {
		return 0, nil, err
	}

	output := c.conn.getOutput()
	logf(logTypeTls, "Ciphertext: [%v] %x", len(output), output)
	return 0, output, nil
}

func (c *tlsConn) writable() bool {
	return c.tls.Writable()
}

func (c *tlsConn) overhead() int {
	return 64 // TODO(ekr@rtfm.com).
}

func (c *tlsConn) getHsState() string {
	return c.tls.GetHsState().String()
}
