package minq

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"github.com/bifurcation/mint"
	"github.com/bifurcation/mint/syntax"
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
	role     uint8
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

	return &tlsConn{
		conf,
		role,
		c,
		mint.NewConn(c, conf.toMint(), isClient),
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

type dtlsHeader struct {
	Typ      uint8
	Version  uint16
	EpochSeq uint64 // epoch + seq
	Length   uint16
}

func (c *tlsConn) newBytes(input []byte) (int, uint64, []byte, []byte, error) {
	logf(logTypeTls, "TLS input [%v] = %x", len(input), input)
	logf(logTypeTrace, "TLS input = %v", hex.EncodeToString(input))
	var hdr dtlsHeader
	il := len(input)

	if len(input) > 0 {
		n, err := syntax.Unmarshal(input, &hdr)
		// Ignore malformatted
		if err != nil {
			logf(logTypeTls, "Malformed DTLS record")
			return il, 0, nil, nil, nil
		}
		if n+int(hdr.Length) > il {
			logf(logTypeTls, "Malformed datagram hdr=%+v, consumed=%v length = %d", n, hdr, il)
			return il, 0, nil, nil, nil
		}
		input = input[:n+int(hdr.Length)]
		il = len(input)

		err = c.conn.input(input)
		if err != nil {
			return il, 0, nil, nil, err
		}
	}

	if !c.isConnected() {
	inner:
		for {
			logf(logTypeTls, "Calling Mint handshake")
			alert := c.tls.Handshake()
			switch alert {
			case mint.AlertNoAlert:
				// There are two cases here:
				// 1. We are done.
				// 2. Intermediate point in the state machine.

				hst := c.tls.GetHsState()
				if hst == mint.StateServerConnected || hst == mint.StateClientConnected {
					logf(logTypeTls, "TLS handshake complete")
					st := c.tls.ConnectionState()
					logf(logTypeTls, "Negotiated ALPN = %v", st.NextProto)
					// TODO(ekr@rtfm.com): Abort on ALPN mismatch when others do.
					if st.NextProto != kQuicALPNToken {
						logf(logTypeTls, "ALPN mismatch %v != %v", st.NextProto, kQuicALPNToken)
					}
					cs := st.CipherSuite
					c.cs = &cs
					c.finished = true
					break inner
				}
				continue // Loop
			case mint.AlertWouldBlock:
				logf(logTypeTls, "TLS handshake would have blocked")
				break inner
			case mint.AlertStatelessRetry:
				logf(logTypeTls, "TLS sent stateless retry")
				break inner

			default:
				// This is an error.
				logf(logTypeTls, "TLS alert %v", alert)
				return il, 0, nil, c.conn.getOutput(), fmt.Errorf("TLS sent an alert %v", alert)
			}
		}
	}

	// At this point, things have gone reasonably smoothly and we've made
	// as much progress as we can.

	// This is whatever Mint wrote.
	logf(logTypeTls, "Mint wrote %d bytes", c.conn.OutputLen())
	output := c.conn.getOutput()

	// Try to read application data if either:
	// 1. We are a connected
	// 2. We are a server, in which case there might be 0-RTT data.
	var buf []byte
	var seq uint64
	if c.isConnected() || c.role == RoleServer {
		logf(logTypeTls, "Trying to read from Mint")
		buf2 := make([]byte, len(input))
		n, err := c.tls.Read(buf2)
		if err == nil {
			if n > 0 {
				assert(il > 0)
				buf = buf2[:n]
				seq = hdr.EpochSeq
				logf(logTypeTls, "Read %d bytes from peer: %x", n, buf)
			}
		} else if err != mint.AlertWouldBlock {
			// TODO(ekr@rtfm.com): Return output?
			return il, 0, nil, nil, err
		}
	}

	return il, seq, buf, output, nil // TODO(ekr@rtfm.com): return packet number
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

func (c *tlsConn) nextRecordNumber() uint64 {
	return c.tls.NextRecordNumber()
}
