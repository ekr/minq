package minq

import (
	"crypto/cipher"
	"encoding/hex"
	"github.com/bifurcation/mint"
)

type cryptoState struct {
	secret []byte
	aead   cipher.AEAD
}

func infallibleHexDecode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("didn't hex decode " + s)
	}
	return b
}

var kQuicVersionSalt = infallibleHexDecode("9c108f98520a5c5c32968e950e8a2c5fe06d6c38")

const clientCtSecretLabel = "client in"
const serverCtSecretLabel = "server in"

const clientPpSecretLabel = "EXPORTER-QUIC client 1rtt"
const serverPpSecretLabel = "EXPORTER-QUIC server 1rtt"

func newCryptoStateInner(secret []byte, cs *mint.CipherSuiteParams) (*cryptoState, error) {
	var st cryptoState
	var err error

	st.secret = secret

	k := mint.HkdfExpandLabel(cs.Hash, st.secret, "key", []byte{}, cs.KeyLen)
	iv := mint.HkdfExpandLabel(cs.Hash, st.secret, "iv", []byte{}, cs.IvLen)

	st.aead, err = newWrappedAESGCM(k, iv)
	if err != nil {
		return nil, err
	}

	return &st, nil
}

func generateCleartextKeys(secret []byte, label string, cs *mint.CipherSuiteParams) (*cryptoState, error) {
	logf(logTypeTls, "Cleartext keys: cid=%x", secret)
	extracted := mint.HkdfExtract(cs.Hash, kQuicVersionSalt, secret)
	inner := mint.HkdfExpandLabel(cs.Hash, extracted, label, []byte{}, cs.Hash.Size())
	return newCryptoStateInner(inner, cs)
}

func newCryptoStateFromTls(t *tlsConn, label string) (*cryptoState, error) {
	panic("TODO")
}
