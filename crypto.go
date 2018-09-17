package minq

import (
	"crypto/cipher"
	"encoding/hex"
	"github.com/bifurcation/mint"
)

type cryptoState struct {
	aead cipher.AEAD
	pne  pneCipherFactory
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

	k := mint.HkdfExpandLabel(cs.Hash, secret, "key", []byte{}, cs.KeyLen)
	iv := mint.HkdfExpandLabel(cs.Hash, secret, "iv", []byte{}, cs.IvLen)
	pn := mint.HkdfExpandLabel(cs.Hash, secret, "pn", []byte{}, cs.KeyLen)
	logf(logTypeAead, "key=%x iv=%x pn=%x", k, iv, pn)
	st.aead, err = newWrappedAESGCM(k, iv)
	if err != nil {
		return nil, err
	}
	st.pne = newPneCipherFactoryAES(pn)

	return &st, nil
}

func generateCleartextKeys(secret []byte, label string, cs *mint.CipherSuiteParams) (*cryptoState, error) {
	logf(logTypeTls, "Cleartext keys: cid=%x initial_salt=%x", secret, kQuicVersionSalt)
	extracted := mint.HkdfExtract(cs.Hash, kQuicVersionSalt, secret)
	inner := mint.HkdfExpandLabel(cs.Hash, extracted, label, []byte{}, cs.Hash.Size())
	logf(logTypeAead, "initial_secret (%s) = %x", label, inner)
	return newCryptoStateInner(inner, cs)
}

func newCryptoStateFromTls(t *tlsConn, label string) (*cryptoState, error) {
	panic("TODO")
}
