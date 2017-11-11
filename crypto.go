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

const kQuicVersionSalt = "afc824ec5fc77eca1e9d36f37fb2d46518c36639"

const clientCtSecretLabel = "QUIC client cleartext Secret"
const serverCtSecretLabel = "QUIC server cleartext Secret"

const clientPpSecretLabel = "EXPORTER-QUIC client 1-RTT Secret"
const serverPpSecretLabel = "EXPORTER-QUIC server 1-RTT Secret"

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

func newCryptoStateFromSecret(secret []byte, label string, cs *mint.CipherSuiteParams) (*cryptoState, error) {
	var err error

	salt, err := hex.DecodeString(kQuicVersionSalt)
	if err != nil {
		panic("Bogus value")
	}
	extracted := mint.HkdfExtract(cs.Hash, salt, secret)
	inner := mint.HkdfExpandLabel(cs.Hash, extracted, label, []byte{}, cs.Hash.Size())
	return newCryptoStateInner(inner, cs)
}

func newCryptoStateFromTls(t *tlsConn, label string) (*cryptoState, error) {
	var err error

	secret, err := t.computeExporter(label)
	if err != nil {
		return nil, err
	}

	return newCryptoStateInner(secret, t.cs)
}
