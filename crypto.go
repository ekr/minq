package minq

import (
	"crypto/cipher"
	"github.com/bifurcation/mint"
)

type cryptoState struct {
	secret []byte
	aead   cipher.AEAD
}

const clientPpSecretLabel = "EXPORTER-QUIC client 1-RTT Secret"
const serverPpSecretLabel = "EXPORTER-QUIC server 1-RTT Secret"

func newCryptoState(t *tlsConn, label string) (*cryptoState, error) {
	var st cryptoState
	var err error

	st.secret, err = t.computeExporter(label)
	if err != nil {
		return nil, err
	}

	k := mint.HkdfExpandLabel(t.cs.Hash, st.secret, "key", []byte{}, t.cs.KeyLen)
	iv := mint.HkdfExpandLabel(t.cs.Hash, st.secret, "iv", []byte{}, t.cs.IvLen)

	st.aead, err = newWrappedAESGCM(k, iv)
	if err != nil {
		return nil, err
	}

	return &st, nil
}
