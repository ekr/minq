package minq

import (
	"crypto"
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

	k := QhkdfExpandLabel(cs.Hash, st.secret, "key", []byte{}, cs.KeyLen)
	iv := QhkdfExpandLabel(cs.Hash, st.secret, "iv", []byte{}, cs.IvLen)

	st.aead, err = newWrappedAESGCM(k, iv)
	if err != nil {
		return nil, err
	}

	return &st, nil
}

func generateCleartextKeys(secret []byte, label string, cs *mint.CipherSuiteParams) (*cryptoState, error) {
	extracted := mint.HkdfExtract(cs.Hash, kQuicVersionSalt, secret)
	inner := QhkdfExpandLabel(cs.Hash, extracted, label, []byte{}, cs.Hash.Size())
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

// struct HkdfLabel {
//    uint16 length;
//    opaque label<9..255>;
//    opaque hash_value<0..255>;
// };
func hkdfEncodeLabel(labelIn string, hashValue []byte, outLen int) []byte {
	label := "QUIC " + labelIn

	labelLen := len(label)
	hashLen := len(hashValue)
	hkdfLabel := make([]byte, 2+1+labelLen+1+hashLen)
	hkdfLabel[0] = byte(outLen >> 8)
	hkdfLabel[1] = byte(outLen)
	hkdfLabel[2] = byte(labelLen)
	copy(hkdfLabel[3:3+labelLen], []byte(label))
	hkdfLabel[3+labelLen] = byte(hashLen)
	copy(hkdfLabel[3+labelLen+1:], hashValue)

	return hkdfLabel
}

func QhkdfExpandLabel(hash crypto.Hash, secret []byte, label string, hashValue []byte, outLen int) []byte {
	info := hkdfEncodeLabel(label, hashValue, outLen)
	derived := mint.HkdfExpand(hash, secret, info, outLen)

	logf(logTypeTls, "HKDF Expand: label=[tls13 ] + '%s',requested length=%d\n", label, outLen)
	logf(logTypeTls, "PRK [%d]: %x\n", len(secret), secret)
	logf(logTypeTls, "Hash [%d]: %x\n", len(hashValue), hashValue)
	logf(logTypeTls, "Info [%d]: %x\n", len(info), info)
	logf(logTypeTls, "Derived key [%d]: %x\n", len(derived), derived)

	return derived
}
