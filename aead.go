package minq

import (
	"crypto/aes"
	"crypto/cipher"
)

// aeadWrapper contains an existing AEAD object and does the
// QUIC nonce masking.
type aeadWrapper struct {
	iv     []byte
	cipher cipher.AEAD
}

func (a *aeadWrapper) NonceSize() int {
	return a.cipher.NonceSize()
}
func (a *aeadWrapper) Overhead() int {
	return a.cipher.Overhead()
}

func (a *aeadWrapper) fmtNonce(in []byte) []byte {
	// The input nonce is actually a packet number.
	assert(len(in) == 8)
	assert(a.NonceSize() == 12)
	assert(len(a.iv) == a.NonceSize())

	nonce := make([]byte, a.NonceSize())
	copy(nonce[len(nonce)-len(in):], in)
	for i, b := range a.iv {
		nonce[i] ^= b
	}

	logf(logTypeAead, "Nonce=%x", nonce)
	return nonce
}

func (a *aeadWrapper) Seal(dst []byte, nonce []byte, plaintext []byte, aad []byte) []byte {
	logf(logTypeAead, "AES protecting aad len=%d, plaintext len=%d", len(aad), len(plaintext))
	logf(logTypeTrace, "AES input AAD=%x P=%x", aad, plaintext)
	ret := a.cipher.Seal(dst, a.fmtNonce(nonce), plaintext, aad)
	logf(logTypeTrace, "AES output %x", ret)

	return ret
}

func (a *aeadWrapper) Open(dst []byte, nonce []byte, ciphertext []byte, aad []byte) ([]byte, error) {
	logf(logTypeAead, "AES unprotecting aad len=%d, ciphertext len=%d", len(aad), len(ciphertext))
	logf(logTypeTrace, "AES input AAD=%x C=%x", aad, ciphertext)
	ret, err := a.cipher.Open(dst, a.fmtNonce(nonce), ciphertext, aad)
	if err != nil {
		return nil, err
	}
	logf(logTypeTrace, "AES output %x", ret)
	return ret, err
}

func newWrappedAESGCM(key []byte, iv []byte) (cipher.AEAD, error) {
	logf(logTypeAead, "New AES GCM context: key=%x iv=%x", key, iv)
	a, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(a)
	if err != nil {
		return nil, err
	}

	return &aeadWrapper{iv, aead}, nil
}
