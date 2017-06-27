package minq

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"hash/fnv"
)

// Definition for AEAD using 64-bit FNV-1a
type AeadFNV struct {
}

func (a *AeadFNV) NonceSize() int {
	return 12
}
func (a *AeadFNV) Overhead() int {
	return 8
}

func (a *AeadFNV) Seal(dst []byte, nonce []byte, plaintext []byte, aad []byte) []byte {
	logf(logTypeAead, "FNV protecting aad len=%d, plaintext len=%d", len(aad), len(plaintext))
	logf(logTypeTrace, "FNV input %x %x", aad, plaintext)
	h := fnv.New64a()
	h.Write(nonce)
	h.Write(aad)
	h.Write(plaintext)
	res := encodeArgs(plaintext, h.Sum64())
	dst = append(dst, res...)
	logf(logTypeAead, "FNV ciphertext length=%d", len(dst))
	return dst
}

func (a *AeadFNV) Open(dst []byte, nonce []byte, ciphertext []byte, aad []byte) ([]byte, error) {
	logf(logTypeAead, "FNV unprotecting aad len=%d, ciphertext len=%d", len(aad), len(ciphertext))
	if len(ciphertext) < 8 {
		return nil, fmt.Errorf("Data too short to contain authentication tag")
	}
	pt := ciphertext[:len(ciphertext)-8]
	at := ciphertext[len(ciphertext)-8:]
	h := fnv.New64a()
	h.Write(nonce)
	h.Write(aad)
	h.Write(pt)

	at2 := encodeArgs(h.Sum64())

	if !bytes.Equal(at, at2) {
		return nil, fmt.Errorf("Invalid authentication tag")
	}

	dst = append(dst, pt...)
	logf(logTypeAead, "FNV plaintext length=%d", len(dst))
	return pt, nil
}

// AeadWrapper contains an existing AEAD object and does the
// QUIC nonce masking.
type AeadWrapper struct {
	iv     []byte
	cipher cipher.AEAD
}

func (a *AeadWrapper) NonceSize() int {
	return a.cipher.NonceSize()
}
func (a *AeadWrapper) Overhead() int {
	return a.cipher.Overhead()
}

func (a *AeadWrapper) fmtNonce(in []byte) []byte {
	// The input nonce is actually a packet number.
	assert(len(in) == 8)
	assert(a.NonceSize() == 12)
	assert(len(a.iv) == a.NonceSize())

	nonce := make([]byte, a.NonceSize())
	copy(nonce[len(nonce)-len(in):], in)
	for i, b := range a.iv {
		nonce[i] ^= b
	}

	return nonce
}

func (a *AeadWrapper) Seal(dst []byte, nonce []byte, plaintext []byte, aad []byte) []byte {
	logf(logTypeAead, "AES protecting aad len=%d, plaintext len=%d", len(aad), len(plaintext))
	logf(logTypeTrace, "AES input %x %x", aad, plaintext)
	ret := a.cipher.Seal(dst, a.fmtNonce(nonce), plaintext, aad)
	logf(logTypeTrace, "AES output %x", ret)

	return ret
}

func (a *AeadWrapper) Open(dst []byte, nonce []byte, ciphertext []byte, aad []byte) ([]byte, error) {
	logf(logTypeAead, "AES unprotecting aad len=%d, ciphertext len=%d", len(aad), len(ciphertext))
	logf(logTypeTrace, "AES input %x", ciphertext)
	ret, err := a.cipher.Open(dst, a.fmtNonce(nonce), ciphertext, aad)
	if err != nil {
		return nil, err
	}
	logf(logTypeTrace, "AES output %x", ret)
	return ret, err
}

func newWrappedAESGCM(key []byte, iv []byte) (cipher.AEAD, error) {
	a, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(a)
	if err != nil {
		return nil, err
	}

	return &AeadWrapper{iv, aead}, nil
}
