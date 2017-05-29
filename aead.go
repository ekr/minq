package chip

import (
	"bytes"
	"fmt"
	"hash/fnv"
)

type Aead interface {
	protect(pn uint64, header []byte, plaintext []byte) (ciphertext []byte, err error)
	unprotect(pn uint64, header []byte, ciphertext []byte) (plaintext []byte, err error)
}

// Definition for AEAD using 64-bit FNV-1a
type AeadFNV struct {
}

func (a *AeadFNV) protect(pn uint64, header []byte, plaintext []byte) (ciphertext []byte, err error) {
	h := fnv.New64a()
	h.Write(encodeArgs(pn))
	h.Write(header)
	h.Write(plaintext)
	return encodeArgs(plaintext, h.Sum64()), nil
}

func (a *AeadFNV) unprotect(pn uint64, header []byte, ciphertext []byte) (plaintext []byte, err error) {
	if len(ciphertext) < 8 {
		return nil, fmt.Errorf("Data too short to contain authentication tag")
	}
	pt := ciphertext[:len(ciphertext)-8]
	at := ciphertext[len(ciphertext)-8:]
	h := fnv.New64a()
	h.Write(encodeArgs(pn))
	h.Write(header)
	h.Write(pt)

	at2 := encodeArgs(h.Sum64())

	if !bytes.Equal(at, at2) {
		return nil, fmt.Errorf("Invalid authentication tag")
	}
	return pt, nil
}
