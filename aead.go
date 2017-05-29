package chip

import (
//	"bytes"
)

type Aead interface {
	protect(pn uint64, header []byte, plaintext []byte) (ciphertext []byte, err error)
	unprotect(pn uint64, header []byte, ciphertext []byte) (plaintext []byte, err error)
}
