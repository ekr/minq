package minq

import (
	"crypto/cipher"
	"testing"
)

var kTestKey1 = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
var kTestIV1 = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
var kTestKey2 = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
var kTestIV2 = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13}

var ktestAeadHdr1 = []byte{1, 2, 3}
var ktestAeadHdr2 = []byte{1, 2, 4}
var ktestAeadBody1 = []byte{5, 6, 7}
var ktestAeadBody2 = []byte{5, 6, 8}

var kNonce0 = []byte{0, 0, 0, 0, 0, 0, 0, 0}
var kNonce1 = []byte{0, 0, 0, 0, 0, 0, 0, 1}

func testAeadSuccess(t *testing.T, aead cipher.AEAD) {
	ct := aead.Seal(nil, kNonce0, ktestAeadBody1, ktestAeadHdr1)

	pt, err := aead.Open(nil, kNonce0, ct, ktestAeadHdr1)
	assertNotError(t, err, "Could not unprotect")

	assertByteEquals(t, pt, ktestAeadBody1)
}

func testAeadWrongPacketNumber(t *testing.T, aead cipher.AEAD) {
	ct := aead.Seal(nil, kNonce0, ktestAeadBody1, ktestAeadHdr1)

	_, err := aead.Open(nil, kNonce1, ct, ktestAeadHdr1)
	assertError(t, err, "Shouldn't have unprotected")
}

func testAeadWrongHeader(t *testing.T, aead cipher.AEAD) {

	ct := aead.Seal(nil, kNonce0, ktestAeadBody1, ktestAeadHdr1)

	_, err := aead.Open(nil, kNonce0, ct, ktestAeadHdr2)
	assertError(t, err, "Shouldn't have unprotected")
}

func testAeadCorruptCT(t *testing.T, aead cipher.AEAD) {
	ct := aead.Seal(nil, kNonce0, ktestAeadBody1, ktestAeadHdr1)

	ct[0]++
	_, err := aead.Open(nil, kNonce0, ct, ktestAeadHdr1)
	assertError(t, err, "Shouldn't have unprotected")
}

func testAeadCorruptTag(t *testing.T, aead cipher.AEAD) {
	ct := aead.Seal(nil, kNonce0, ktestAeadBody1, ktestAeadHdr1)
	ct[len(ct)-1]++
	_, err := aead.Open(nil, kNonce0, ct, ktestAeadHdr1)
	assertError(t, err, "Shouldn't have unprotected")
}

func testAeadWrongAead(t *testing.T, aead cipher.AEAD, aead2 cipher.AEAD) {
	ct := aead.Seal(nil, kNonce0, ktestAeadBody1, ktestAeadHdr1)
	_, err := aead2.Open(nil, kNonce0, ct, ktestAeadHdr1)
	assertError(t, err, "Shouldn't have unprotected")
}

func testAeadAll(t *testing.T, aead cipher.AEAD) {
	t.Run("Success", func(t *testing.T) { testAeadSuccess(t, aead) })
	t.Run("WrongHeader", func(t *testing.T) { testAeadWrongHeader(t, aead) })
	t.Run("CorruptCT", func(t *testing.T) { testAeadCorruptCT(t, aead) })
	t.Run("CorruptTag", func(t *testing.T) { testAeadCorruptTag(t, aead) })
}

func makeWrappedAead(t *testing.T, key []byte, iv []byte) cipher.AEAD {
	a, err := newWrappedAESGCM(key, iv)
	assertNotError(t, err, "Couldn't make AEAD")
	return a
}

func TestAeadAES128GCM(t *testing.T) {
	a1 := makeWrappedAead(t, kTestKey1, kTestIV1)
	a2 := makeWrappedAead(t, kTestKey2, kTestIV1)
	a3 := makeWrappedAead(t, kTestKey1, kTestIV2)

	testAeadAll(t, a1)
	t.Run("WrongKey", func(t *testing.T) { testAeadWrongAead(t, a1, a2) })
	t.Run("WrongIV", func(t *testing.T) { testAeadWrongAead(t, a1, a3) })
	t.Run("WrongPacketNumber", func(t *testing.T) { testAeadWrongPacketNumber(t, a1) })
}
