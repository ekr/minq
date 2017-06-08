package chip

import (
	//	"encoding/hex"
	//	"fmt"
	"testing"
)

var kTestAeadHdr1 = []byte{1, 2, 3}
var kTestAeadHdr2 = []byte{1, 2, 4}
var kTestAeadBody1 = []byte{5, 6, 7}
var kTestAeadBody2 = []byte{5, 6, 8}

func TestAeadSuccess(t *testing.T) {
	var fnv AeadFNV

	ct, err := fnv.protect(uint64(0), kTestAeadHdr1, kTestAeadBody1)
	assertNotError(t, err, "Could not protect")

	pt, err := fnv.unprotect(uint64(0), kTestAeadHdr1, ct)
	assertNotError(t, err, "Could not unprotect")

	assertByteEquals(t, pt, kTestAeadBody1)
}

func TestAeadSuccessWrongPacketNumber(t *testing.T) {
	var fnv AeadFNV

	ct, err := fnv.protect(uint64(0), kTestAeadHdr1, kTestAeadBody1)
	assertNotError(t, err, "Could not protect")

	_, err = fnv.unprotect(uint64(1), kTestAeadHdr1, ct)
	assertError(t, err, "Shouldn't have unprotected")
}

func TestAeadSuccessWrongHeader(t *testing.T) {
	var fnv AeadFNV

	ct, err := fnv.protect(uint64(0), kTestAeadHdr1, kTestAeadBody1)
	assertNotError(t, err, "Could not protect")

	_, err = fnv.unprotect(uint64(0), kTestAeadHdr2, ct)
	assertError(t, err, "Shouldn't have unprotected")
}

func TestAeadSuccessCorruptCT(t *testing.T) {
	var fnv AeadFNV

	ct, err := fnv.protect(uint64(0), kTestAeadHdr1, kTestAeadBody1)
	assertNotError(t, err, "Could not protect")

	ct[0] += 1
	_, err = fnv.unprotect(uint64(0), kTestAeadHdr1, ct)
	assertError(t, err, "Shouldn't have unprotected")
}

func TestAeadSuccessCorruptTag(t *testing.T) {
	var fnv AeadFNV

	ct, err := fnv.protect(uint64(0), kTestAeadHdr1, kTestAeadBody1)
	assertNotError(t, err, "Could not protect")

	ct[len(ct)-1] += 1
	_, err = fnv.unprotect(uint64(0), kTestAeadHdr1, ct)
	assertError(t, err, "Shouldn't have unprotected")
}
