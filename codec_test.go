package chip

import (
	"encoding/hex"
	"fmt"
	"testing"
)

type TestStructDefaultLengths struct {
	U8  uint8
	U16 uint16
	B []byte
}

type TestStructOverrideLengths struct {
	U8  uint8
	U16 uint16
	B []byte
}

func (t TestStructOverrideLengths) U16__length() uintptr {
	return 1
}

func (t TestStructOverrideLengths) B__length() uintptr {
	return 3
}

func codecEDE(t *testing.T, s interface{}, s2 interface{}, expectedLen uintptr){
	res, err := encode(s)
	assertNotError(t, err, "Could not encode")

	fmt.Println("Result = ", hex.EncodeToString(res))
	// TODO(ekr@rtfm.com). What is the type of len().
	assertEquals(t, uintptr(expectedLen), uintptr(len(res)))
	
	_, err = decode(s2, res)
	assertNotError(t, err, "Could not decode")

	res2, err := encode(s2)
	assertNotError(t, err, "Could not re-encode")
	fmt.Println("Result2 = ", hex.EncodeToString(res2))	
	assertByteEquals(t, res, res2)
}

func TestCodecDefaultEncode(t *testing.T) {
	s := TestStructDefaultLengths { 1, 2, []byte{'a','b','c'} }
	var s2 TestStructDefaultLengths

	codecEDE(t, &s, &s2, 6)
}

func TestCodecOverrideEncode(t *testing.T) {
	s := TestStructOverrideLengths { 1, 2, []byte{'a','b','c'} }
	var s2 TestStructOverrideLengths

	codecEDE(t, &s, &s2, 5)
}

func TestCodecOverrideDecodeLength(t *testing.T) {
	s := TestStructOverrideLengths { 1, 2, []byte{'a','b','c'} }
	var s2 TestStructOverrideLengths

	res, err := encode(&s)
	assertNotError(t, err, "Could not encode")

	modified := append(res, 'd')
	_, err = decode(&s2, modified)
	assertNotError(t, err, "Could not decode")

	fmt.Println(s2)
	
	res2, err := encode(&s2)
	assertNotError(t, err, "Could not re-encode")

	assertByteEquals(t, res, res2)
}
