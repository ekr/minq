package chip

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

/* STOLEN FROM MINT.
The MIT License (MIT)

Copyright (c) 2016 Richard Barnes

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

func unhex(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return b
}

func assertX(t *testing.T, test bool, msg string) {
	if !test {
		t.Fatalf(msg)
	}
}

func assertError(t *testing.T, err error, msg string) {
	assertX(t, err != nil, msg)
}

func assertNotError(t *testing.T, err error, msg string) {
	if err != nil {
		msg += ": " + err.Error()
	}
	assertX(t, err == nil, msg)
}

func assertNotNil(t *testing.T, x interface{}, msg string) {
	assertX(t, x != nil, msg)
}

func assertEquals(t *testing.T, a, b interface{}) {
	assertX(t, a == b, fmt.Sprintf("%+v != %+v", a, b))
}

func assertByteEquals(t *testing.T, a, b []byte) {
	assertX(t, bytes.Equal(a, b), fmt.Sprintf("%+v != %+v", hex.EncodeToString(a), hex.EncodeToString(b)))
}

func assertNotByteEquals(t *testing.T, a, b []byte) {
	assertX(t, !bytes.Equal(a, b), fmt.Sprintf("%+v == %+v", hex.EncodeToString(a), hex.EncodeToString(b)))
}

/* END STOLEN FROM MINT. */
