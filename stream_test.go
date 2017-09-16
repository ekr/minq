package minq

import (
	"fmt"
	"runtime"
	"testing"
)

type testStreamFixture struct {
	t    *testing.T
	name string
	log  loggingFunction
	s    stream
	b    []byte
}

func (f *testStreamFixture) read() {
	f.b = make([]byte, 1024)
	n, err := f.s.read(f.b)
	assertNotError(f.t, err, "Should be able to read bytes")
	f.b = f.b[:n]
}

func (f *testStreamFixture) readExpectError(exerr error) {
	f.b = make([]byte, 1024)
	n, err := f.s.read(f.b)
	assertError(f.t, err, "Should not be able to read bytes")
	assertEquals(f.t, exerr, err)
	assertEquals(f.t, 0, n)
}

var kTestString1 = []byte("abcdef")
var kTestString2 = []byte("ghijkl")

func newTestStreamFixture(t *testing.T) *testStreamFixture {
	pc, _, _, ok := runtime.Caller(1)
	name := "unknown"
	if ok {
		name = runtime.FuncForPC(pc).Name()
	}
	log := func(tag string, format string, args ...interface{}) {
		fullFormat := fmt.Sprintf("%s: %s", name, format)
		logf(tag, fullFormat, args...)
	}

	return &testStreamFixture{
		t,
		name,
		log,
		newStreamInt(0, kStreamStateOpen, log),
		nil,
	}
}

func TestStreamInputOneChunk(t *testing.T) {
	f := newTestStreamFixture(t)
	readable := f.s.newFrameData(0, false, kTestString1)
	assertX(t, readable, "Stream should be readable")
	f.read()
	assertByteEquals(t, f.b, kTestString1)
}

func TestStreamInputTwoChunks(t *testing.T) {
	f := newTestStreamFixture(t)
	readable := f.s.newFrameData(0, false, kTestString1)
	assertX(t, readable, "Stream should be readable")
	f.read()
	assertByteEquals(t, f.b, kTestString1)
	readable = f.s.newFrameData(uint64(len(kTestString1)), false, kTestString2)
	assertX(t, readable, "Stream should be readable")
	f.read()
	assertByteEquals(t, f.b, kTestString2)
}

func TestStreamInputCoalesceChunks(t *testing.T) {
	f := newTestStreamFixture(t)
	readable := f.s.newFrameData(0, false, kTestString1[:2])
	assertX(t, readable, "Stream should be readable")
	readable = f.s.newFrameData(2, false, kTestString1[2:])
	assertX(t, readable, "Stream should be readable")
	f.read()
	assertByteEquals(t, f.b, kTestString1)
}

func TestStreamInputChunksOverlap(t *testing.T) {
	f := newTestStreamFixture(t)
	readable := f.s.newFrameData(0, false, kTestString1[:2])
	assertX(t, readable, "Stream should be readable")
	readable = f.s.newFrameData(0, false, kTestString1)
	assertX(t, readable, "Stream should be readable")
	f.read()
	assertByteEquals(t, f.b, kTestString1)
}

func TestStreamInputTwoChunksWrongOrder(t *testing.T) {
	f := newTestStreamFixture(t)
	readable := f.s.newFrameData(2, false, kTestString1[2:])
	assertX(t, !readable, "Stream not should be readable")
	f.readExpectError(ErrorWouldBlock)
	readable = f.s.newFrameData(0, false, kTestString1[:2])
	assertX(t, readable, "Stream should be readable")
	f.read()
	assertByteEquals(t, f.b, kTestString1)
}

func TestStreamInputChunk1FinChunk2(t *testing.T) {
	f := newTestStreamFixture(t)
	readable := f.s.newFrameData(0, true, kTestString1)
	assertX(t, readable, "Stream should be readable")
	assertEquals(t, kStreamStateOpen, f.s.state)
	f.read()
	assertByteEquals(t, f.b, kTestString1)
	assertEquals(t, kStreamStateHCRemote, f.s.state)
	readable = f.s.newFrameData(uint64(len(kTestString1)), false, kTestString2)
	assertX(t, !readable, "Stream not be readable")
	f.readExpectError(ErrorStreamIsClosed)
}
