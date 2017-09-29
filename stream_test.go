package minq

import (
	"fmt"
	"runtime"
	"testing"
)

type testBaseStreamFixture struct {
	t    *testing.T
	name string
	log  loggingFunction
}

func newTestBaseStreamFixture(t *testing.T) *testBaseStreamFixture {
	pc, _, _, ok := runtime.Caller(1)
	name := "unknown"
	if ok {
		name = runtime.FuncForPC(pc).Name()
	}
	log := func(tag string, format string, args ...interface{}) {
		fullFormat := fmt.Sprintf("%s: %s", name, format)
		logf(tag, fullFormat, args...)
	}

	return &testBaseStreamFixture{
		t,
		name,
		log,
	}
}

type testSendStreamFixture struct {
	testBaseStreamFixture
	s *sendStream
}

func newTestSendStreamFixture(t *testing.T) *testSendStreamFixture {
	b := newTestBaseStreamFixture(t)
	return &testSendStreamFixture{
		*b,
		newSendStreamInt(1, b.log, 2048),
	}
}

func (f *testRecvStreamFixture) read() {
	f.b = make([]byte, 1024)
	n, err := f.s.read(f.b)
	assertNotError(f.t, err, "Should be able to read bytes")
	f.b = f.b[:n]
}

func (f *testRecvStreamFixture) readExpectError(exerr error) {
	f.b = make([]byte, 1024)
	n, err := f.s.read(f.b)
	assertError(f.t, err, "Should not be able to read bytes")
	assertEquals(f.t, exerr, err)
	assertEquals(f.t, 0, n)
}

type testRecvStreamFixture struct {
	testBaseStreamFixture
	s *recvStream
	b []byte
}

func newTestRecvStreamFixture(t *testing.T) *testRecvStreamFixture {
	b := newTestBaseStreamFixture(t)
	return &testRecvStreamFixture{
		*b,
		newRecvStreamInt(1, b.log, 2048),
		nil,
	}
}

var kTestString1 = []byte("abcdef")
var kTestString2 = []byte("ghijkl")

func TestRecvStreamInputOneChunk(t *testing.T) {
	f := newTestRecvStreamFixture(t)
	readable := f.s.newFrameData(0, false, kTestString1)
	assertX(t, readable, "Stream should be readable")
	f.read()
	assertByteEquals(t, f.b, kTestString1)
}

func TestRecvStreamInputTwoChunks(t *testing.T) {
	f := newTestRecvStreamFixture(t)
	readable := f.s.newFrameData(0, false, kTestString1)
	assertX(t, readable, "Stream should be readable")
	f.read()
	assertByteEquals(t, f.b, kTestString1)
	readable = f.s.newFrameData(uint64(len(kTestString1)), false, kTestString2)
	assertX(t, readable, "Stream should be readable")
	f.read()
	assertByteEquals(t, f.b, kTestString2)
}

func TestRecvStreamInputCoalesceChunks(t *testing.T) {
	f := newTestRecvStreamFixture(t)
	readable := f.s.newFrameData(0, false, kTestString1[:2])
	assertX(t, readable, "Stream should be readable")
	readable = f.s.newFrameData(2, false, kTestString1[2:])
	assertX(t, readable, "Stream should be readable")
	f.read()
	assertByteEquals(t, f.b, kTestString1)
}

func TestRecvStreamInputChunksOverlap(t *testing.T) {
	f := newTestRecvStreamFixture(t)
	readable := f.s.newFrameData(0, false, kTestString1[:2])
	assertX(t, readable, "Stream should be readable")
	readable = f.s.newFrameData(0, false, kTestString1)
	assertX(t, readable, "Stream should be readable")
	f.read()
	assertByteEquals(t, f.b, kTestString1)
}

func TestRecvStreamInputTwoChunksWrongOrder(t *testing.T) {
	f := newTestRecvStreamFixture(t)
	readable := f.s.newFrameData(2, false, kTestString1[2:])
	assertX(t, !readable, "Stream not should be readable")
	f.readExpectError(ErrorWouldBlock)
	readable = f.s.newFrameData(0, false, kTestString1[:2])
	assertX(t, readable, "Stream should be readable")
	f.read()
	assertByteEquals(t, f.b, kTestString1)
}

func TestRecvStreamInputChunk1FinChunk2(t *testing.T) {
	f := newTestRecvStreamFixture(t)
	readable := f.s.newFrameData(0, true, kTestString1)
	assertX(t, readable, "Stream should be readable")
	assertEquals(t, kStreamStateOpen, f.s.state)
	f.read()
	assertByteEquals(t, f.b, kTestString1)
	assertEquals(t, kStreamStateClosed, f.s.state)
	readable = f.s.newFrameData(uint64(len(kTestString1)), false, kTestString2)
	assertX(t, !readable, "Stream not be readable")
	f.readExpectError(ErrorStreamIsClosed)
}

func TestSendStreamIncreaseFlowControl(t *testing.T) {
	f := newTestSendStreamFixture(t)
	err := f.s.processMaxStreamData(2050)
	assertEquals(t, nil, err)
}

func countChunkLens(chunks []streamChunk) int {
	ct := 0
	for _, ch := range chunks {
		ct += len(ch.data)
	}
	return ct
}

func TestSendStreamBlockRelease(t *testing.T) {
	f := newTestSendStreamFixture(t)
	b := make([]byte, 5000)
	err := f.s.write(b)
	assertEquals(t, nil, err)
	chunks, blocked := f.s.outputWritable()
	assertEquals(t, 2048, countChunkLens(chunks))
	assertX(t, blocked, "Output should be blocked")
	// Calling output writable again returns 0 chunks
	// and not blocked (so we don't complain twice).
	chunks, blocked = f.s.outputWritable()
	assertX(t, !blocked, "Output is blocked")
	assertEquals(t, 0, countChunkLens(chunks))
	// Increasing the limit should let us write.
	f.s.processMaxStreamData(8192)
	chunks, blocked = f.s.outputWritable()
	assertX(t, !blocked, "Output is not blocked")
	assertEquals(t, 2952, countChunkLens(chunks))
}
