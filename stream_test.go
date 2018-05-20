package minq

import (
	"fmt"
	"io"
	"runtime"
	"testing"
)

type testStreamFixture struct {
	t    *testing.T
	name string
	log  loggingFunction
	r    *recvStreamBase
	w    *sendStreamBase
	b    []byte
}

func (f *testStreamFixture) read() {
	assertX(f.t, f.r.readable, "stream should be readable")
	f.b = make([]byte, 1024)
	n, err := f.r.read(f.b)
	assertNotError(f.t, err, "Should be able to read bytes")
	f.b = f.b[:n]
	assertX(f.t, f.r.clearReadable(), "should have been readable")
}

func (f *testStreamFixture) readExpectError(exerr error) {
	f.b = make([]byte, 1024)
	n, err := f.r.read(f.b)
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

	fc := flowControl{false, 2048, 0}
	return &testStreamFixture{
		t:    t,
		name: name,
		log:  log,
		r:    &recvStreamBase{streamCommon: streamCommon{log: log, fc: fc}},
		w:    &sendStreamBase{streamCommon: streamCommon{log: log, fc: fc}},
		b:    nil,
	}
}

func TestStreamInputOneChunk(t *testing.T) {
	f := newTestStreamFixture(t)
	err := f.r.newFrameData(0, false, kTestString1, &flowControl{false, 2048, 0})
	assertNotError(t, err, "Data should be accepted")
	assertEquals(t, f.r.fc.used, uint64(len(kTestString1)))
	assertEquals(t, RecvStreamStateRecv, f.r.state)
	f.read()
	assertByteEquals(t, f.b, kTestString1)
}

func TestStreamInputTwoChunks(t *testing.T) {
	f := newTestStreamFixture(t)
	err := f.r.newFrameData(0, false, kTestString1, &flowControl{false, 2048, 0})
	assertNotError(t, err, "Data should be accepted")
	assertEquals(t, f.r.fc.used, uint64(len(kTestString1)))
	f.read()
	assertByteEquals(t, f.b, kTestString1)
	err = f.r.newFrameData(uint64(len(kTestString1)), false, kTestString2, &flowControl{false, 2048, 0})
	assertEquals(t, f.r.fc.used, uint64(len(kTestString1)+len(kTestString2)))
	f.read()
	assertByteEquals(t, f.b, kTestString2)
}

func TestStreamInputCoalesceChunks(t *testing.T) {
	f := newTestStreamFixture(t)
	err := f.r.newFrameData(0, false, kTestString1[:2], &flowControl{false, 2048, 0})
	assertNotError(t, err, "data should be accepted")
	err = f.r.newFrameData(2, false, kTestString1[2:], &flowControl{false, 2048, 0})
	assertNotError(t, err, "data should be accepted")
	f.read()
	assertByteEquals(t, f.b, kTestString1)
}

func TestStreamInputChunksOverlap(t *testing.T) {
	f := newTestStreamFixture(t)
	err := f.r.newFrameData(0, false, kTestString1[:2], &flowControl{false, 2048, 0})
	assertNotError(t, err, "data should be accepted")
	err = f.r.newFrameData(0, false, kTestString1, &flowControl{false, 2048, 0})
	assertNotError(t, err, "data should be accepted")
	f.read()
	assertByteEquals(t, f.b, kTestString1)
}

func TestStreamInputTwoChunksWrongOrder(t *testing.T) {
	f := newTestStreamFixture(t)
	err := f.r.newFrameData(2, false, kTestString1[2:], &flowControl{false, 2048, 0})
	assertNotError(t, err, "data should be accepted")
	assertX(t, !f.r.readable, "Stream not should be readable")
	assertEquals(t, f.r.fc.used, uint64(len(kTestString1)))
	f.readExpectError(ErrorWouldBlock)
	err = f.r.newFrameData(0, false, kTestString1[:2], &flowControl{false, 2048, 0})
	assertNotError(t, err, "data should be accepted")
	f.read()
	assertByteEquals(t, f.b, kTestString1)
}

func TestStreamInputChunk1FinChunk2(t *testing.T) {
	f := newTestStreamFixture(t)
	err := f.r.newFrameData(0, true, kTestString1, &flowControl{false, 2048, 0})
	assertNotError(t, err, "data should be accepted")
	assertEquals(t, RecvStreamStateSizeKnown, f.r.state)
	f.read()
	assertByteEquals(t, f.b, kTestString1)
	assertEquals(t, RecvStreamStateDataRead, f.r.state)
	err = f.r.newFrameData(uint64(len(kTestString1)), false, kTestString2, &flowControl{false, 2048, 0})
	assertEquals(t, err, ErrorFlowControlError)
	assertX(t, !f.r.readable, "Stream not be readable")
	f.readExpectError(io.EOF)
}

func TestStreamInputShortFinChunkAfterFin(t *testing.T) {
	f := newTestStreamFixture(t)
	err := f.r.newFrameData(0, true, kTestString1, &flowControl{false, 2048, 0})
	assertNotError(t, err, "data should be accepted")
	assertEquals(t, RecvStreamStateSizeKnown, f.r.state)
	f.read()
	err = f.r.newFrameData(0, true, kTestString1[:2], &flowControl{false, 2048, 0})
	assertNotError(t, err, "overlapping data can be discarded")
}

func TestStreamReadReset(t *testing.T) {
	f := newTestStreamFixture(t)
	err := f.r.handleReset(10)
	assertNotError(t, err, "should accept the reset")
	assertEquals(t, RecvStreamStateResetRecvd, f.r.state)
}

func TestStreamWriteClose(t *testing.T) {
	f := newTestStreamFixture(t)
	f.w.close()
	assertEquals(t, SendStreamStateCloseQueued, f.w.state)
}

func TestStreamIncreaseFlowControl(t *testing.T) {
	f := newTestStreamFixture(t)
	f.w.processMaxStreamData(2050)
	f.w.processMaxStreamData(2000)
	assertEquals(t, uint64(2050), f.w.fc.max)
}

func countChunkLens(chunks []streamChunk) int {
	ct := 0
	for _, ch := range chunks {
		ct += len(ch.data)
	}
	return ct
}

func TestStreamBlockRelease(t *testing.T) {
	f := newTestStreamFixture(t)
	b := make([]byte, 5000)
	connFc := &flowControl{false, uint64(len(b)), 0}
	n, err := f.w.write(b, connFc)
	assertEquals(t, nil, err)
	chunks := f.w.outputWritable()
	assertEquals(t, 2048, countChunkLens(chunks))
	assertEquals(t, 2048, n)
	assertEquals(t, uint64(2048), connFc.used)
	// Calling output writable again returns 0 chunks
	chunks = f.w.outputWritable()
	assertEquals(t, 0, countChunkLens(chunks))

	// Writing again blocks
	_, err = f.w.write(b[n:], connFc)
	assertEquals(t, ErrorWouldBlock, err)

	// Increasing the limit should let us write.
	f.w.processMaxStreamData(8192)
	n, err = f.w.write(b[n:], connFc)
	assertNotError(t, err, "Writing works")
	assertEquals(t, 2952, n)
	assertEquals(t, connFc.max, connFc.used)
	chunks = f.w.outputWritable()
	assertEquals(t, 2952, countChunkLens(chunks))
}
