package minq

import (
	"encoding/hex"
	"fmt"
	"time"
)

type streamChunk struct {
	offset uint64
	last   bool
	data   []byte
	pns    []uint64 // The packet numbers where we sent this.
	time   time.Time
}

type streamState byte

const (
	kStreamStateIdle     = streamState(0)
	kStreamStateOpen     = streamState(1)
	kStreamStateHCLocal  = streamState(2)
	kStreamStateHCRemote = streamState(3)
	kStreamStateClosed   = streamState(4)
)

type direction byte

const (
	kDirSending = direction(1)
	kDirRecving = direction(2)
)

type streamHalf struct {
	s      *stream
	log    loggingFunction
	dir    direction
	closed bool
	offset uint64
	chunks []streamChunk
}

func newStreamHalf(s *stream, log loggingFunction, dir direction) *streamHalf {
	return &streamHalf{
		s,
		log,
		dir,
		false,
		0,
		nil,
	}
}

func (h *streamHalf) label() string {
	if h.dir == kDirRecving {
		return "recv"
	}
	return "send"
}

// TODO(ekr@rtfm.com): This isn't efficient in the case where the chunk
// is the last one, either because we have lost one chunk or because
// we are writing.
func (h *streamHalf) insertSortedChunk(offset uint64, last bool, payload []byte) {
	h.log(logTypeStream, "chunk insert %s stream %v with offset=%v, length=%v (current offset=%v) last=%v", h.label(), h.s.id, offset, len(payload), h.offset, last)
	h.log(logTypeTrace, "Stream payload %v", hex.EncodeToString(payload))
	c := streamChunk{offset, last, dup(payload), nil, time.Unix(0, 0)}

	var i int
	for i = 0; i < len(h.chunks); i++ {
		if offset < h.chunks[i].offset {
			break
		}
	}

	// This may not be the fastest way to do this splice.
	tmp := make([]streamChunk, 0, len(h.chunks)+1)
	tmp = append(tmp, h.chunks[:i]...)
	tmp = append(tmp, c)
	tmp = append(tmp, h.chunks[i:]...)
	h.chunks = tmp
	h.log(logTypeStream, "Stream now has %v chunks", len(h.chunks))
}

// Uses to force the client initial.
func (h *streamHalf) setOffset(offset uint64) {
	assert(h.s.id == 0)
	h.offset = offset
}

// A single QUIC stream (internal)
type stream struct {
	id         uint32
	log        loggingFunction
	state      streamState
	send, recv *streamHalf
}

// A single QUIC stream.
type Stream struct {
	c *Connection
	stream
}

func (s *stream) label() string {
	return fmt.Sprintf("%v", s.id)
}

func (s *stream) readAll() []byte {
	all := make([]byte, 0)
	b := make([]byte, 1024)

	for {
		n, err := s.read(b)
		if err != nil || n == 0 {
			break
		}
		all = append(all, b[:n]...)
	}

	return all
}

// Add data to a stream. Return true if this is readable now.
func (s *stream) newFrameData(offset uint64, last bool, payload []byte) bool {
	s.log(logTypeStream, "New data on stream %d, offset=%d, len=%d", s.id, offset, len(payload))
	if s.recv.closed {
		return false
	}
	s.recv.insertSortedChunk(offset, last, payload)
	return s.recv.chunks[0].offset <= s.recv.offset
}

func (s *stream) queue(payload []byte) error {
	if s.send.closed {
		return ErrorStreamIsClosed
	}
	s.log(logTypeStream, "%v queueing %v bytes", s.label(), len(payload))
	s.send.insertSortedChunk(s.send.offset, false, payload)
	s.send.offset += uint64(len(payload))
	return nil
}

// Uses to force the client initial.
func (s *stream) setReadOffset(offset uint64) {
	assert(s.id == 0)
	s.recv.offset = offset
}

func (s *stream) removeAckedChunks(pn uint64) {
	s.log(logTypeStream, "Removing ACKed chunks for stream %v, PN=%x, currently %v chunks", s.id, pn, len(s.send.chunks))

	for i := int(0); i < len(s.send.chunks); {
		remove := false
		ch := s.send.chunks[i]
		s.log(logTypeStream, "Examining chunk offset=%v, length=%v pns=%x", ch.offset, len(ch.data), ch.pns)
		for _, p := range ch.pns {
			if pn == p {
				remove = true
				break
			}
		}

		if remove {
			s.log(logTypeStream, "Removing chunk offset=%v len=%v from stream %v, sent in PN %v last=%v", s.send.chunks[i].offset, len(s.send.chunks[i].data), s.id, pn, ch.last)
			s.send.chunks = append(s.send.chunks[:i], s.send.chunks[i+1:]...)
			if ch.last {
				s.closeSend()
			}
		} else {
			i++
		}
		s.log(logTypeStream, "Un-acked chunks remaining %v", len(s.send.chunks))
	}
}

func (s *stream) outstandingQueuedBytes() (n int) {
	for _, ch := range s.send.chunks {
		n += len(ch.data)
	}

	return
}

func (s *stream) setState(state streamState) *stream {
	if state == s.state {
		return s
	}

	s.log(logTypeStream, "Setting state of stream %x %v->%v", s.id, s.state, state)
	s.state = state
	return s
}

func (s *stream) openMaybe() *stream {
	if s.state == kStreamStateIdle {
		s.setState(kStreamStateOpen)
	}
	return s
}

func newStreamInt(id uint32, state streamState, log loggingFunction) stream {
	s := stream{
		state: state,
		id:    id,
		log:   log,
	}
	s.send = newStreamHalf(&s, log, kDirSending)
	s.recv = newStreamHalf(&s, log, kDirRecving)
	return s
}

func newStream(c *Connection, id uint32, state streamState) *Stream {
	s := &Stream{
		c,
		newStreamInt(id, state, c.log),
	}
	return s
}

// Write bytes to a stream. This function always succeeds, though the
// bytes may end up being buffered.
func (s *Stream) Write(b []byte) (int, error) {
	if s.c.isClosed() {
		return 0, ErrorConnIsClosed
	}

	err := s.queue(b)
	if err != nil {
		return 0, err
	}

	s.c.sendQueued(false)
	return len(b), nil
}

func (s *stream) closeRecv() {
	switch s.state {
	case kStreamStateClosed, kStreamStateHCRemote:
		return
	case kStreamStateHCLocal:
		s.setState(kStreamStateClosed)
	default:
		s.setState(kStreamStateHCRemote)
	}
	s.recv.closed = true
	s.recv.chunks = nil
}

func (s *stream) closeSend() {
	switch s.state {
	case kStreamStateClosed, kStreamStateHCLocal:
		return
	case kStreamStateHCRemote:
		s.setState(kStreamStateClosed)
	default:
		s.setState(kStreamStateHCLocal)
	}
	s.send.closed = true
	s.send.chunks = nil
}

// Read from a stream into a buffer. Up to |len(b)| bytes will be read,
// and the number of bytes returned is in |n|.
func (s *stream) read(b []byte) (int, error) {
	s.log(logTypeStream, "Reading from stream %v requested len = %v current chunks=%v", s.id, len(b), len(s.recv.chunks))

	read := 0

	for len(b) > 0 {
		if len(s.recv.chunks) == 0 {
			break
		}

		chunk := s.recv.chunks[0]

		// We have a gap.
		if chunk.offset > s.recv.offset {
			break
		}

		// Remove leading bytes
		remove := s.recv.offset - chunk.offset
		if remove > uint64(len(chunk.data)) {
			// Nothing left.
			s.recv.chunks = s.recv.chunks[1:]
			continue
		}

		chunk.offset += remove
		chunk.data = chunk.data[remove:]

		// Now figure out how much we can read
		n := copy(b, chunk.data)
		chunk.data = chunk.data[n:]
		chunk.offset += uint64(n)
		s.recv.offset += uint64(n)
		b = b[n:]
		read += n

		// This chunk is empty.
		if len(chunk.data) == 0 {
			s.recv.chunks = s.recv.chunks[1:]
			if chunk.last {
				s.closeRecv()
			}
		}
	}

	// If we have read no data, say we would have blocked.
	if read == 0 {
		if s.recv.closed {
			return 0, ErrorStreamIsClosed
		}
		return 0, ErrorWouldBlock
	}
	return read, nil
}

func (s *Stream) Read(b []byte) (int, error) {
	if s.c.isClosed() {
		return 0, ErrorConnIsClosed
	}
	return s.read(b)
}

// Get the ID of a stream.
func (s *Stream) Id() uint32 {
	return s.id
}

func (s *Stream) Close() {
	s.send.insertSortedChunk(s.send.offset, true, nil)
	s.c.sendQueued(false)
	s.send.closed = true // Mark closed so future writes fail
}

func (s *Stream) Reset(error ErrorCode) error {
	s.closeSend()
	f := newRstStreamFrame(s.id, error, s.send.offset)
	return s.c.sendPacketNow([]frame{f})
}
