package minq

import (
	"encoding/hex"
)

type streamChunk struct {
	offset uint64
	data   []byte
	pns    []uint64 // The packet numbers where we sent this.
}

// A single QUIC stream.
type Stream struct {
	c           *Connection
	id          uint32
	writeOffset uint64
	readOffset  uint64
	in          []streamChunk
	out         []streamChunk
}

func (s *Stream) readAll() []byte {
	logf(logTypeStream, "stream readAll() %d chunks", len(s.in))
	ret := make([]byte, 0) // Arbitrary

	for i, b := range s.in {
		logf(logTypeStream, "Next packet has offset %v, readOffset=%v", b.offset, s.readOffset)
		if b.offset > s.readOffset {
			break
		}

		s.in = s.in[i+1:]
		if s.readOffset < (b.offset + uint64(len(b.data))) {
			c := b.data[s.readOffset-b.offset:]
			s.readOffset += uint64(len(c))
			ret = append(ret, c...)
		}
	}

	return ret
}

// Add data to a stream. Return true if this is readable now.
func (s *Stream) newFrameData(offset uint64, payload []byte) bool {
	logf(logTypeStream, "%s Receiving stream %v with offset=%v, length=%v", s.c.label(), s.id, offset, len(payload))
	logf(logTypeTrace, "Stream payload %v", hex.EncodeToString(payload))
	c := &streamChunk{offset, dup(payload), nil}

	var i int
	for i = 0; i < len(s.in); i++ {
		if offset >= s.in[i].offset {
			break
		}
	}

	tmp := append(s.in[:i], *c)
	tmp = append(tmp, s.in[i:]...)

	s.in = tmp
	logf(logTypeStream, "Stream now has %v chunks", len(s.in))

	return s.in[0].offset <= s.readOffset
}

func (s *Stream) send(payload []byte) {
	s.out = append(s.out, streamChunk{s.writeOffset, dup(payload), nil})
	s.writeOffset += uint64(len(payload))
}

func (s *Stream) removeAckedChunks(pn uint64) {
	logf(logTypeStream, "Removing ACKed chunks for stream %v, PN=%v, currently %v chunks", s.id, pn, len(s.out))

	for i := int(0); i < len(s.out); {
		remove := false
		ch := s.out[i]
		for _, p := range ch.pns {
			if pn == p {
				remove = true
				break
			}
		}

		if remove {
			logf(logTypeStream, "Removing chunk offset=%v len=%v from stream %v, sent in PN %v", s.out[i].offset, len(s.out[i].data), s.id, pn)
			s.out = append(s.out[:i], s.out[i+1:]...)
		} else {
			i++
		}
		logf(logTypeStream, "Un-acked chunks remaining %v", len(s.out))
	}
}

func (s *Stream) outstandingQueuedBytes() (n int) {
	for _, ch := range s.out {
		n += len(ch.data)
	}

	return
}

// Write bytes to a stream. This function always succeeds, though the
// bytes may end up being buffered.
func (s *Stream) Write(b []byte) (int, error) {
	if s.c.isClosed() {
		return 0, ErrorConnIsClosed
	}
	s.send(b)
	s.c.sendQueued(false)
	return len(b), nil
}

// Read from a stream into a buffer. Up to |len(b)| bytes will be read,
// and the number of bytes returned is in |n|.
func (s *Stream) Read(b []byte) (int, error) {
	if s.c.isClosed() {
		return 0, ErrorConnIsClosed
	}
	logf(logTypeStream, "Reading from stream %v requested len = %v current chunks=%v", s.Id(), len(b), len(s.in))

	read := 0

	for len(b) > 0 {
		if len(s.in) == 0 {
			break
		}

		chunk := s.in[0]

		// We have a gap.
		if chunk.offset > s.readOffset {
			break
		}

		// Remove leading bytes
		remove := s.readOffset - chunk.offset
		if remove > uint64(len(chunk.data)) {
			// Nothing left.
			s.in = s.in[1:]
			continue
		}

		chunk.offset += remove
		chunk.data = chunk.data[remove:]

		// Now figure out how much we can read
		n := copy(b, chunk.data)
		chunk.data = chunk.data[n:]
		chunk.offset += uint64(n)
		s.readOffset += uint64(n)
		b = b[n:]
		read += n

		// This chunk is empty.
		if len(chunk.data) == 0 {
			s.in = s.in[1:]
		}
	}

	// If we have read no data, say we would have blocked.
	if read == 0 {
		return 0, ErrorWouldBlock
	}
	return read, nil
}

// Get the ID of a stream.
func (s *Stream) Id() uint32 {
	return s.id
}
