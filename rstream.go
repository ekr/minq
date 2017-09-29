package minq

import (
	"encoding/hex"
)

type recvStream struct {
	baseStream
	blocked bool
}

type RecvStream struct {
	c *Connection
	recvStream
}

func newRecvStreamInt(id uint32, log loggingFunction, maxStreamData uint64) *recvStream {
	return &recvStream{
		baseStream{
			kStreamStateOpen,
			id,
			log,
			0,
			nil,
			maxStreamData,
			false,
			0,
		},
		false,
	}
}

func newRecvStream(c *Connection, id uint32, maxStreamData uint64) *RecvStream {
	return &RecvStream{
		c,
		*newRecvStreamInt(id, c.log, maxStreamData),
	}
}

// TODO(ekr@rtfm.com): This isn't efficient in the case where the chunk
// is the last one.
func (s *recvStream) newFrameData(offset uint64, last bool, payload []byte) bool {
	s.log(logTypeStream, "New data on stream %d, offset=%d, len=%d", s.id, offset, len(payload))
	if s.state == kStreamStateClosed {
		return false
	}
	s.log(logTypeTrace, "Stream payload %v", hex.EncodeToString(payload))
	c := streamChunk{offset, last, dup(payload)}

	var i int
	for i = 0; i < len(s.chunks); i++ {
		if offset < s.chunks[i].offset {
			break
		}
	}

	// This may not be the fastest way to do this splice.
	tmp := make([]streamChunk, 0, len(s.chunks)+1)
	tmp = append(tmp, s.chunks[:i]...)
	tmp = append(tmp, c)
	tmp = append(tmp, s.chunks[i:]...)
	s.chunks = tmp
	s.log(logTypeStream, "Stream now has %v chunks", len(s.chunks))

	return s.chunks[0].offset <= s.offset
}

func (s *recvStream) readAll() []byte {
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

// Read from a stream into a buffer. Up to |len(b)| bytes will be read,
// and the number of bytes returned is in |n|.
func (s *recvStream) read(b []byte) (int, error) {
	s.log(logTypeStream, "Reading from stream %v requested len = %v current chunks=%v", s.id, len(b), len(s.chunks))

	read := 0

	for len(b) > 0 {
		if len(s.chunks) == 0 {
			break
		}

		chunk := s.chunks[0]

		// We have a gap.
		if chunk.offset > s.offset {
			s.log(logTypeStream, "Gap: %d > %d", chunk.offset, s.offset)
			break
		}

		// Remove leading bytes
		remove := s.offset - chunk.offset
		if remove > uint64(len(chunk.data)) {
			// Nothing left.
			s.chunks = s.chunks[1:]
			continue
		}

		chunk.offset += remove
		chunk.data = chunk.data[remove:]

		// Now figure out how much we can read
		n := copy(b, chunk.data)
		chunk.data = chunk.data[n:]
		chunk.offset += uint64(n)
		s.offset += uint64(n)
		b = b[n:]
		read += n

		// This chunk is empty.
		if len(chunk.data) == 0 {
			s.chunks = s.chunks[1:]
			if chunk.last {
				s.close()
			}
		}
	}

	// If we have read no data, say we would have blocked.
	if read == 0 {
		if s.state == kStreamStateClosed {
			return 0, ErrorStreamIsClosed
		}
		return 0, ErrorWouldBlock
	}
	s.log(logTypeStream, "Successfuly read %d bytes", read)
	return read, nil
}

// Return the last received byte, even if it's out of order.
func (s *recvStream) lastReceivedByte() uint64 {
	mx := s.offset

	for _, ch := range s.chunks {
		lb := ch.offset + uint64(len(ch.data))
		if lb > mx {
			mx = lb
		}
	}
	return mx
}

func (s *RecvStream) Read(b []byte) (int, error) {
	if s.c.isClosed() {
		return 0, ErrorConnIsClosed
	}

	n, err := s.read(b)
	if err != nil {
		return 0, err
	}

	return n, nil
}
