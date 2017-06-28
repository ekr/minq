package minq

import (
	"encoding/hex"
)

type streamChunk struct {
	offset uint64
	data   []byte
	pns    []uint64 // The packet numbers where we sent this.
}

type Stream struct {
	c           *Connection
	id          uint32
	writeOffset uint64
	readOffset  uint64
	in          []streamChunk
	out         []streamChunk
}

func (s *Stream) readAll() []byte {
	logf(logTypeConnection, "stream readAll() %d chunks", len(s.in))
	ret := make([]byte, 0) // Arbitrary

	for i, b := range s.in {
		logf(logTypeConnection, "Next packet has offset %v, readOffset=%v", b.offset, s.readOffset)
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
	logf(logTypeConnection, "Receiving stream with offset=%v, length=%v", offset, len(payload))
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
	logf(logTypeConnection, "Stream now has %v chunks", len(s.in))

	return s.in[0].offset <= s.readOffset
}

func (s *Stream) send(payload []byte) {
	s.out = append(s.out, streamChunk{s.writeOffset, dup(payload), nil})
	s.writeOffset += uint64(len(payload))
}

func (s *Stream) removeAckedChunks(pn uint64) {
	logf(logTypeConnection, "Removing ACKed chunks for stream %v, PN=%v, currently %v chunks", s.id, pn, len(s.out))

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
			logf(logTypeConnection, "Removing chunk offset=%v len=%v from stream %v, sent in PN %v", s.out[i].offset, len(s.out[i].data), s.id, pn)
			s.out = append(s.out[:i], s.out[i+1:]...)
		} else {
			i++
		}
		logf(logTypeConnection, "Un-acked chunks remaining %v", len(s.out))
	}
}

func (s *Stream) outstandingQueuedBytes() (n int) {
	for _, ch := range s.out {
		n += len(ch.data)
	}

	return
}

// Write bytes to a stream.
func (s *Stream) Write(b []byte) {
	s.send(b)
	s.c.sendQueued()
}

// Read from a stream into a buffer.
func (s *Stream) Read(b []byte) (int, error) {
	logf(logTypeConnection, "Reading from stream %v", s.Id())
	if len(s.in) == 0 {
		return 0, WouldBlock
	}
	if s.in[0].offset > s.readOffset {
		return 0, WouldBlock
	}
	n := copy(b, s.in[0].data)
	if n == len(s.in[0].data) {
		s.in = s.in[1:]
	}
	s.readOffset += uint64(n)
	return n, nil
}

// Get the ID of a stream.
func (s *Stream) Id() uint32 {
	return s.id
}
