package minq

import (
	"encoding/hex"
)
type streamChunk struct {
	offset uint64
	data []byte
	pns []uint64  // The packet numbers where we sent this.
}

type stream struct {
	id uint32
	writeOffset uint64
	readOffset uint64
	in []streamChunk
	out []streamChunk
}

func (s *stream) readAll() []byte {
	logf(logTypeConnection, "stream readAll() %d chunks", len(s.in))
	ret := make([]byte, 0) // Arbitrary

	for i, b := range(s.in) {
		logf(logTypeConnection, "Next packet has offset %v, readOffset=%v", b.offset, s.readOffset)
		if b.offset > s.readOffset {
			break
		}

		s.in = s.in[i+1:]
		if s.readOffset < (b.offset + uint64(len(b.data))) {
			c := b.data[s.readOffset - b.offset:]
			s.readOffset += uint64(len(c))
			ret = append(ret, c...)
		}
	}
	
	return ret
}

func (s *stream) newFrameData(offset uint64, payload []byte) {
	logf(logTypeConnection, "Receiving stream with offset=%v, length=%v", offset, len(payload))
	logf(logTypeTrace, "Stream payload %v", hex.EncodeToString(payload))
	c := &streamChunk{offset, dup(payload), nil}

	var i int
	for i = 0; i < len(s.in); i ++ {
		if offset >= s.in[i].offset {
			break
		}
	}

	tmp := append(s.in[:i], *c)
	tmp = append(tmp, s.in[i:]...)

	s.in = tmp
	logf(logTypeConnection, "Stream now has %v chunks", len(s.in))
}

func (s *stream) send(payload []byte) {
	s.out = append(s.out, streamChunk{s.writeOffset, dup(payload), nil})
	s.writeOffset += uint64(len(payload))
}
