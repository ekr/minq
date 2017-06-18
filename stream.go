package minq

import (
	"encoding/hex"
)

type streamChunk struct {
	offset uint64
	data   []byte
	pns    []uint64 // The packet numbers where we sent this.
}

type stream struct {
	c           *Connection
	id          uint32
	writeOffset uint64
	readOffset  uint64
	in          []streamChunk
	out         []streamChunk
}

func (s *stream) readAll() []byte {
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

func (s *stream) newFrameData(offset uint64, payload []byte) {
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
}

func (s *stream) send(payload []byte) {
	s.out = append(s.out, streamChunk{s.writeOffset, dup(payload), nil})
	s.writeOffset += uint64(len(payload))
}

func (s *stream) removeAckedChunks(pn uint64) {
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

func (s *stream) outstandingQueuedBytes() (n int) {
	for _, ch := range s.out {
		n += len(ch.data)
	}

	return
}

// Write bytes to a stream.
func (s *stream) Write(b []byte) {
	s.send(b)
	s.c.sendQueued()
}
