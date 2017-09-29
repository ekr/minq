package minq

import ()

type sendStream struct {
	baseStream
	blocked bool
}

type SendStream struct {
	c *Connection
	sendStream
}

func newSendStreamInt(id uint32, log loggingFunction, maxStreamData uint64) *sendStream {
	return &sendStream{
		baseStream{
			kStreamStateOpen,
			id,
			log,
			0,
			nil,
			maxStreamData,
		},
		false,
	}
}

func newSendStream(c *Connection, id uint32, maxStreamData uint64) *SendStream {
	return &SendStream{
		c,
		*newSendStreamInt(id, c.log, maxStreamData),
	}
}

func (s *sendStream) closePending() bool {
	if len(s.chunks) == 0 {
		return false
	}
	return s.chunks[len(s.chunks)-1].last
}

func (s *sendStream) queue(payload []byte) {
	s.log(logTypeStream, "Stream %v queueing %v bytes", s.id, len(payload))
	s.chunks = append(s.chunks, streamChunk{s.offset, false, payload})
	s.offset += uint64(len(payload))
}

// Push out all the frames permitted by flow control.
func (s *sendStream) outputWritable() ([]streamChunk, bool) {
	s.log(logTypeStream, "outputWritable(stream=%d, current max offset=%d)", s.id, s.maxStreamData)
	out := make([]streamChunk, 0)
	blocked := false
	for len(s.chunks) > 0 {
		ch := s.chunks[0]
		if ch.offset+uint64(len(ch.data)) > s.maxStreamData {
			blocked = true
			s.log(logTypeFlowControl, "stream %d is blocked, s.maxStreamData=%d, chunk(offset=%d, len=%d)", s.id, s.maxStreamData, ch.offset, len(ch.data))
			break
		}
		out = append(out, ch)
		s.chunks = s.chunks[1:]
		if ch.last {
			s.close()
		}
	}

	if s.blocked {
		// Don't return blocked > once
		blocked = false
	} else {
		s.blocked = blocked
	}
	return out, blocked
}

func (s *sendStream) processMaxStreamData(offset uint64) error {
	if offset < s.maxStreamData {
		return nil
	}
	s.log(logTypeFlowControl, "Stream=%d now has max send offset=%d", s.id, offset)
	s.maxStreamData = offset

	return nil
}

func (s *sendStream) write(data []byte) error {
	if s.closePending() || s.state == kStreamStateClosed {
		return ErrorStreamIsClosed
	}

	for len(data) > 0 {
		tocpy := 1024
		if tocpy > len(data) {
			tocpy = len(data)
		}
		s.chunks = append(s.chunks, streamChunk{s.offset, false, data[:tocpy]})
		s.offset += uint64(tocpy)
		data = data[tocpy:]
	}

	return nil
}

func (s *sendStream) outstandingQueuedBytes() (n int) {
	for _, ch := range s.chunks {
		n += len(ch.data)
	}

	return
}

func (s *SendStream) Write(data []byte) (int, error) {
	if s.c.isClosed() {
		return 0, ErrorConnIsClosed
	}

	err := s.write(data)
	if err != nil {
		return 0, err
	}

	s.c.sendQueued(false)

	return len(data), nil
}

func (s *SendStream) Close() {
	s.log(logTypeStream, "Closing stream %d", s.id)
	s.chunks = append(s.chunks, streamChunk{s.offset, true, nil})
	s.c.sendQueued(false)
}

func (s *SendStream) Reset(error ErrorCode) error {
	s.close()
	f := newRstStreamFrame(s.id, error, s.offset)
	s.c.queueFrame(&s.c.outputProtectedQ, f)
	s.c.sendQueued(false)
	return nil
}
