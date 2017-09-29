package minq

import ()

type streamChunk struct {
	offset uint64
	last   bool
	data   []byte
}

type streamState byte

const (
	kStreamStateIdle   = streamState(0)
	kStreamStateOpen   = streamState(1)
	kStreamStateClosed = streamState(2)
)

type baseStream struct {
	state         streamState
	id            uint32
	log           loggingFunction
	offset        uint64
	chunks        []streamChunk
	maxStreamData uint64
}

func (s *baseStream) setState(state streamState) {
	if s.state == state {
		return
	}

	s.log(logTypeStream, "Stream %d state %d -> %d", s.id, s.state, state)
	s.state = state
}

// Uses to force the client initial.
func (s *baseStream) setOffset(offset uint64) {
	assert(s.id == 0)
	s.offset = offset
}

func (s *baseStream) close() {
	s.setState(kStreamStateClosed)
	s.chunks = nil
}

// Get the ID of a stream.
func (s *baseStream) Id() uint32 {
	return s.id
}
