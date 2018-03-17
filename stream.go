package minq

import (
	"encoding/hex"
	"fmt"
	"io"
)

// SendStreamState is the state of a SendStream
type SendStreamState uint8

// SendStreamState values.  Not all of these are tracked
const (
	SendStreamStateOpen        = SendStreamState(0)
	SendStreamStateSend        = SendStreamState(1)
	SendStreamStateCloseQueued = SendStreamState(2) // Not in the spec
	SendStreamStateDataSent    = SendStreamState(3)
	SendStreamStateResetSent   = SendStreamState(4)
	SendStreamStateDataRecvd   = SendStreamState(5) // Not tracked
	SendStreamStateResetRecvd  = SendStreamState(6) // Not tracked
)

// String produces a nice string from a SendStreamState.
func (s SendStreamState) String() string {
	switch s {
	case SendStreamStateOpen:
		return "SendStreamStateOpen"
	case SendStreamStateSend:
		return "SendStreamStateSend"
	case SendStreamStateCloseQueued:
		return "SendStreamStateCloseQueued"
	case SendStreamStateDataSent:
		return "SendStreamStateDataSent"
	case SendStreamStateResetSent:
		return "SendStreamStateResetSent"
	case SendStreamStateDataRecvd:
		return "SendStreamStateDataRecvd"
	case SendStreamStateResetRecvd:
		return "SendStreamStateResetRecvd"
	default:
		panic("Unknown SendStreamState")
	}
}

// RecvStreamState is the state of a RecvStream
type RecvStreamState uint8

// RecvStreamState values.  Not all of these are tracked.
const (
	RecvStreamStateRecv       = RecvStreamState(0)
	RecvStreamStateSizeKnown  = RecvStreamState(1)
	RecvStreamStateDataRecvd  = RecvStreamState(2) // Not tracked
	RecvStreamStateResetRecvd = RecvStreamState(3)
	RecvStreamStateDataRead   = RecvStreamState(4)
	RecvStreamStateResetRead  = RecvStreamState(5) // Not tracked
)

// String produces a nice string from a RecvStreamState.
func (s RecvStreamState) String() string {
	switch s {
	case RecvStreamStateRecv:
		return "RecvStreamStateRecv"
	case RecvStreamStateSizeKnown:
		return "RecvStreamStateSizeKnown"
	case RecvStreamStateDataRecvd:
		return "RecvStreamStateDataRecvd"
	case RecvStreamStateResetRecvd:
		return "RecvStreamStateResetRecvd"
	case RecvStreamStateDataRead:
		return "RecvStreamStateDataRead"
	case RecvStreamStateResetRead:
		return "RecvStreamStateResetRead"
	default:
		panic("Unknown RecvStreamState")
	}
}

// The structure here is a little convoluted.
//
// There are three primary interfaces: SendStream, RecvStream, and Stream. These
// all implement hasIdentity and one or both (for Stream) of sendStreamMethods
// or recvStreamMethods.
//
// The implementations are layered.
//
// streamCommon is at the bottom, it includes stuff common to sending and receiving.
//
// sendStreamBase and recvStreamBase add sending and receiving functions. These
// know how to send and receive, but don't know about identifiers or
// connections.  This allows them to be tested in isolation.
//
// Those types don't know about connections, so sendStream and recvStream add
// that by mixing in streamWithIdentity. The same applies to stream, which mixes
// both sendStream and recvStream. These include the concrete implementations of
// the interfaces.

type hasIdentity interface {
	Id() uint64
}

type sendStreamMethods interface {
	io.WriteCloser
	Reset(ErrorCode) error
	SendState() SendStreamState
}

type sendStreamPrivateMethods interface {
	setSendState(SendStreamState)
	outstandingQueuedBytes() int
	processMaxStreamData(uint64)
	outputWritable() ([]streamChunk, bool)
}

type recvStreamMethods interface {
	io.Reader
	StopSending(ErrorCode) error
	RecvState() RecvStreamState
}

type recvStreamPrivateMethods interface {
	setRecvState(RecvStreamState)
	handleReset(offset uint64) error
	clearReadable() bool
	newFrameData(uint64, bool, []byte) error
	creditMaxStreamData() (uint64, bool)
}

// SendStream can send.
type SendStream interface {
	hasIdentity
	sendStreamMethods
}

type sendStreamPrivate interface {
	SendStream
	sendStreamPrivateMethods
}

// RecvStream can receive.
type RecvStream interface {
	hasIdentity
	recvStreamMethods
}

type recvStreamPrivate interface {
	RecvStream
	recvStreamPrivateMethods
}

// Stream is both a send and receive stream.
type Stream interface {
	hasIdentity
	sendStreamMethods
	recvStreamMethods
}

type streamPrivate interface {
	Stream
	sendStreamPrivateMethods
	recvStreamPrivateMethods
}

type streamChunk struct {
	offset uint64
	last   bool
	data   []byte
}

func (sc streamChunk) String() string {
	return fmt.Sprintf("chunk(offset=%v, len=%v, last=%v)", sc.offset, len(sc.data), sc.last)
}

type streamCommon struct {
	log    loggingFunction
	offset uint64
	chunks []streamChunk
	fc     flowControl
}

func (s *streamCommon) insertSortedChunk(offset uint64, last bool, payload []byte) {
	c := streamChunk{offset, last, dup(payload)}
	s.log(logTypeStream, "insert %v, current offset=%v", c, s.offset)
	s.log(logTypeTrace, "payload %v", hex.EncodeToString(payload))

	// First check if we can append the new slice at the end
	if nchunks := len(s.chunks); nchunks == 0 || offset > s.chunks[nchunks-1].offset {
		s.chunks = append(s.chunks, c)
	} else {
		// Otherwise find out where it should go
		var i int
		for i = 0; i < nchunks; i++ {
			if offset < s.chunks[i].offset {
				break
			}
		}

		// This may not be the fastest way to do this splice.
		tmp := make([]streamChunk, 0, nchunks+1)
		tmp = append(tmp, s.chunks[:i]...)
		tmp = append(tmp, c)
		tmp = append(tmp, s.chunks[i:]...)
		s.chunks = tmp
	}
	s.log(logTypeStream, "Stream now has %v chunks", len(s.chunks))
}

type sendStreamBase struct {
	streamCommon
	state   SendStreamState
	blocked bool // Have we returned blocked
}

func (s *sendStreamBase) setSendState(state SendStreamState) {
	if state != s.state {
		s.log(logTypeStream, "set state %v->%v", s.state, state)
		s.state = state
	}
}

// SendState returns the current state of the receive stream.
func (s *sendStreamBase) SendState() SendStreamState {
	return s.state
}

func (s *sendStreamBase) queue(payload []byte) error {
	s.log(logTypeStream, "queueing %v bytes", len(payload))
	s.insertSortedChunk(s.offset, false, payload)
	s.offset += uint64(len(payload))
	return nil
}

func (s *sendStreamBase) write(data []byte) error {
	switch s.state {
	case SendStreamStateOpen:
		s.setSendState(SendStreamStateSend)
		// Allow a zero-octet write on a stream that hasn't been opened.
		if len(data) == 0 {
			return s.queue(data)
		}
	case SendStreamStateSend:
		// OK to send
	default:
		return ErrorStreamIsClosed
	}
	for len(data) > 0 {
		tocpy := 1024
		if tocpy > len(data) {
			tocpy = len(data)
		}
		err := s.queue(data[:tocpy])
		if err != nil {
			return err
		}

		data = data[tocpy:]
	}

	return nil
}

func (s *sendStreamBase) outstandingQueuedBytes() int {
	n := 0
	for _, ch := range s.chunks {
		n += len(ch.data)
	}
	return n
}

// Push out all the frames permitted by flow control.
func (s *sendStreamBase) outputWritable() ([]streamChunk, bool) {
	s.log(logTypeStream, "outputWritable, current max offset=%d)", s.fc.max)
	out := make([]streamChunk, 0)
	blocked := false
	for len(s.chunks) > 0 {
		ch := s.chunks[0]
		if ch.offset+uint64(len(ch.data)) > s.fc.max {
			blocked = true
			s.log(logTypeFlowControl, "stream blocked at maxStreamData=%d, chunk(offset=%d, len=%d)", s.fc.max, ch.offset, len(ch.data))
			break
		}
		out = append(out, ch)
		s.chunks = s.chunks[1:]
		if ch.last {
			s.setSendState(SendStreamStateDataSent)
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

func (s *sendStreamBase) processMaxStreamData(offset uint64) {
	s.fc.update(offset)
}

func (s *sendStreamBase) close() {
	switch s.state {
	case SendStreamStateOpen, SendStreamStateSend:
		s.insertSortedChunk(s.offset, true, nil)
		s.setSendState(SendStreamStateCloseQueued)
	default:
		// NOOP
	}
}

type recvStreamBase struct {
	streamCommon
	state        RecvStreamState
	lastReceived uint64
	readable     bool
}

func (s *recvStreamBase) setRecvState(state RecvStreamState) {
	if state != s.state {
		s.log(logTypeStream, "set state %v->%v", s.state, state)
		s.state = state
	}
}

// RecvState returns the current state of the receive stream.
func (s *recvStreamBase) RecvState() RecvStreamState {
	return s.state
}

// clearReadable clears the readable flag and returns true if it was set.
func (s *recvStreamBase) clearReadable() bool {
	r := s.readable
	s.readable = false
	return r
}

// Add data to a stream. Return true if this is readable now.
func (s *recvStreamBase) newFrameData(offset uint64, last bool, payload []byte) error {
	s.log(logTypeStream, "New data offset=%d, len=%d", offset, len(payload))

	end := offset + uint64(len(payload))
	if s.fc.max < s.lastReceived {
		return ErrorFrameFormatError
	}
	if last {
		if end < s.lastReceived {
			return ErrorProtocolViolation
		}
		if s.state == RecvStreamStateRecv {
			s.setRecvState(RecvStreamStateSizeKnown)
		}
	} else if end > s.lastReceived {
		if s.state != RecvStreamStateRecv {
			// We shouldn't be increasing lastReceived in any other state.
			return ErrorProtocolViolation
		}
	} else if end <= s.offset {
		// No new data here.
		return nil
	}
	s.lastReceived = end
	if s.state != RecvStreamStateRecv && s.state != RecvStreamStateSizeKnown {
		// We shouldn't be increasing lastReceived in RecvStreamStateSizeKnown.
		return nil
	}

	s.insertSortedChunk(offset, last, payload)
	if s.chunks[0].offset <= s.offset {
		s.readable = true
	}

	return nil
}

// Read from a stream into a buffer. Up to |len(b)| bytes will be read,
// and the number of bytes returned is in |n|.
func (s *recvStreamBase) read(b []byte) (int, error) {
	s.log(logTypeStream, "Reading len = %v current chunks=%v", len(b), len(s.chunks))

	read := 0

	for len(b) > 0 {
		if len(s.chunks) == 0 {
			break
		}

		chunk := s.chunks[0]

		// We have a gap.
		if chunk.offset > s.offset {
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
				s.setRecvState(RecvStreamStateDataRead)
				s.chunks = nil
				break
			}
		}
	}

	// If we have read no data, say we would have blocked.
	if read == 0 {
		switch s.state {
		case RecvStreamStateRecv, RecvStreamStateSizeKnown:
			return 0, ErrorWouldBlock
		default:
			if s.chunks == nil {
				return 0, io.EOF
			}
			return 0, ErrorStreamIsClosed
		}
	}
	return read, nil
}

func (s *recvStreamBase) handleReset(offset uint64) error {
	switch s.state {
	case RecvStreamStateRecv:
		s.lastReceived = offset
	case RecvStreamStateDataRecvd, RecvStreamStateResetRead:
		panic("we don't use this state")
	case RecvStreamStateSizeKnown, RecvStreamStateDataRead:
		if offset != s.lastReceived {
			return ErrorProtocolViolation
		}
	default:
		panic("unknown state")
	}
	s.setRecvState(RecvStreamStateResetRecvd)
	s.chunks = nil
	return nil
}

func (s *recvStreamBase) creditMaxStreamData() (uint64, bool) {
	remaining := s.fc.max - s.lastReceived
	s.log(logTypeFlowControl, "%d bytes of credit remaining, lastReceived=%d",
		remaining, s.lastReceived)
	credit := false
	if remaining < kInitialMaxStreamData/2 {
		credit = true

		s.fc.credit(kInitialMaxStreamData)
	}

	return s.fc.max, credit
}

// SendStream is a unidirectional stream for sending.
type sendStream struct {
	c  *Connection
	id uint64
	sendStreamBase
}

// Compile-time interface check.
var _ SendStream = &sendStream{}

func newSendStream(c *Connection, id uint64, initialMax uint64) sendStreamPrivate {
	return &sendStream{
		c: c, id: id,
		sendStreamBase: sendStreamBase{
			streamCommon: streamCommon{
				log: newStreamLogger(id, "send", c.log),
				fc:  flowControl{initialMax, 0},
			},
			state:   SendStreamStateOpen,
			blocked: false,
		},
	}
}

// Id returns the id.
func (s *sendStream) Id() uint64 {
	return s.id
}

// Write writes data.
func (s *sendStream) Write(data []byte) (int, error) {
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

// Close makes the stream end cleanly.
func (s *sendStream) Close() error {
	s.close()
	s.c.sendQueued(false)
	return nil
}

// Reset abandons writing on the stream.
func (s *sendStream) Reset(code ErrorCode) error {
	s.setSendState(SendStreamStateResetSent)
	f := newRstStreamFrame(s.id, code, s.offset)
	return s.c.sendFrame(f)
}

// recvStream is the implementation of a unidirectional stream for receiving.
type recvStream struct {
	c  *Connection
	id uint64
	recvStreamBase
}

// Compile-time interface check.
var _ RecvStream = &recvStream{}

func newRecvStream(c *Connection, id uint64, maxStreamData uint64) recvStreamPrivate {
	return &recvStream{
		c: c, id: id,
		recvStreamBase: recvStreamBase{
			streamCommon: streamCommon{
				log: newStreamLogger(id, "recv", c.log),
				fc:  flowControl{maxStreamData, 0},
			},
			state:    RecvStreamStateRecv,
			readable: false,
		},
	}
}

// Id returns the id.
func (s *recvStream) Id() uint64 {
	return s.id
}

// Read implements io.Reader.
func (s *recvStream) Read(b []byte) (int, error) {
	if s.c.isClosed() {
		return 0, io.EOF
	}

	n, err := s.read(b)
	if err != nil {
		return 0, err
	}
	if s.state == RecvStreamStateDataRead {
		s.c.issueStreamIdCredit(streamTypeFromId(s.id, s.c.role))
	}
	return n, nil
}

// StopSending requests a reset.
func (s *recvStream) StopSending(code ErrorCode) error {
	f := newStopSendingFrame(s.id, code)
	return s.c.sendFrame(f)
}

// stream is a bidirectional stream.
type stream struct {
	c  *Connection
	id uint64

	sendStreamPrivate
	recvStreamPrivate
}

// Compile-time interface check.
var _ Stream = &stream{}

func newStream(c *Connection, id uint64, sendMax uint64, recvMax uint64) streamPrivate {
	return &stream{
		sendStreamPrivate: newSendStream(c, id, sendMax),
		recvStreamPrivate: newRecvStream(c, id, recvMax),
	}
}

// Id needs to be overwritten so that the ambiguity between send and receive can be resolved.
func (s *stream) Id() uint64 {
	return s.sendStreamPrivate.Id()
}

type streamType uint8

// These values match the low bits of the stream ID for a client, but the low
// bit is flipped for a server.
const (
	streamTypeBidirectionalLocal   = streamType(0)
	streamTypeBidirectionalRemote  = streamType(1)
	streamTypeUnidirectionalLocal  = streamType(2)
	streamTypeUnidirectionalRemote = streamType(3)
)

func streamTypeFromId(id uint64, role Role) streamType {
	t := id & 3
	if role == RoleServer {
		t ^= 1
	}
	return streamType(t)
}

func (t streamType) suffix(role Role) uint64 {
	suff := uint64(t)
	if role == RoleServer {
		suff ^= 1
	}
	return suff
}

func (t streamType) String() string {
	switch t {
	case streamTypeBidirectionalLocal:
		return "bidirectional local"
	case streamTypeBidirectionalRemote:
		return "bidirectional remote"
	case streamTypeUnidirectionalLocal:
		return "unidirectional local"
	case streamTypeUnidirectionalRemote:
		return "unidirectional remote"
	default:
		panic("unknown stream type")
	}
}

type streamSet struct {
	// t is the type of stream relative to the endpoints role
	t streamType
	// role is the endpoint's role
	role Role
	// max is the maximum number of streams (as opposed to the maximum ID)
	nstreams int
	// typeless array of streams because go doesn't have generics
	streams []hasIdentity
}

func newStreamSet(t streamType, role Role, nstreams int) *streamSet {
	return &streamSet{t, role, nstreams, make([]hasIdentity, 0, nstreams)}
}

func (ss *streamSet) check(id uint64) {
	// If sizeof(int) == sizeof(uint64), then we will never overflow int.
	assert(^uint64(0) == uint64(^uint(0)))
	assert((id & (^uint64(0) >> 2)) == id) // The top bits should be clear.
	assert((id & 3) == ss.t.suffix(ss.role))
}

func (ss *streamSet) index(id uint64) int {
	ss.check(id)
	return int(id >> 2)
}

func (ss *streamSet) id(index int) uint64 {
	assert(index >= 0)
	return uint64(index<<2) | uint64(ss.t.suffix(ss.role))
}

type flowControl struct {
	max  uint64
	used uint64
}

func (fc *flowControl) update(max uint64) {
	if max > fc.max {
		fc.max = max
	}
}

func (fc *flowControl) credit(c uint64) {
	max := ^uint64(0)
	if max-fc.max > c {
		max = fc.max + c
	}
	fc.max = max
}

func (fc *flowControl) take(other *flowControl, amount uint64) uint64 {
	taken := fc.available()
	if taken > other.available() {
		taken = other.available()
	}
	if taken > amount {
		taken = amount
	}
	return taken
}

func (fc *flowControl) available() uint64 {
	return fc.max - fc.used
}

func (ss *streamSet) updateMax(id uint64) {
	ss.nstreams = ss.index(id) + 1
}

func (ss *streamSet) credit(n int) uint64 {
	ss.nstreams += n
	return ss.id(ss.nstreams - 1)
}

func (ss *streamSet) get(id uint64) hasIdentity {
	i := ss.index(id)
	if i >= len(ss.streams) {
		return nil
	}
	return ss.streams[i]
}

type streamSetCtor func(id uint64) hasIdentity

func (ss *streamSet) create(ctor streamSetCtor) hasIdentity {
	i := len(ss.streams)
	if i >= ss.nstreams {
		return nil
	}
	ss.streams = append(ss.streams, ctor(ss.id(i)))
	return ss.streams[i]
}

func (ss *streamSet) ensure(id uint64, ctor streamSetCtor,
	notify func(s hasIdentity)) hasIdentity {
	i := ss.index(id)
	if i >= ss.nstreams {
		return nil
	}
	if i >= len(ss.streams) {
		needed := i - len(ss.streams) + 1
		start := len(ss.streams)
		ss.streams = append(ss.streams, make([]hasIdentity, needed)...)
		for j := start; j < len(ss.streams); j++ {
			s := ctor(ss.id(j))
			ss.check(s.Id())
			ss.streams[j] = s
			notify(ss.streams[j])
		}
	}
	return ss.streams[i]
}

func (ss *streamSet) forEach(f func(hasIdentity)) {
	for _, s := range ss.streams {
		f(s)
	}
}
