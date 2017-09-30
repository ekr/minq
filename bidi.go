package minq

// Bidirectional streams: syntactic sugar around unidirectional streams
type Stream struct {
	id   uint32
	send *SendStream
	recv *RecvStream
}

func (s *Stream) Write(data []byte) (int, error) {
	return s.send.Write(data)
}

func (s *Stream) Read(b []byte) (int, error) {
	if s.recv == nil {
		return 0, ErrorWouldBlock
	}
	return s.recv.Read(b)
}

type Connection2Handler interface {
	// The connection has changed state to state |s|
	StateChanged(s State)

	// A new receiving stream has been created (by receiving a frame
	// from the other side. |s| contains the stream.
	NewStream(s *Stream)

	// Stream |s| is now readable.
	StreamReadable(s *Stream)
}

type Connection2 struct {
	Connection
	shim    *connection2ShimHandler
	streams []*Stream // Odd for client originated, even for server.
}

// A shim that implements the ConnectionHandler interface
type connection2ShimHandler struct {
	c2      *Connection2
	handler Connection2Handler
}

func (h *connection2ShimHandler) StateChanged(state State) {
	if h.handler != nil {
		h.handler.StateChanged(state)
	}
}

func (h *connection2ShimHandler) NewRecvStream(s *RecvStream) {
	h.c2.incomingRecvStream(s)
}

func (h *connection2ShimHandler) StreamReadable(s *RecvStream) {
	relatedId, related := s.Related()
	var s2 *Stream

	// The logic here depends on the fact that related is a
	// one-way relationship, with the second-created streams
	// being related to the first-created, but not the other
	// way around.
	if related {
		s2 = h.c2.streams[h.c2.streamId(relatedId, true)]
	} else {
		s2 = h.c2.streams[h.c2.streamId(s.Id(), false)]
	}

	if h.handler != nil {
		h.handler.StreamReadable(s2)
	}
}

// Map stream IDs to the odd/even scheme from -06.
func (c *Connection2) streamId(id uint32, local bool) uint32 {
	id *= 2
	if local == (c.role == RoleClient) {
		id -= 1
	}
	return id
}

func (c *Connection2) saveStream(s *Stream) {
	needed := 1 + s.id - uint32(len(c.streams))
	c.streams = append(c.streams, make([]*Stream, needed)...)
	c.streams[s.id] = s
	c.log(logTypeBidi, "Creating new bidi stream id=%d", s.id)
}

func (c *Connection2) incomingRecvStream(remote *RecvStream) {
	relatedId, related := remote.Related()
	c.log(logTypeBidi, "Incoming remote stream %d related=%v relatedId=%d", remote.Id(), related, relatedId)
	if related {
		// We must already have a stream for this, and the stack enforces this.
		local := c.GetSendStream(relatedId)
		assert(local != nil)
		s := c.streams[c.streamId(local.id, true)]
		// Don't allow many-to-one.
		// TODO(ekr@rtfm.com): In reality, throw an error, but this makes
		// it easier to debug.
		assert(s.recv == nil)
		s.recv = remote
	} else {
		// This is a new stream, so we create our own local stream and
		// pair it with it.
		local := c.CreateRelatedSendStream(remote)
		s := &Stream{
			c.streamId(remote.id, false),
			local,
			remote,
		}
		c.saveStream(s)
		if c.shim.handler != nil {
			c.shim.handler.NewStream(s)
		}
	}
}

func (c *Connection2) CreateStream() *Stream {
	local := c.CreateSendStream()
	s := &Stream{
		c.streamId(local.id, true),
		local,
		nil,
	}
	c.saveStream(s)
	return s
}

func (c *Connection2) GetStream(id uint32) *Stream {
	if id >= uint32(len(c.streams)) {
		return nil
	}
	return c.streams[id]
}

func NewConnection2(trans Transport, role uint8, tls TlsConfig, handler Connection2Handler) *Connection2 {
	shim := &connection2ShimHandler{nil, handler}
	c := &Connection2{
		*NewConnection(trans, role, tls, shim),
		shim,
		nil,
	}
	shim.c2 = c
	return c
}
