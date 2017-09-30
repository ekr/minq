package minq

// Interface for the handler object which the Connection will call
// to notify of events on the connection.
type ConnectionHandler interface {
	// The connection has changed state to state |s|
	StateChanged(s State)

	// A new receiving stream has been created (by receiving a frame
	// from the other side. |s| contains the stream.
	NewRecvStream(s *RecvStream)

	// Stream |s| is now readable.
	StreamReadable(s *RecvStream)
}
