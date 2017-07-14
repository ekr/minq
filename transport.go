package minq

import ()

// Interface for an object to send packets. Each Transport
// is bound to some particular remote address (or in testing
// we just use a mock which sends the packet into a queue).
type Transport interface {
	Send(p []byte) error
}
