package minq

import (
	"fmt"
)

// Return codes.
var ErrorWouldBlock = fmt.Errorf("Would have blocked")
var ErrorDestroyConnection = fmt.Errorf("Terminate connection")
var ErrorReceivedVersionNegotiation = fmt.Errorf("Received a version negotiation packet advertising a different version than ours")

// Protocol errors
type ErrorCode uint32

const (
	kQuicErrorNoError = ErrorCode(0x80000000)
)
