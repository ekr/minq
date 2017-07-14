package minq

import (
	"fmt"
)

var ErrorWouldBlock = fmt.Errorf("Would have blocked")
var ErrorDestroyConnection = fmt.Errorf("Terminate connection")
var ErrorReceivedVersionNegotiation = fmt.Errorf("Received a version negotiation packet advertising a different version than ours")
