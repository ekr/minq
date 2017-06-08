package chip

import (
	"fmt"
)

var WouldBlock = fmt.Errorf("Would have blocked")

type Transport interface {
	Send(p []byte) error
	Recv() ([]byte, error)
}
