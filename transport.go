package chip

import (
	"fmt"
)
WouldBlock = fmt.Errorf("Would have blocked")

type Transport interface {
	Send(p []byte) error
	Recv() ([]byte, error)
}
