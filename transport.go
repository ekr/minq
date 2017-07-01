package minq

import (
	"fmt"
)

var ErrorWouldBlock = fmt.Errorf("Would have blocked")

type Transport interface {
	Send(p []byte) error
}
