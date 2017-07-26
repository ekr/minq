package minq

import (
	"os"
)

var (
	debug = checkDebug()
)

func checkDebug() bool {
	if os.Getenv("MINQ_DEBUG") == "true" {
		return true
	}
	return false
}

func assert(t bool) {
	if !t {
		panic("Assert")
	}
}

func dup(b []byte) []byte {
	ret := make([]byte, len(b))
	copy(ret, b)
	return ret
}
