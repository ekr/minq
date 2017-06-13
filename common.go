package minq

func assert(t bool) {
	if (!t) {
		panic("Assert")
	}
}

func dup(b []byte) []byte{
	ret := make([]byte, len(b))
	copy(ret, b)
	return ret
}
