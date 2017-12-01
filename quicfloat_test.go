/*
 * Based of the "half" package. See https://github.com/h2so5/half
 */

package minq

import (
	"math"
	"testing"
)

func getFloatTable() map[QuicFloat16]float32 {
	table := map[QuicFloat16]float32{
		0x3c00: 1,
		0x4000: 2,
		0xc000: -2,
		0x7bfe: 65472,
		0x7bff: 65504,
		0xfbff: -65504,
		0x0000: 0,
		0x8000: float32(math.Copysign(0, -1)),
		0x7c00: float32(math.Inf(1)),
		0xfc00: float32(math.Inf(-1)),
		0x5b8f: 241.875,
		0x48c8: 9.5625,
	}
	return table
}

func TestFloat32(t *testing.T) {
	for k, v := range getFloatTable() {
		f := k.Float32()
		if f != v {
			t.Errorf("ToFloat32(%d) = %f, want %f.", k, f, v)
		}
	}
}

func TestNewQuicFloat16(t *testing.T) {
	for k, v := range getFloatTable() {
		i := NewQuicFloat16(v)
		if i != k {
			t.Errorf("FromFloat32(%f) = %d, want %d.", v, i, k)
		}
	}
}
