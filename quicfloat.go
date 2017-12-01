/*
 * Based of the "half" package. See https://github.com/h2so5/half
 */

package minq

import "math"

//TODO(ekr@rtfm.com) At the moment this is just a IEEE 754 float16

// A QuicFloat16 represents a 16-bit floating point number.
type QuicFloat16 uint16

// NewQuicFloat16 allocates and returns a new Float16 set to f.
func NewQuicFloat16(f float32) QuicFloat16 {
	i := math.Float32bits(f)
	sign := uint16((i >> 31) & 0x1)
	exp := (i >> 23) & 0xff
	exp16 := int16(exp) - 127 + 15
	frac := uint16(i>>13) & 0x3ff
	if exp == 0 {
		exp16 = 0
	} else if exp == 0xff {
		exp16 = 0x1f
	} else {
		if exp16 > 0x1e {
			exp16 = 0x1f
			frac = 0
		} else if exp16 < 0x01 {
			exp16 = 0
			frac = 0
		}
	}
	f16 := (sign << 15) | uint16(exp16<<10) | frac
	return QuicFloat16(f16)
}

// Float32 returns the float32 representation of f.
func (f QuicFloat16) Float32() float32 {
	sign := uint32((f >> 15) & 0x1)
	exp := (f >> 10) & 0x1f
	exp32 := uint32(exp) + 127 - 15
	if exp == 0 {
		exp32 = 0
	} else if exp == 0x1f {
		exp32 = 0xff
	}
	frac := uint32(f & 0x3ff)
	i := (sign << 31) | (exp32 << 23) | (frac << 13)
	return math.Float32frombits(i)
}
