package minq

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"unicode"
)

const (
	codecDefaultSize = ^uintptr(0)
)

func uintEncode(buf *bytes.Buffer, v reflect.Value, encodingSize uintptr) error {
	size := v.Type().Size()
	if encodingSize != codecDefaultSize {
		if encodingSize > size {
			return fmt.Errorf("Requested a length longer than the native type")
		}
		size = encodingSize
	}

	uintEncodeInt(buf, v.Uint(), size)
	return nil
}

func uintEncodeInt(buf *bytes.Buffer, val uint64, size uintptr) {
	// Now encode the low-order bytes of the value.
	for b := size; b > 0; b -= 1 {
		buf.WriteByte(byte(val >> ((b - 1) * 8)))
	}
}

// isVarint determines if the field is a varint.  This reads the mint/syntax tag
// for the field, but only supports a simple "varint".
func isVarint(f reflect.StructField) bool {
	return f.Tag.Get("tls") == "varint"
}

func varintEncode(buf *bytes.Buffer, v uint64) {
	switch {
	case v < (uint64(1) << 6):
		uintEncodeInt(buf, v, 1)
	case v < (uint64(1) << 14):
		uintEncodeInt(buf, v|(1<<14), 2)
	case v < (uint64(1) << 30):
		uintEncodeInt(buf, v|(2<<30), 4)
	case v < (uint64(1) << 62):
		uintEncodeInt(buf, v|(3<<62), 8)
	default:
		panic("varint value is too large")
	}
}

func arrayEncode(buf *bytes.Buffer, v reflect.Value) error {
	b := v.Bytes()
	logf(logTypeCodec, "Encoding array length=%d", len(b))
	buf.Write(b)

	return nil
}

// Check to see if fields
func ignoreField(name string) bool {
	return unicode.IsLower(rune(name[0]))
}

// Length specifications are of the form:
//
// lengthbits: "B:L1,L2,...LN
//
// where B is the rightmost bit of the length bits and
// L_n are the various lengths (in bytes) indicated by
// the bit values in sequence. N must be a power of 2
// and the right number of bytes is drawn to compute it.
type lengthSpec struct {
	rightBit uint
	numBits  uint
	values   []int
}

func parseLengthSpecification(spec string) (*lengthSpec, error) {
	spl := strings.Split(spec, ":")
	assert(len(spl) == 2)

	// Rightmost bit.
	p, err := strconv.ParseUint(spl[0], 10, 8)
	if err != nil {
		return nil, err
	}
	bitr := uint(p)
	vals := strings.Split(spl[1], ",")

	// Figure out how many bits we need.
	nvals := int(1)
	var bits int
	for bits = 1; bits <= 8; bits++ {
		nvals <<= 1
		if nvals == len(vals) {
			break
		}
	}
	assert(bits < 9)

	// Now compute the values
	valArr := make([]int, nvals)
	for i, v := range vals {
		valArr[i], err = strconv.Atoi(v)
		if err != nil {
			return nil, err
		}
	}

	return &lengthSpec{
		bitr,
		uint(bits),
		valArr,
	}, nil
}

func computeLengthFromSpec(t byte, f reflect.StructField) uintptr {
	st := f.Tag.Get("lengthbits")
	if st == "" {
		return codecDefaultSize
	}

	spec, err := parseLengthSpecification(st)
	assert(err == nil)

	mask := byte(0)
	bit := uint(0)
	for ; bit < spec.numBits; bit++ {
		mask |= (1 << bit)
	}
	idx := int(t >> (spec.rightBit - 1) & mask)

	return uintptr(spec.values[idx])
}

// Encode all the fields of a struct to a bytestring.
func encode(i interface{}) (ret []byte, err error) {
	var buf bytes.Buffer
	var res error
	reflected := reflect.ValueOf(i).Elem()
	fields := reflected.NumField()

	for j := 0; j < fields; j += 1 {
		field := reflected.Field(j)
		tipe := reflected.Type().Field(j)

		if ignoreField(tipe.Name) {
			continue
		}

		logf(logTypeCodec, "Type name %s Kind=%v", tipe.Name, field.Kind())

		switch field.Kind() {
		case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			// Call the length overrider to tell us if we shoud be using a shorter
			// encoding.
			encodingSize := uintptr(codecDefaultSize)
			lFunc, getLength := reflected.Type().MethodByName(tipe.Name + "__length")
			logf(logTypeCodec, "Looking for length overrider for type %v", tipe.Name)
			if getLength {
				lengthResult := lFunc.Func.Call([]reflect.Value{reflect.ValueOf(i).Elem()})
				encodingSize = uintptr(lengthResult[0].Uint())
				logf(logTypeCodec, "Overriden length to %v", encodingSize)
			}
			if isVarint(tipe) {
				if encodingSize != 0 {
					varintEncode(&buf, field.Uint())
				}
				res = nil
				break
			}

			res = uintEncode(&buf, field, encodingSize)
		case reflect.Array, reflect.Slice:
			res = arrayEncode(&buf, field)
		default:
			return nil, fmt.Errorf("Unknown type")
		}

		if res != nil {
			return nil, res
		}
	}

	ret = buf.Bytes()
	logf(logTypeCodec, "Total encoded length = %v", len(ret))
	return ret, nil
}

func uintDecodeIntBuf(val []byte) uint64 {
	tmp := uint64(0)
	for b := 0; b < len(val); b++ {
		tmp = (tmp << 8) + uint64(val[b])
	}
	return tmp
}

func uintDecodeInt(r io.Reader, size uintptr) (uint64, error) {
	val := make([]byte, size)
	_, err := io.ReadFull(r, val)
	if err != nil {
		return 0, err
	}

	return uintDecodeIntBuf(val), nil
}

func uintDecode(r io.Reader, v reflect.Value, encodingSize uintptr) (uintptr, error) {
	size := v.Type().Size()
	if encodingSize != codecDefaultSize {
		if encodingSize > size {
			return 0, fmt.Errorf("Requested a length longer than the native type")
		}
		size = encodingSize
	}

	tmp, err := uintDecodeInt(r, size)
	if err != nil {
		return 0, err
	}

	v.SetUint(tmp)

	return size, nil
}

func varintDecode(r io.Reader, v reflect.Value) (uintptr, error) {
	p := make([]byte, 8)
	_, err := r.Read(p[:1])
	if err != nil {
		return 0, err
	}

	value := uint64(p[0] & 0x3f)
	extra := uintptr(1<<(p[0]>>6)) - 1
	if extra > 0 {
		tail, err := uintDecodeInt(r, extra)
		if err != nil {
			return 0, err
		}
		value = (value << (8 * extra)) | tail
	}

	v.SetUint(value)
	return 1 + extra, nil
}

func encodeArgs(args ...interface{}) []byte {
	var buf bytes.Buffer
	var res error

	for _, arg := range args {
		reflected := reflect.ValueOf(arg)
		switch reflected.Kind() {
		case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			res = uintEncode(&buf, reflected, codecDefaultSize)
		case reflect.Array, reflect.Slice:
			res = arrayEncode(&buf, reflected)
		default:
			panic(fmt.Sprintf("Unknown type"))
		}
		if res != nil {
			panic(fmt.Sprintf("Encoding error"))
		}
	}

	return buf.Bytes()
}

func arrayDecode(r io.Reader, v reflect.Value, encodingSize uintptr) (uintptr, error) {
	logf(logTypeCodec, "encodingSize = %v", encodingSize)

	val := make([]byte, encodingSize)

	logf(logTypeCodec, "Reading array of size %v", encodingSize)

	// Go will return EOF if you try to read 0 bytes off a closed stream.
	if encodingSize == 0 {
		return 0, nil
	}
	_, err := io.ReadFull(r, val)
	if err != nil {
		return 0, err
	}

	v.SetBytes(val)
	return encodingSize, nil
}

// Decode all the fields of a struct from a bytestring. Takes
// a pointer to the struct to fill in
func decode(i interface{}, data []byte) (uintptr, error) {
	buf := bytes.NewReader(data)
	var res error
	reflected := reflect.ValueOf(i).Elem()
	fields := reflected.NumField()
	bytesread := uintptr(0)

	for j := 0; j < fields; j++ {
		br := uintptr(0)
		field := reflected.Field(j)
		tipe := reflected.Type().Field(j)

		if ignoreField(tipe.Name) {
			continue
		}

		// Call the length overrider to tell us if we should be using a shorter
		// encoding.
		encodingSize := uintptr(codecDefaultSize)
		lFunc, getLength := reflected.Type().MethodByName(tipe.Name + "__length")
		if getLength {
			lengthResult := lFunc.Func.Call([]reflect.Value{reflect.ValueOf(i).Elem()})
			encodingSize = uintptr(lengthResult[0].Uint())
			logf(logTypeCodec, "Length overrider for %s returns %v", tipe.Name, encodingSize)
		}

		switch field.Kind() {
		case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			if isVarint(tipe) && encodingSize != 0 {
				br, res = varintDecode(buf, field)
			} else {
				br, res = uintDecode(buf, field, encodingSize)
			}
		case reflect.Array, reflect.Slice:
			if encodingSize == codecDefaultSize {
				encodingSize = uintptr(buf.Len())
			}
			br, res = arrayDecode(buf, field, encodingSize)
		default:
			return 0, fmt.Errorf("Unknown type")
		}
		if res != nil {
			logf(logTypeCodec, "Error while reading field %v: %v", tipe.Name, res)
			return bytesread, res
		}
		bytesread += br
	}

	return bytesread, nil
}

func backtrace() string {
	bt := string("")
	for i := 1; ; i++ {
		_, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}
		bt = fmt.Sprintf("%v: %d\n", file, line) + bt
	}
	return bt
}
