package chip

import (
	"bytes"
	"fmt"
	"reflect"
)

const (
	CodecDefaultSize = ^uintptr(0)
)

func uintEncode(buf *bytes.Buffer, v reflect.Value, encodingSize uintptr) error {
	size := v.Type().Size()
	if encodingSize != CodecDefaultSize {
		if encodingSize > size {
			return fmt.Errorf("Requested a length longer than the native type")
		}
		size = encodingSize
	}

	val := v.Uint()
	// Now encode the low-order bytes of the value.
	for b := size; b > 0; b -= 1 {
		buf.WriteByte(byte(val >> ((b - 1) * 8)))
	}

	return nil
}

func arrayEncode(buf *bytes.Buffer, v reflect.Value) error {
	buf.Write(v.Bytes())

	return nil
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
		
		switch (field.Kind()) {
		case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			// Call the length overrider to tell us if we shoud be using a shorter
			// encoding.
			encodingSize := uintptr(CodecDefaultSize)
			lFunc, getLength := reflected.Type().MethodByName(tipe.Name + "__length")
			if getLength {
				length_result := lFunc.Func.Call([]reflect.Value{reflect.ValueOf(i).Elem()})
				encodingSize = uintptr(length_result[0].Uint())
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

	return buf.Bytes(), nil
}

func uintDecode(buf *bytes.Reader, v reflect.Value, encodingSize uintptr) error {
	size := v.Type().Size()
	if encodingSize != CodecDefaultSize {
		if encodingSize > size {
			return fmt.Errorf("Requested a length longer than the native type")
		}
		size = encodingSize
	}

	val := make([]byte, size)
	rv, err := buf.Read(val)
	if err != nil {
		return err
	}
	if rv != int(size) {
		return fmt.Errorf("Not enough bytes in buffer")
	}

	tmp := uint64(0)
	for b := uintptr(0); b < size; b += 1 {
		tmp = (tmp << 8) + uint64(val[b])
	}
	v.SetUint(tmp)

	return nil
}

func arrayDecode(buf *bytes.Reader, v reflect.Value, encodingSize uintptr) error {
	if encodingSize == CodecDefaultSize {
		encodingSize = uintptr(buf.Len())
	}

	val := make([]byte, encodingSize)
	rv, err := buf.Read(val)
	if err != nil {
		return err
	}
	if rv != int(encodingSize) {
		return fmt.Errorf("Not enough bytes in buffer")
	}

	v.SetBytes(val)
	return nil
}


// Decode all the fields of a struct from a bytestring. Takes
// a pointer to the struct to fill in
func decode(i interface{}, data []byte) (err error) {
	buf := bytes.NewReader(data)
	var res error
	reflected := reflect.ValueOf(i).Elem()
	fields := reflected.NumField()

	for j := 0; j < fields; j += 1 {
		field := reflected.Field(j)
		tipe := reflected.Type().Field(j)


		// Call the length overrider to tell us if we should be using a shorter
		// encoding.
		encodingSize := uintptr(CodecDefaultSize)
		lFunc, getLength := reflected.Type().MethodByName(tipe.Name + "__length")
		if getLength {
			length_result := lFunc.Func.Call([]reflect.Value{reflect.ValueOf(i).Elem()})
			encodingSize = uintptr(length_result[0].Uint())
		}

		switch (field.Kind()) {
		case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			res = uintDecode(buf, field, encodingSize)
		case reflect.Array, reflect.Slice:
			res = arrayDecode(buf, field, encodingSize)
		default:
			return fmt.Errorf("Unknown type")
		}
		if res != nil {
			return res
		}
	}

	
	return nil
}
