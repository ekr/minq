package chip

type frameType uint8
const (
	kFrameTypePadding = frameType(0x0)
	kFrameTypeRstStream = frameType(0x1)
	kFrameTypeConnectionClose = frameType(0x2)
	kFrameTypeGoaway = frameType(0x3)
	kFrameTypeMaxData = frameType(0x4)
	kFrameTypeMaxStreamData = frameType(0x5)
	kFrameTypeMaxStreamId = frameType(0x6)
	kFrameTypePing = frameType(0x7)
	kFrameTypeBlocked = frameType(0x8)
	kFrameTypeStreamBlocked = frameType(0x9)
	kFrameTypeStreamIdNeeded = frameType(0xa)
	kFrameTypeNewConnectionId = frameType(0xb)
	kFrameTypeAck = frameType(0xa0)
	kFrameTypeStream = frameType(0xc0)
)

const (
	kFrameTypeFlagF = frameType(0x40) 	
	kFrameTypeFlagD= frameType(0x20)
)

type innerFrame interface {
	getType() frameType
}

type frame struct {
	stream uint32
	f innerFrame
	encoded []byte
}

// Encode internally if not already encoded.
func (f *frame) encode() error {
	if f.encoded != nil {
		return nil
	}
	var err error
	f.encoded, err = encode(f.f)
	return err
}

func (f *frame) length() (int, error) {
	err := f.encode()
	if err != nil {            
		return 0, err
	}
	return len(f.encoded), nil
}

// Padding
type paddingFrame struct {
	Typ frameType
}

func (f paddingFrame) getType() frameType {
	return kFrameTypePadding
}

func newPaddingFrame(stream uint32) frame {
	return frame{stream, &paddingFrame{0}, nil}
}

// Stream
type streamFrame struct {
	Typ frameType
	DataLength uint16
	StreamId uint32
	Offset uint64
	Data []byte
}

func (f streamFrame) getType() frameType {
	return kFrameTypeStream
}

func (f streamFrame) DataLength__length() uintptr {
	logf(logTypeFrame, "DataLength__length() called")
	if (f.Typ & kFrameTypeFlagD) == 0 {
		return 0
	}
	logf(logTypeFrame, "DataLength__length() returning 2")	
	return 2
}

func (f streamFrame) StreamId__length() uintptr {
	lengths := []uintptr{1, 2, 3, 4}
	val := (f.Typ >> 2) & 0x03
	return lengths[val]
}


func (f streamFrame) Offset__length() uintptr {
	lengths := []uintptr{0, 2, 4, 8}
	val := (f.Typ) & 0x03
	return lengths[val]
}

func (f streamFrame) Data__length() uintptr {
	if (f.DataLength__length() == 0) {
		return CodecDefaultSize
	}
	return uintptr(f.DataLength)
}

func newStreamFrame(stream uint32, offset uint64, data []byte) frame {
	logf(logTypeFrame, "Creating stream frame with data length=%d", len(data))
	assert(len(data) <= 65535)
	return frame{
		stream,
		&streamFrame{
			// TODO(ekr@tfm.com): One might want to allow non
			// D bit, but not for now.
			kFrameTypeStream | kFrameTypeFlagD,
			uint16(len(data)),
			stream,
			offset,
			dup(data),
		},
		nil,
	}
}




