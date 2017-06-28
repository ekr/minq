package minq

import ()

type frameType uint8

const (
	kFrameTypePadding         = frameType(0x0)
	kFrameTypeRstStream       = frameType(0x1)
	kFrameTypeConnectionClose = frameType(0x2)
	kFrameTypeGoaway          = frameType(0x3)
	kFrameTypeMaxData         = frameType(0x4)
	kFrameTypeMaxStreamData   = frameType(0x5)
	kFrameTypeMaxStreamId     = frameType(0x6)
	kFrameTypePing            = frameType(0x7)
	kFrameTypeBlocked         = frameType(0x8)
	kFrameTypeStreamBlocked   = frameType(0x9)
	kFrameTypeStreamIdNeeded  = frameType(0xa)
	kFrameTypeNewConnectionId = frameType(0xb)
	kFrameTypeAck             = frameType(0xa0)
	kFrameTypeStream          = frameType(0xc0)
)

const (
	kFrameTypeFlagF = frameType(0x40)
	kFrameTypeFlagD = frameType(0x01)
)

type innerFrame interface {
	getType() frameType
}

type frame struct {
	stream  uint32
	f       innerFrame
	encoded []byte
}

// Encode internally if not already encoded.
func (f *frame) encode() error {
	if f.encoded != nil {
		return nil
	}
	var err error
	f.encoded, err = encode(f.f)
	logf(logTypeFrame, "Frame encoded, total length=%v", len(f.encoded))
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
	Typ        frameType
	StreamId   uint32
	Offset     uint64
	DataLength uint16
	Data       []byte
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
	val := (f.Typ >> 3) & 0x03
	return lengths[val]
}

func (f streamFrame) Offset__length() uintptr {
	lengths := []uintptr{0, 2, 4, 8}
	val := (f.Typ >> 1) & 0x03
	return lengths[val]
}

func (f streamFrame) Data__length() uintptr {
	if f.DataLength__length() == 0 {
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
			// Set all of SSOO to 1
			kFrameTypeStream | 0x1e | kFrameTypeFlagD,
			uint32(stream),
			offset,
			uint16(len(data)),
			dup(data),
		},
		nil,
	}
}

type ackBlock struct {
	Gap    uint8
	Length uint64
}

type ackFrame struct {
	Type                frameType
	NumBlocks           uint8
	NumTS               uint8
	LargestAcknowledged uint64
	AckDelay            uint16
	FirstAckBlockLength uint64
	AckBlockSection     []byte
	TimestampSection    []byte
}

func (f ackFrame) getType() frameType {
	return kFrameTypeAck
}

func (f ackFrame) NumBlocks__length() uintptr {
	if f.Type&0x10 == 0 {
		return 0
	}
	return 1
}

func ackFieldsLength(b byte) uintptr {
	return []uintptr{1, 2, 4, 6}[b]
}

func (f ackFrame) LargestAcknowledged__length() uintptr {
	return ackFieldsLength((byte(f.Type) >> 2) & 0x3)
}

func (f ackFrame) FirstAckBlockLength__length() uintptr {
	return ackFieldsLength(byte(f.Type) & 0x3)
}

func (f ackFrame) AckBlockSection__length() uintptr {
	return uintptr(f.NumBlocks) * (1 + f.FirstAckBlockLength__length())
}

func (f ackFrame) TimestampSection__length() uintptr {
	return uintptr(f.NumTS * 5)
}

func newAckFrame(rs []ackRange) (*frame, error) {
	logf(logTypeFrame, "Making ACK frame")
	var f ackFrame

	f.Type = kFrameTypeAck | 0xb
	if len(rs) > 1 {
		f.Type |= 0x10
		f.NumBlocks = uint8(len(rs))
	}
	f.LargestAcknowledged = rs[len(rs)-1].lastPacket
	f.FirstAckBlockLength = rs[len(rs)-1].count - 1
	last := f.LargestAcknowledged - f.FirstAckBlockLength
	// TODO(ekr@rtfm.com): Fill in any of the timestamp stuff.
	f.AckDelay = 0
	f.NumTS = 0
	f.TimestampSection = nil

	for i := 1; i < len(rs); i++ {
		gap := last - rs[i].lastPacket
		assert(gap < 256) // TODO(ekr@rtfm.com): handle this.
		b := &ackBlock{
			uint8(last - rs[i].lastPacket),
			rs[i].count,
		}
		last = rs[i].lastPacket - rs[i].count + 1
		encoded, err := encode(&b)
		if err != nil {
			return nil, err
		}
		f.AckBlockSection = append(f.AckBlockSection, encoded...)
	}

	return &frame{0, &f, nil}, nil
}

type goawayFrame struct {
	LargestClientStreamId uint32
	LargestServerStreamId uint32
}

func (f goawayFrame) getType() frameType {
	return kFrameTypeGoaway
}

type connectionCloseFrame struct {
	ErrorCode          uint32
	ReasonPhraseLength uint16
	ReasonPhrase       []byte
}

func (f connectionCloseFrame) getType() frameType {
	return kFrameTypeConnectionClose
}

func decodeFrame(data []byte) (uintptr, *frame, error) {
	var inner innerFrame
	t := data[0]
	logf(logTypeFrame, "Frame type byte %v", t)
	switch {
	case t == uint8(kFrameTypePadding):
		inner = &paddingFrame{}
	case t == uint8(kFrameTypeGoaway):
		inner = &goawayFrame{}
	case t >= uint8(kFrameTypeAck) && t <= 0xbf:
		inner = &ackFrame{}
	case t >= uint8(kFrameTypeStream):
		inner = &streamFrame{}
	default:
		panic("Unknown frame type") // TODO(ekr@rtfm.com): implement the others in the spec.
	}

	n, err := decode(inner, data)
	if err != nil {
		return 0, nil, err
	}

	return n, &frame{0, inner, data[:n]}, nil
}
