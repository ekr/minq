package minq

import (
	"fmt"
	"time"
)

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
	kFrameTypeFlagF    = frameType(0x20)
	kFrameTypeFlagD    = frameType(0x01)
	kFrameTypeAckFlagN = frameType(0x10)
)

const (
	maxAckGap = 255
)

type innerFrame interface {
	getType() frameType
	String() string
}

type frame struct {
	stream  uint32
	f       innerFrame
	encoded []byte
	pns     []uint64
	time    time.Time
}

func (f frame) String() string {
	return f.f.String()
}

func newFrame(stream uint32, inner innerFrame) frame {
	return frame{stream, inner, nil, nil, time.Unix(0, 0)}
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

// Decode an arbitrary frame.
func decodeFrame(data []byte) (uintptr, *frame, error) {
	var inner innerFrame
	t := data[0]
	logf(logTypeFrame, "Frame type byte %v", t)
	switch {
	case t == uint8(kFrameTypePadding):
		inner = &paddingFrame{}
	case t == uint8(kFrameTypeRstStream):
		inner = &rstStreamFrame{}
	case t == uint8(kFrameTypeConnectionClose):
		inner = &connectionCloseFrame{}
	case t == uint8(kFrameTypeGoaway):
		inner = &goawayFrame{}
	case t == uint8(kFrameTypeMaxData):
		inner = &maxDataFrame{}
	case t == uint8(kFrameTypeMaxStreamData):
		inner = &maxStreamDataFrame{}
	case t == uint8(kFrameTypeMaxStreamId):
		inner = &maxStreamIdFrame{}
	case t == uint8(kFrameTypePing):
		inner = &pingFrame{}
	case t == uint8(kFrameTypeBlocked):
		inner = &blockedFrame{}
	case t == uint8(kFrameTypeStreamBlocked):
		inner = &streamBlockedFrame{}
	case t == uint8(kFrameTypeStreamIdNeeded):
		inner = &streamIdNeededFrame{}
	case t == uint8(kFrameTypeNewConnectionId):
		inner = &newConnectionIdFrame{}
	case t >= uint8(kFrameTypeAck) && t <= 0xbf:
		inner = &ackFrame{}
	case t >= uint8(kFrameTypeStream):
		inner = &streamFrame{}
	default:
		logf(logTypeConnection, "Unknown frame type %v", t)
		return 0, nil, fmt.Errorf("Received unknown frame type: %v", t)
	}

	n, err := decode(inner, data)
	if err != nil {
		return 0, nil, err
	}

	return n, &frame{0, inner, data[:n], nil, time.Now()}, nil
}

// Frame definitions below this point.

// PADDING
type paddingFrame struct {
	Typ frameType
}

func (f paddingFrame) String() string {
	return "P"
}

func (f paddingFrame) getType() frameType {
	return kFrameTypePadding
}

func newPaddingFrame(stream uint32) frame {
	return newFrame(stream, &paddingFrame{0})
}

// RST_STREAM
type rstStreamFrame struct {
	Type        frameType
	StreamId    uint32
	ErrorCode   uint16
	FinalOffset uint64
}

func (f rstStreamFrame) String() string {
	return fmt.Sprintf("RST_STREAM stream=%x errorCode=%d finalOffset=%x", f.StreamId, f.ErrorCode, f.FinalOffset)
}

func (f rstStreamFrame) getType() frameType {
	return kFrameTypeRstStream
}

func newRstStreamFrame(streamId uint32, errorCode ErrorCode, finalOffset uint64) frame {
	return newFrame(streamId, &rstStreamFrame{
		kFrameTypeRstStream,
		streamId,
		uint16(errorCode),
		finalOffset})

}

// CONNECTION_CLOSE
type connectionCloseFrame struct {
	Type               frameType
	ErrorCode          uint16
	ReasonPhraseLength uint16
	ReasonPhrase       []byte
}

func (f connectionCloseFrame) String() string {
	return fmt.Sprintf("CONNECTION_CLOSE errorCode=%x", f.ErrorCode)
}

func (f connectionCloseFrame) getType() frameType {
	return kFrameTypeConnectionClose
}

func (f connectionCloseFrame) ReasonPhrase__length() uintptr {
	return uintptr(f.ReasonPhraseLength)
}

func newConnectionCloseFrame(errcode ErrorCode, reason string) frame {
	str := []byte(reason)

	return newFrame(0, &connectionCloseFrame{
		kFrameTypeConnectionClose,
		uint16(errcode),
		uint16(len(str)),
		[]byte(str),
	})
}

// GOAWAY
type goawayFrame struct {
	Type                  frameType
	LargestClientStreamId uint32
	LargestServerStreamId uint32
}

func (f goawayFrame) String() string {
	return "GO_AWAY"
}

func (f goawayFrame) getType() frameType {
	return kFrameTypeGoaway
}

func newGoawayFrame(client uint32, server uint32) frame {
	return newFrame(0,
		&goawayFrame{kFrameTypeGoaway, client, server})
}

// MAX_DATA
type maxDataFrame struct {
	Type        frameType
	MaximumData uint64
}

func (f maxDataFrame) String() string {
	return fmt.Sprintf("MAX_DATA %d", f.MaximumData)
}

func (f maxDataFrame) getType() frameType {
	return kFrameTypeMaxData
}

// MAX_STREAM_DATA
type maxStreamDataFrame struct {
	Type              frameType
	StreamId          uint32
	MaximumStreamData uint64
}

func newMaxStreamData(stream uint32, offset uint64) frame {
	return newFrame(stream,
		&maxStreamDataFrame{
			kFrameTypeMaxStreamData,
			stream,
			offset,
		})
}

func (f maxStreamDataFrame) String() string {
	return fmt.Sprintf("MAX_STREAM_DATA stream=%d %d", f.StreamId, f.MaximumStreamData)
}

func (f maxStreamDataFrame) getType() frameType {
	return kFrameTypeMaxStreamData
}

// MAX_STREAM_ID
type maxStreamIdFrame struct {
	Type            frameType
	MaximumStreamId uint32
}

func (f maxStreamIdFrame) String() string {
	return fmt.Sprintf("MAX_STREAM_ID %d", f.MaximumStreamId)
}

func (f maxStreamIdFrame) getType() frameType {
	return kFrameTypeMaxStreamId
}

// PING
type pingFrame struct {
	Type frameType
}

func (f pingFrame) String() string {
	return "PING"
}

func (f pingFrame) getType() frameType {
	return kFrameTypePing
}

// BLOCKED
type blockedFrame struct {
	Type frameType
}

func (f blockedFrame) String() string {
	return "BLOCKED"
}

func (f blockedFrame) getType() frameType {
	return kFrameTypeBlocked
}

// STREAM_BLOCKED
type streamBlockedFrame struct {
	Type     frameType
	StreamId uint32
}

func (f streamBlockedFrame) String() string {
	return "STREAM_BLOCKED"
}

func (f streamBlockedFrame) getType() frameType {
	return kFrameTypeStreamBlocked
}

// STREAM_ID_NEEDED
type streamIdNeededFrame struct {
	Type frameType
}

func (f streamIdNeededFrame) String() string {
	return "STREAM_ID_NEEDED"
}

func (f streamIdNeededFrame) getType() frameType {
	return kFrameTypeStreamIdNeeded
}

// NEW_CONNECTION_ID
type newConnectionIdFrame struct {
	Type         frameType
	Sequence     uint16
	ConnectionId uint64
}

func (f newConnectionIdFrame) String() string {
	return "NEW_CONNECTION_ID"
}

func (f newConnectionIdFrame) getType() frameType {
	return kFrameTypeNewConnectionId
}

// ACK
type ackBlock struct {
	lengthLength uintptr
	Gap          uint8
	Length       uint64
}

func (f ackBlock) Length__length() uintptr {
	return f.lengthLength
}

type ackFrame struct {
	Type                frameType
	NumBlocks           uint8
	LargestAcknowledged uint64
	AckDelay            uint16
	AckBlockLength      uint64
	AckBlockSection     []byte
}

func (f ackFrame) String() string {
	return fmt.Sprintf("ACK numBlocks=%d largestAck=%x", f.NumBlocks, f.LargestAcknowledged)
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
	return []uintptr{1, 2, 4, 8}[b]
}

func (f ackFrame) LargestAcknowledged__length() uintptr {
	return ackFieldsLength((byte(f.Type) >> 2) & 0x3)
}

func (f ackFrame) AckBlockLength__length() uintptr {
	return ackFieldsLength(byte(f.Type) & 0x3)
}

func (f ackFrame) AckBlockSection__length() uintptr {
	return uintptr(f.NumBlocks) * (1 + f.AckBlockLength__length())
}

func newAckFrame(rs ackRanges, left int) (*frame, int, error) {
	if left < 16 {
		return nil, 0, nil
	}
	logf(logTypeFrame, "Making ACK frame %v", rs)

	// See if there is space for any acks, and if there are acks waiting
	maxackblocks := uint8((left - 16) / 5) // We are using 32-byte values for all the variable-lengths
	if maxackblocks > 255 {
		maxackblocks = 255
	}

	// FIRST, fill in the basic info of the ACK frame
	var f ackFrame
	f.Type = kFrameTypeAck | 0xa // 32 bit inner fields.
	f.NumBlocks = 0
	f.LargestAcknowledged = rs[0].lastPacket
	f.AckBlockLength = rs[0].count - 1
	last := f.LargestAcknowledged - f.AckBlockLength
	f.AckDelay = 0

	addedRanges := 1

	// SECOND, add the remaining ACK blocks that fit and that we have
	for (maxackblocks > f.NumBlocks) && (addedRanges < len(rs)) {
		// calculate blocks needed for the next range
		gap := last - rs[addedRanges].lastPacket - 1
		blocksneeded := uint64((gap + (maxAckGap - 1)) / maxAckGap)
		if blocksneeded > uint64(maxackblocks) {
			// break if there is no space
			break
		}

		// place the needed empty blocks
		for i := uint64(0); i < blocksneeded-1; i++ {
			b := &ackBlock{
				4, // Fixed 32-bit width (see 0xa above)
				uint8(maxAckGap),
				0,
			}
			last -= maxAckGap
			encoded, err := encode(b)
			if err != nil {
				return nil, 0, err
			}
			f.Type |= kFrameTypeAckFlagN
			f.NumBlocks += 1
			f.AckBlockSection = append(f.AckBlockSection, encoded...)
		}

		// Now place the actual block
		gap = last - rs[addedRanges].lastPacket - 1
		assert(gap < 256)
		b := &ackBlock{
			4,
			uint8(gap),
			rs[addedRanges].count,
		}
		last = rs[addedRanges].lastPacket - rs[addedRanges].count + 1
		encoded, err := encode(b)
		if err != nil {
			return nil, 0, err
		}
		f.Type |= kFrameTypeAckFlagN
		f.NumBlocks += 1
		f.AckBlockSection = append(f.AckBlockSection, encoded...)

		addedRanges += 1
	}

	ret := newFrame(0, &f)
	return &ret, addedRanges, nil
}

// STREAM
type streamFrame struct {
	Typ        frameType
	StreamId   uint32
	Offset     uint64
	DataLength uint16
	Data       []byte
}

func (f streamFrame) String() string {
	return fmt.Sprintf("STREAM stream=%d offset=%d len=%d FIN=%v", f.StreamId, f.Offset, len(f.Data), f.hasFin())
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
		return codecDefaultSize
	}
	return uintptr(f.DataLength)
}

func (f streamFrame) hasFin() bool {
	if f.Typ&kFrameTypeFlagF == 0 {
		return false
	}
	return true
}

func newStreamFrame(stream uint32, offset uint64, data []byte, last bool) frame {
	logf(logTypeFrame, "Creating stream frame with data length=%d", len(data))
	assert(len(data) <= 65535)
	// TODO(ekr@tfm.com): One might want to allow non
	// D bit, but not for now.
	// Set all of SSOO to 1
	typ := kFrameTypeStream | 0x1e | kFrameTypeFlagD
	if last {
		typ |= kFrameTypeFlagF
	}
	return newFrame(
		stream,
		&streamFrame{
			typ,
			uint32(stream),
			offset,
			uint16(len(data)),
			dup(data),
		})
}
