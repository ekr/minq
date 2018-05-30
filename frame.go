package minq

import (
	"fmt"
	"time"

	"github.com/bifurcation/mint/syntax"
)

type frameType uint8

type frameNonSyntax interface {
	unmarshal(b []byte) (int, error)
}

const (
	kFrameTypePadding          = frameType(0x0)
	kFrameTypeRstStream        = frameType(0x1)
	kFrameTypeConnectionClose  = frameType(0x2)
	kFrameTypeApplicationClose = frameType(0x3)
	kFrameTypeMaxData          = frameType(0x4)
	kFrameTypeMaxStreamData    = frameType(0x5)
	kFrameTypeMaxStreamId      = frameType(0x6)
	kFrameTypePing             = frameType(0x7)
	kFrameTypeBlocked          = frameType(0x8)
	kFrameTypeStreamBlocked    = frameType(0x9)
	kFrameTypeStreamIdBlocked  = frameType(0xa)
	kFrameTypeNewConnectionId  = frameType(0xb)
	kFrameTypeStopSending      = frameType(0xc)
	kFrameTypeAck              = frameType(0xd)
	kFrameTypePathChallenge    = frameType(0xe)
	kFrameTypePathResponse     = frameType(0xf)
	kFrameTypeStream           = frameType(0x10)
	kFrameTypeStreamMax        = frameType(0x17)
)

const (
	kFrameTypeStreamFlagFIN = frameType(0x01)
	kFrameTypeStreamFlagLEN = frameType(0x02)
	kFrameTypeStreamFlagOFF = frameType(0x04)
)

const (
	// Assume maximal sizes for these.
	kMaxAckHeaderLength     = 33
	kMaxAckBlockEntryLength = 16
	kMaxAckGap              = 255
	kMaxAckBlocks           = 255
)

type innerFrame interface {
	getType() frameType
	String() string
}

type frame struct {
	stream        uint64
	f             innerFrame
	encoded       []byte
	pns           []uint64
	lostPns       []uint64
	time          time.Time
	needsTransmit bool
}

func (f frame) String() string {
	return f.f.String()
}

func newFrame(stream uint64, inner innerFrame) frame {
	return frame{stream, inner, nil, nil, nil, time.Unix(0, 0), true}
}

// Encode internally if not already encoded.
func (f *frame) encode() error {
	if f.encoded != nil {
		return nil
	}
	var err error
	f.encoded, err = syntax.Marshal(f.f)
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
	var n int
	var err error

	t := data[0]
	logf(logTypeFrame, "Frame type byte %v", t)
	switch {
	case t == uint8(kFrameTypePadding):
		inner = &paddingFrame{}
	case t == uint8(kFrameTypeRstStream):
		inner = &rstStreamFrame{}
	case t == uint8(kFrameTypeConnectionClose):
		inner = &connectionCloseFrame{}
	case t == uint8(kFrameTypeApplicationClose):
		inner = &applicationCloseFrame{}
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
	case t == uint8(kFrameTypeStreamIdBlocked):
		inner = &streamIdBlockedFrame{}
	case t == uint8(kFrameTypeNewConnectionId):
		inner = &newConnectionIdFrame{}
	case t == uint8(kFrameTypeStopSending):
		inner = &stopSendingFrame{}
	case t == uint8(kFrameTypeAck):
		inner = &ackFrame{}
	case t == uint8(kFrameTypePathChallenge):
		inner = &pathChallengeFrame{}
	case t == uint8(kFrameTypePathResponse):
		inner = &pathResponseFrame{}
	case t >= uint8(kFrameTypeStream) && t <= uint8(kFrameTypeStreamMax):
		inner = &streamFrame{}
	default:
		logf(logTypeConnection, "Unknown frame type %v", t)
		return 0, nil, fmt.Errorf("Received unknown frame type: %v", t)
	}

	ns, ok := inner.(frameNonSyntax)
	if ok {
		n, err = ns.unmarshal(data)

	} else {
		n, err = syntax.Unmarshal(data, inner)
	}
	if err != nil {
		return 0, nil, err
	}

	return uintptr(n), &frame{0, inner, data[:n], nil, nil, time.Now(), false}, nil
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

func newPaddingFrame(stream uint64) frame {
	return newFrame(stream, &paddingFrame{0})
}

// RST_STREAM
type rstStreamFrame struct {
	Type        frameType
	StreamId    uint64 `tls:"varint"`
	ErrorCode   uint16
	FinalOffset uint64 `tls:"varint"`
}

func (f rstStreamFrame) String() string {
	return fmt.Sprintf("RST_STREAM stream=%x errorCode=%d finalOffset=%x", f.StreamId, f.ErrorCode, f.FinalOffset)
}

func (f rstStreamFrame) getType() frameType {
	return kFrameTypeRstStream
}

func newRstStreamFrame(streamId uint64, errorCode uint16, finalOffset uint64) frame {
	return newFrame(streamId, &rstStreamFrame{
		kFrameTypeRstStream,
		uint64(streamId),
		errorCode,
		finalOffset})
}

// STOP_SENDING
type stopSendingFrame struct {
	Type      frameType
	StreamId  uint64 `tls:"varint"`
	ErrorCode uint16
}

func (f stopSendingFrame) String() string {
	return fmt.Sprintf("STOP_SENDING stream=%x errorCode=%d", f.StreamId, f.ErrorCode)
}

func (f stopSendingFrame) getType() frameType {
	return kFrameTypeStopSending
}

func newStopSendingFrame(streamId uint64, errorCode uint16) frame {
	return newFrame(streamId, &stopSendingFrame{
		kFrameTypeStopSending,
		uint64(streamId),
		errorCode})
}

// CONNECTION_CLOSE
type connectionCloseFrame struct {
	Type         frameType
	ErrorCode    uint16
	ReasonPhrase []byte `tls:"head=varint"`
}

func (f connectionCloseFrame) String() string {
	return fmt.Sprintf("CONNECTION_CLOSE errorCode=%x", f.ErrorCode)
}

func (f connectionCloseFrame) getType() frameType {
	return kFrameTypeConnectionClose
}

func newConnectionCloseFrame(errcode ErrorCode, reason string) frame {
	return newFrame(0, &connectionCloseFrame{
		kFrameTypeConnectionClose,
		uint16(errcode),
		[]byte(reason),
	})
}

// APPLICATION_CLOSE
type applicationCloseFrame struct {
	Type         frameType
	ErrorCode    uint16
	ReasonPhrase []byte `tls:"head=varint"`
}

func (f applicationCloseFrame) String() string {
	return fmt.Sprintf("APPLICATION_CLOSE errorCode=%x", f.ErrorCode)
}

func (f applicationCloseFrame) getType() frameType {
	return kFrameTypeApplicationClose
}

func newApplicationCloseFrame(errcode uint16, reason string) frame {
	return newFrame(0, &applicationCloseFrame{
		kFrameTypeApplicationClose,
		uint16(errcode),
		[]byte(reason),
	})
}

// MAX_DATA
type maxDataFrame struct {
	Type        frameType
	MaximumData uint64 `tls:"varint"`
}

func (f maxDataFrame) String() string {
	return fmt.Sprintf("MAX_DATA %d", f.MaximumData)
}

func (f maxDataFrame) getType() frameType {
	return kFrameTypeMaxData
}

func newMaxData(m uint64) frame {
	return newFrame(0, &maxDataFrame{kFrameTypeMaxData, m})
}

// MAX_STREAM_DATA
type maxStreamDataFrame struct {
	Type              frameType
	StreamId          uint64 `tls:"varint"`
	MaximumStreamData uint64 `tls:"varint"`
}

func newMaxStreamData(stream uint64, offset uint64) frame {
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
	MaximumStreamId uint64 `tls:"varint"`
}

func newMaxStreamId(id uint64) frame {
	return newFrame(0,
		&maxStreamIdFrame{
			kFrameTypeMaxStreamId,
			id,
		})
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
	Type   frameType
	Offset uint64 `tls:"varint"`
}

func (f blockedFrame) String() string {
	return "BLOCKED"
}

func (f blockedFrame) getType() frameType {
	return kFrameTypeBlocked
}

func newBlockedFrame(offset uint64) frame {
	return newFrame(0, &blockedFrame{kFrameTypeBlocked, offset})
}

// STREAM_BLOCKED
type streamBlockedFrame struct {
	Type     frameType
	StreamId uint64 `tls:"varint"`
	Offset   uint64 `tls:"varint"`
}

func (f streamBlockedFrame) String() string {
	return "STREAM_BLOCKED"
}

func (f streamBlockedFrame) getType() frameType {
	return kFrameTypeStreamBlocked
}

func newStreamBlockedFrame(id uint64, offset uint64) frame {
	return newFrame(0, &streamBlockedFrame{kFrameTypeStreamBlocked, id, offset})
}

// STREAM_ID_BLOCKED
type streamIdBlockedFrame struct {
	Type     frameType
	StreamId uint64 `tls:"varint"`
}

func (f streamIdBlockedFrame) String() string {
	return "STREAM_ID_BLOCKED"
}

func (f streamIdBlockedFrame) getType() frameType {
	return kFrameTypeStreamIdBlocked
}

func newStreamIdBlockedFrame(id uint64) frame {
	return newFrame(0, &streamIdBlockedFrame{
		kFrameTypeStreamIdBlocked,
		id})
}

// NEW_CONNECTION_ID
type newConnectionIdFrame struct {
	Type         frameType
	Sequence     uint16 `tls:"varint"`
	ConnectionId uint64
	ResetToken   [16]byte
}

func (f newConnectionIdFrame) String() string {
	return "NEW_CONNECTION_ID"
}

func (f newConnectionIdFrame) getType() frameType {
	return kFrameTypeNewConnectionId
}

// ACK
type ackBlock struct {
	Gap    uint64 `tls:"varint"`
	Length uint64 `tls:"varint"`
}

type ackFrameHeader struct {
	Type                frameType
	LargestAcknowledged uint64 `tls:"varint"`
	AckDelay            uint64 `tls:"varint"`
	AckBlockCount       uint64 `tls:"varint"`
	FirstAckBlock       uint64 `tls:"varint"`
}

type ackFrame struct {
	ackFrameHeader
	AckBlockSection []*ackBlock `tls:"head=none"`
}

func (f ackFrame) String() string {
	return fmt.Sprintf("ACK numBlocks=%d largestAck=%x", f.AckBlockCount, f.LargestAcknowledged)
}

func (f ackFrame) getType() frameType {
	return kFrameTypeAck
}

// ACK frames can't presently be decoded with syntax, so we need
// a custom decoder.
func (f *ackFrame) unmarshal(buf []byte) (int, error) {
	// First, decode the header
	read := int(0)
	n, err := syntax.Unmarshal(buf, &f.ackFrameHeader)
	if err != nil {
		return 0, err
	}
	buf = buf[n:]
	read += n

	// Now decode each block
	for i := uint64(0); i < f.AckBlockCount; i++ {
		blk := &ackBlock{}
		n, err := syntax.Unmarshal(buf, blk)
		if err != nil {
			return 0, err
		}
		buf = buf[n:]
		read += n

		f.AckBlockSection = append(f.AckBlockSection, blk)
	}

	return read, nil
}

func newAckFrame(recvd *recvdPackets, rs ackRanges, left int) (*frame, int, error) {
	if left < kMaxAckHeaderLength {
		return nil, 0, nil
	}
	logf(logTypeFrame, "Making ACK frame %v", rs)

	left -= kMaxAckHeaderLength

	last := rs[0].lastPacket
	largestAckData, ok := recvd.packets[last]
	// Should always be there. Packets only get removed after being set to ack2,
	// which means we should not be acking it again.
	assert(ok)

	// FIRST, fill in the basic info of the ACK frame
	var f ackFrame
	f.Type = kFrameTypeAck
	f.LargestAcknowledged = last
	f.AckDelay = uint64(time.Since(largestAckData.t).Nanoseconds()) / 1000
	f.AckBlockCount = 0
	f.FirstAckBlock = rs[0].count - 1

	// ...and account for the first block.
	last -= f.FirstAckBlock
	addedRanges := 1

	// SECOND, add the remaining ACK blocks that fit and that we have
	for (left > 0) && (addedRanges < len(rs)) {
		// calculate blocks needed for the next range
		gap := last - rs[addedRanges].lastPacket - 1

		gap = last - rs[addedRanges].lastPacket - 1
		b := &ackBlock{
			gap,
			rs[addedRanges].count - 1,
		}

		last = rs[addedRanges].lastPacket - rs[addedRanges].count

		f.AckBlockCount++
		f.AckBlockSection = append(f.AckBlockSection, b)
		addedRanges++
		left -= kMaxAckBlockEntryLength // Assume worst-case.
	}

	ret := newFrame(0, &f)
	return &ret, addedRanges, nil
}

// PATH_CHALLENGE
type pathChallengeFrame struct {
	Type frameType
	Data [8]byte
}

func (f pathChallengeFrame) String() string {
	return "PATH_CHALLENGE"
}

func (f pathChallengeFrame) getType() frameType {
	return kFrameTypePathChallenge
}

func newPathChallengeFrame(data []byte) frame {
	payload := &pathChallengeFrame{Type: kFrameTypePathChallenge}
	assert(len(data) == len(payload.Data))
	copy(payload.Data[:], data)
	return newFrame(0, payload)
}

// PATH_RESPONSE
type pathResponseFrame struct {
	Type frameType
	Data [8]byte
}

func (f pathResponseFrame) String() string {
	return "PATH_RESPONSE"
}

func (f pathResponseFrame) getType() frameType {
	return kFrameTypePathResponse
}

func newPathResponseFrame(data []byte) frame {
	payload := &pathResponseFrame{Type: kFrameTypePathResponse}
	assert(len(data) == len(payload.Data))
	copy(payload.Data[:], data)
	return newFrame(0, payload)
}

// STREAM
type streamFrame struct {
	Typ      frameType
	StreamId uint64 `tls:"varint"`
	Offset   uint64 `tls:"varint"`
	Data     []byte `tls:"head=varint"`
}

func (f streamFrame) String() string {
	return fmt.Sprintf("STREAM stream=%d offset=%d len=%d FIN=%v", f.StreamId, f.Offset, len(f.Data), f.hasFin())
}

func (f streamFrame) getType() frameType {
	return kFrameTypeStream
}

func (f streamFrame) hasFin() bool {
	if f.Typ&kFrameTypeStreamFlagFIN == 0 {
		return false
	}
	return true
}

func newStreamFrame(stream uint64, offset uint64, data []byte, last bool) frame {
	logf(logTypeFrame, "Creating stream frame with data length=%d", len(data))
	assert(len(data) <= 65535)
	// TODO(ekr@tfm.com): One might want to allow non
	// D bit, but not for now.
	// Set all of SSOO to 1
	typ := kFrameTypeStream | kFrameTypeStreamFlagLEN | kFrameTypeStreamFlagOFF
	if last {
		typ |= kFrameTypeStreamFlagFIN
	}
	return newFrame(
		stream,
		&streamFrame{
			typ,
			stream,
			offset,
			dup(data),
		})
}

func decodeVarint(buf []byte) (int, uint64, error) {
	var vi struct {
		Val uint64 `tls:"varint"`
	}

	n, err := syntax.Unmarshal(buf, &vi)
	if err != nil {
		return 0, 0, err
	}

	return n, vi.Val, nil
}

// Stream frames can't presently be decoded with syntax, so we need
// a custom decoder.
func (f *streamFrame) unmarshal(buf []byte) (int, error) {
	f.Typ = frameType(buf[0])
	buf = buf[1:]
	var read = int(1)
	var n int
	var err error

	n, f.StreamId, err = decodeVarint(buf)
	if err != nil {
		return 0, err
	}
	buf = buf[n:]
	read += n

	if f.Typ&kFrameTypeStreamFlagOFF != 0 {
		n, f.Offset, err = decodeVarint(buf)
		if err != nil {
			return 0, err
		}
		buf = buf[n:]
		read += n
	}

	if f.Typ&kFrameTypeStreamFlagLEN != 0 {
		var l uint64
		n, l, err = decodeVarint(buf)
		if err != nil {
			return 0, err
		}
		buf = buf[n:]
		read += n

		logf(logTypeFrame, "Expecting %v bytes", l)

		if l > uint64(len(buf)) {
			return 0, fmt.Errorf("Insufficient bytes left")
		}
		f.Data = dup(buf[:l])
		read += int(l)
	} else {
		f.Data = dup(buf)
		read += len(buf)
	}

	return read, nil
}
