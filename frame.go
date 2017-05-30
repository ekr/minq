package chip

const (
	kFrameTypePadding = 0x0
	kFrameTypeRstStream = 0x1
	kFrameTypeConnectionClose = 0x2
	kFrameTypeGoaway = 0x3
	kFrameTypeMaxData = 0x4
	kFrameTypeMaxStreamData = 0x5
	kFrameTypeMaxStreamId = 0x6
	kFrameTypePing = 0x7
	kFrameTypeBlocked = 0x8
	kFrameTypeStreamBlocked = 0x9
	kFrameTypeStreamIdNeeded = 0xa
	kFrameTypeNewConnectionId = 0xb
	kFrameTypeAck = 0xa0
	kFrameTypeStream = 0xc0
)

type InnerFrame interface {
	getType() uint8
}

type Frame struct {
	inner InnerFrame
}

// Padding
type PaddingFrame struct {
}

// Stream Frames


