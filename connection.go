package chip

type ConnectionState interface {
	expandPacketNumber(spn uint64) uint64
}
