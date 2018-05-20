package minq

import (
	"github.com/bifurcation/mint"
	"io"
	"sync"
)

type RecordLayerImpl struct {
	sync.Mutex
	conn  *Connection
	epoch mint.Epoch
	dir   mint.Direction
}

func (r *RecordLayerImpl) SetVersion(v uint16) {
	// Do nothing
}

func (r *RecordLayerImpl) SetLabel(s string) {
	// Do nothing
}

func (r *RecordLayerImpl) Rekey(epoch mint.Epoch, factory mint.AeadFactory, key []byte, iv []byte) error {
	logf(logTypeTls, "Rekey epoch=%v", epoch)
	// TODO(ekr@rtfm.com): Check to see if it's GCM.
	aead, err := newWrappedAESGCM(key, iv)
	if err != nil {
		return mint.AlertInternalError
	}
	st := cryptoState{
		secret: nil,
		aead:   aead,
	}

	if r.dir == mint.DirectionRead {
		r.conn.encryptionLevels[epoch].recvCipher = &st
	} else {
		r.conn.encryptionLevels[epoch].sendCipher = &st
	}
	r.epoch = epoch
	return nil
}

func (r *RecordLayerImpl) ResetClear(seq uint64) {
	panic("UNIMPLEMENTED")
}
func (r *RecordLayerImpl) DiscardReadKey(epoch mint.Epoch) {
	// Do nothing
}
func (r *RecordLayerImpl) PeekRecordType(block bool) (mint.RecordType, error) {
	panic("UNIMPLEMENTED")
}

func (r *RecordLayerImpl) ReadRecord() (*mint.TLSPlaintext, error) {
	str := &(r.conn.encryptionLevels[r.epoch].recvCryptoStream.(*recvStream).recvStreamBase)

	b := make([]byte, 16384)
	n, err := str.read(b)
	logf(logTypeStream, "EKR: n=%d err=%v\n", n, err)
	if err == ErrorWouldBlock {
		return nil, mint.AlertWouldBlock
	}
	if err != nil {
		return nil, mint.AlertInternalError
	}

	return mint.NewTLSPlaintext(mint.RecordTypeHandshake, r.epoch, b[:n]), nil
}

func (r *RecordLayerImpl) WriteRecord(pt *mint.TLSPlaintext) error {
	logf(logTypeTls, "WriteRecord(epoch=%v, len=%v)", r.epoch, len(pt.Fragment()))
	_, err := r.conn.encryptionLevels[r.epoch].sendCryptoStream.(*sendStream).write(pt.Fragment(), nil)
	return err
}

func (r *RecordLayerImpl) Epoch() mint.Epoch {
	return r.epoch
}

type RecordLayerFactoryImpl struct {
	conn *Connection
}

func newRecordLayerFactory(conn *Connection) mint.RecordLayerFactory {
	return &RecordLayerFactoryImpl{conn: conn}
}

func (f *RecordLayerFactoryImpl) NewLayer(conn io.ReadWriter, dir mint.Direction) mint.RecordLayer {
	return &RecordLayerImpl{
		dir:  dir,
		conn: f.conn,
	}
}
