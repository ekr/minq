package minq

import (
	"github.com/bifurcation/mint"
	"io"
	"sync"
)

type RecordLayerImpl struct {
	sync.Mutex
	conn   *Connection
	epoch  mint.Epoch
	dir    mint.Direction
	buffer []byte
}

func (r *RecordLayerImpl) SetVersion(v uint16) {
	// Do nothing
}

func (r *RecordLayerImpl) SetLabel(s string) {
	// Do nothing
}

func (r *RecordLayerImpl) Rekey(epoch mint.Epoch, factory mint.AeadFactory, keys *mint.KeySet) error {
	logf(logTypeTls, "Rekey epoch=%v", epoch)
	// TODO(ekr@rtfm.com): Check to see if it's GCM.
	aead, err := newWrappedAESGCM(keys.Key, keys.Iv)
	if err != nil {
		return mint.AlertInternalError
	}

	st := cryptoState{
		aead: aead,
		pne:  newPneCipherFactoryAES(keys.Pn),
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

func (r *RecordLayerImpl) readBytes() ([]byte, error) {
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

	return b[:n], nil
}
func (r *RecordLayerImpl) PeekRecordType(block bool) (mint.RecordType, error) {
	assert(r.buffer == nil)
	var err error
	r.buffer, err = r.readBytes()
	if err != nil {
		return 0, err
	}
	return mint.RecordTypeHandshake, nil
}

func (r *RecordLayerImpl) ReadRecord() (*mint.TLSPlaintext, error) {
	var b []byte
	var err error
	if r.buffer != nil {
		b = r.buffer
		r.buffer = nil
	} else {
		b, err = r.readBytes()
		if err != nil {
			return nil, err
		}
	}
	return mint.NewTLSPlaintext(mint.RecordTypeHandshake, r.epoch, b), nil
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
		dir:    dir,
		conn:   f.conn,
		buffer: nil,
	}
}
