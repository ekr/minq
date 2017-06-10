// Stolen from Mint and renamed
package chip

import (
	"bytes"
	"io"
	"net"
	"time"
)


type connBuffer struct {
	r     *bytes.Buffer
	w     *bytes.Buffer
}

func (p *connBuffer) Read(data []byte) (n int, err error) {
	logf(logTypeConnBuffer, "Reading %v", n)	
	n, err = p.r.Read(data)

	// Suppress bytes.Buffer's EOF on an empty buffer
	if err == io.EOF {
		err = nil
	}
	return
}

func (p *connBuffer) Write(data []byte) (n int, err error) {
	logf(logTypeConnBuffer, "Writing %v", n)
	return p.w.Write(data)
}

func (p *connBuffer) Close() error {
	return nil
}


func (p *connBuffer) LocalAddr() net.Addr                { return nil }
func (p *connBuffer) RemoteAddr() net.Addr               { return nil }
func (p *connBuffer) SetDeadline(t time.Time) error      { return nil }
func (p *connBuffer) SetReadDeadline(t time.Time) error  { return nil }
func (p *connBuffer) SetWriteDeadline(t time.Time) error { return nil }

func newConnBuffer() *connBuffer {
	return &connBuffer{
		bytes.NewBuffer(nil),
		bytes.NewBuffer(nil),
	}
}

func (p *connBuffer) input(data []byte) error {
	logf(logTypeConnBuffer, "input %v", len(data))
	_, err :=  p.r.Write(data)
	return err
}

func (p *connBuffer) getOutput() []byte {
	b := p.w.Bytes()
	p.w.Reset()
	return b
}

func (p *connBuffer) OutputLen() int {
	return p.w.Len()
}
