package chip

import (
	"testing"
)

type testPacket struct {
	b []byte
}

type testTransportPipe struct {
	in []*testPacket
	out []*testPacket
	autoFlush bool
}


func newTestTransportPipe(autoFlush bool) *testTransportPipe {
	return &testTransportPipe{
		make([]*testPacket, 0),
		make([]*testPacket, 0),		
		autoFlush,
	}
}

func (t *testTransportPipe) Send(p *testPacket) {
	if !t.autoFlush {
		t.in = append(t.in, p)
	} else {
		t.out = append(t.in, p)
	}
}

func (t *testTransportPipe) Recv() *testPacket {
	if len(t.in) == 0 {
		return nil
	}

	p := t.in[0]
	t.in = t.in[1:]
	
	return p
}
			
func (t *testTransportPipe) Flush() {
	t.out = append(t.out, t.in...)
	t.in = make([]*testPacket, 0) 
}

type testTransport struct {
	r *testTransportPipe
	w *testTransportPipe
}

func (t *testTransport) Send(p []byte) error {
	w.Send(&TestPacket{p})
	return nil
}

func (t *testTransport) Recv() ([]byte, error) {
	p := r.Recv()
	if p == nil {
		return WouldBlock
	}
	return p.b
}


func newTransportPair(autoFlush bool) (a, b *testTransportPipe) {
	a = newTestTransportPipe(autoFlush)
	b = newTestTransportPipe(autoFlush)
	return
}


func TestSendCH(t *testing.T) {
	

}
