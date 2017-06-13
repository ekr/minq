package minq

import (
	"fmt"
	"testing"
)

type testPacket struct {
	b []byte
}

type testTransportPipe struct {
	in        []*testPacket
	out       []*testPacket
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
		t.out = append(t.out, p)
	}
}

func (t *testTransportPipe) Recv() *testPacket {
	if len(t.out) == 0 {
		return nil
	}

	p := t.out[0]
	t.out = t.out[1:]

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
	t.w.Send(&testPacket{p})
	return nil
}

func (t *testTransport) Recv() ([]byte, error) {
	p := t.r.Recv()
	if p == nil {
		return nil, WouldBlock
	}
	return p.b, nil
}

func newTestTransportPair(autoFlush bool) (a, b *testTransport) {
	a2b := newTestTransportPipe(autoFlush)
	b2a := newTestTransportPipe(autoFlush)

	a = &testTransport{b2a, a2b}
	b = &testTransport{a2b, b2a}

	return
}

func TestSendCI(t *testing.T) {
	cTrans, _ := newTestTransportPair(true)

	client := NewConnection(cTrans, kRoleClient, TlsConfig{})
	assertNotNil(t, client, "Couldn't make client")

	err := client.sendClientInitial()
	assertNotError(t, err, "Couldn't send client initial packet")
}

func TestSendReceiveCI(t *testing.T) {
	cTrans, sTrans := newTestTransportPair(true)

	client := NewConnection(cTrans, kRoleClient, TlsConfig{})
	assertNotNil(t, client, "Couldn't make client")

	server := NewConnection(sTrans, kRoleServer, TlsConfig{})
	assertNotNil(t, server, "Couldn't make server")

	err := client.sendClientInitial()
	assertNotError(t, err, "Couldn't send client initial packet")

	err = server.input()
	assertNotError(t, err, "Error processing CI")
}

func TestSendReceiveCISI(t *testing.T) {
	cTrans, sTrans := newTestTransportPair(true)

	client := NewConnection(cTrans, kRoleClient, TlsConfig{})
	assertNotNil(t, client, "Couldn't make client")

	server := NewConnection(sTrans, kRoleServer, TlsConfig{})
	assertNotNil(t, server, "Couldn't make server")

	err := client.sendClientInitial()
	assertNotError(t, err, "Couldn't send client initial packet")

	err = server.input()
	assertNotError(t, err, "Error processing CI")

	err = client.input()
	assertNotError(t, err, "Error processing SH")

	err = server.input()
	assertNotError(t, err, "Error processing CFIN")

	fmt.Println("Checking client state")
	assertEquals(t, client.state, kStateEstablished)
	fmt.Println("Checking server state")
	assertEquals(t, server.state, kStateEstablished)

	// All the server's data should be acked.
	n := server.outstandingQueuedBytes()
	assertEquals(t, 0, n)

	// But the client still has-unacked-data
	n = client.outstandingQueuedBytes()
	assertX(t, n > 0, "Client should still have un-acked data")

	// Run the server timer which will cause it to send
	// it's backup ACK frame.
	n, err = server.checkTimer()
	assertNotError(t, err, "Couldn't run server timer")
	assertEquals(t, 1, n)

	// Now the client can ingest it.
	err = client.input()
	assertNotError(t, err, "Error processing server ACK")
	n = client.outstandingQueuedBytes()
	assertEquals(t, 0, n)
}
