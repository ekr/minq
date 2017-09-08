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
		return nil, ErrorWouldBlock
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

func inputAll(c *Connection) error {
	t := c.transport.(*testTransport)

	for {
		p, err := t.Recv()
		if err != nil && err != ErrorWouldBlock {
			return err
		}

		if p == nil {
			return nil
		}

		err = c.Input(p)
		if err != nil {
			return err
		}
	}
}

func inputAllCapture(c *Connection) ([][]byte, error) {
	ret := make([][]byte, 0)

	t := c.transport.(*testTransport)

	for {
		p, err := t.Recv()
		if err != nil && err != ErrorWouldBlock {
			return ret, err
		}

		if p == nil {
			return ret, nil
		}

		ret = append(ret, p)
		err = c.Input(p)
		if err != nil {
			return ret, err
		}
	}
}

var testTlsConfig = NewTlsConfig("localhost")

type csPair struct {
	client *Connection
	server *Connection
}

func newCsPair(t *testing.T) *csPair {
	cTrans, sTrans := newTestTransportPair(true)

	client := NewConnection(cTrans, RoleClient, testTlsConfig, nil)
	assertNotNil(t, client, "Couldn't make client")

	server := NewConnection(sTrans, RoleServer, testTlsConfig, nil)
	assertNotNil(t, server, "Couldn't make server")

	return &csPair{
		client,
		server,
	}
}

func (pair *csPair) handshake(t *testing.T) {
	err := pair.client.sendClientInitial()
	assertNotError(t, err, "Couldn't send client initial packet")

	for pair.client.state != StateEstablished && pair.server.state != StateEstablished {
		err = inputAll(pair.server)
		assertNotError(t, err, "Error processing CI")

		err = inputAll(pair.client)
		assertNotError(t, err, "Error processing SH")
	}
}

func TestSendCI(t *testing.T) {
	cTrans, _ := newTestTransportPair(true)

	client := NewConnection(cTrans, RoleClient, testTlsConfig, nil)
	assertNotNil(t, client, "Couldn't make client")

	err := client.sendClientInitial()
	assertNotError(t, err, "Couldn't send client initial packet")
}

func TestSendReceiveCI(t *testing.T) {
	cTrans, sTrans := newTestTransportPair(true)

	client := NewConnection(cTrans, RoleClient, testTlsConfig, nil)
	assertNotNil(t, client, "Couldn't make client")

	server := NewConnection(sTrans, RoleServer, testTlsConfig, nil)
	assertNotNil(t, server, "Couldn't make server")

	err := client.sendClientInitial()
	assertNotError(t, err, "Couldn't send client initial packet")

	err = inputAll(server)

	assertNotError(t, err, "Error processing CI")
}

func TestSendReceiveDupCI(t *testing.T) {
	cTrans, sTrans := newTestTransportPair(true)

	client := NewConnection(cTrans, RoleClient, testTlsConfig, nil)
	assertNotNil(t, client, "Couldn't make client")

	server := NewConnection(sTrans, RoleServer, testTlsConfig, nil)
	assertNotNil(t, server, "Couldn't make server")

	err := client.sendClientInitial()
	assertNotError(t, err, "Couldn't send client initial packet")

	err = inputAll(server)
	assertNotError(t, err, "Error processing CI")

	n, err := client.CheckTimer()
	assertNotError(t, err, "Couldn't check timer on client")
	assertEquals(t, n, 1)

	err = inputAll(server)
	assertNotError(t, err, "Error processing second CI")
}

func TestSendReceiveCISI(t *testing.T) {
	cTrans, sTrans := newTestTransportPair(true)

	client := NewConnection(cTrans, RoleClient, testTlsConfig, nil)
	assertNotNil(t, client, "Couldn't make client")

	server := NewConnection(sTrans, RoleServer, testTlsConfig, nil)
	assertNotNil(t, server, "Couldn't make server")

	err := client.sendClientInitial()
	assertNotError(t, err, "Couldn't send client initial packet")

	err = inputAll(server)
	assertNotError(t, err, "Error processing CI")

	err = inputAll(client)
	assertNotError(t, err, "Error processing SH")

	err = inputAll(server)
	assertNotError(t, err, "Error processing CFIN")

	fmt.Println("Checking client state")
	assertEquals(t, client.state, StateEstablished)
	fmt.Println("Checking server state")
	assertEquals(t, server.state, StateEstablished)

	// All the server's data should be acked.
	n := server.outstandingQueuedBytes()
	assertEquals(t, 0, n)

	// But the client still has-unacked-data
	n = client.outstandingQueuedBytes()
	assertX(t, n > 0, "Client should still have un-acked data")

	// Have the client ingest the server's ACK, sent on
	// reading CFIN.
	err = inputAll(client)
	assertNotError(t, err, "Error processing server ACK")
	n = client.outstandingQueuedBytes()
	assertEquals(t, 0, n)

	// Run the client's checkTimer, which shouldn't do
	// anything because you don't ACK acks.
	n, err = client.CheckTimer()
	assertNotError(t, err, "Couldn't run client timer")
	assertEquals(t, 0, n)

	n, err = server.CheckTimer()
	assertNotError(t, err, "Couldn't run server timer")
	assertEquals(t, 0, n)
}

func TestSendReceiveData(t *testing.T) {
	testString := []byte("abcdef")
	pair := newCsPair(t)

	pair.handshake(t)

	// Force the client to get the ACK from the server
	pair.server.CheckTimer()
	err := inputAll(pair.client)

	// Write data C->S
	cs := pair.client.CreateStream()
	assertNotNil(t, cs, "Failed to create a stream")
	cs.Write(testString)

	// Read data C->S
	err = inputAll(pair.server)
	assertNotError(t, err, "Couldn't read input packets")
	ss := pair.server.GetStream(1)
	b := ss.readAll()
	assertNotNil(t, b, "Read data from server")
	assertByteEquals(t, []byte(testString), b)

	// Write data S->C
	for i, _ := range b {
		b[i] ^= 0xff
	}
	ss.Write(b)

	// Read data C->S
	err = inputAll(pair.client)
	b2 := cs.readAll()
	assertNotNil(t, b2, "Read data from client")
	assertByteEquals(t, b, b2)

	// Check that we only create streams in one direction
	cs = pair.client.CreateStream()
	assertEquals(t, uint32(3), cs.Id())
	assertNotNil(t, pair.client.GetStream(3), "Stream 3 should exist")
	assertX(t, pair.client.GetStream(2) == nil, "Stream 2 should not exist")

	// Close the client.
	pair.client.Close()

	// Read the close.
	err = inputAll(pair.server)
	assertNotError(t, err, "Read close")
	assertEquals(t, pair.server.GetState(), StateClosed)
}

func TestSendReceiveRetransmit(t *testing.T) {
	testString := []byte("abcdef")
	pair := newCsPair(t)

	pair.handshake(t)

	// Force the client to get the ACK from the server
	pair.server.CheckTimer()
	err := inputAll(pair.client)

	// Write data C->S
	cs := pair.client.CreateStream()
	assertNotNil(t, cs, "Failed to create a stream")
	cs.Write(testString)

	// Check the timer (forcing retransmit)
	pair.client.CheckTimer()
	pair.client.CheckTimer()

	// Read data C->S
	err = inputAll(pair.server)
	assertNotError(t, err, "Couldn't read input packets")
	ss := pair.server.GetStream(1)
	b := make([]byte, 1024)
	n, err := ss.Read(b)
	assertNotError(t, err, "Error reading")
	b = b[:n]
	assertByteEquals(t, []byte(testString), b)

	// Write data S->C
	for i, _ := range b {
		b[i] ^= 0xff
	}
	ss.Write(b)

	// Force potential retransmit.
	pair.server.CheckTimer()

	// Now read the data
	b2 := make([]byte, 1024)
	err = inputAll(pair.client)
	assertNotError(t, err, "Couldn't read input packets")
	n, err = cs.Read(b2)
	assertNotError(t, err, "Error reading")
	b2 = b2[:n]
	assertByteEquals(t, b2, b)

}

func TestVersionNegotiationPacket(t *testing.T) {
	cTrans, sTrans := newTestTransportPair(true)

	client := NewConnection(cTrans, RoleClient, testTlsConfig, nil)
	assertNotNil(t, client, "Couldn't make client")
	// Set the client version to something bogus.
	client.version = kQuicGreaseVersion2

	server := NewConnection(sTrans, RoleServer, testTlsConfig, nil)
	assertNotNil(t, server, "Couldn't make server")

	err := client.sendClientInitial()
	assertNotError(t, err, "Couldn't send client initial packet")

	err = inputAll(server)
	assertError(t, err, "Expected version negotiation error")
	assertEquals(t, err, ErrorDestroyConnection)

	cap, err := inputAllCapture(client)
	assertError(t, err, "Expected version negotiation error")
	assertEquals(t, err, ErrorReceivedVersionNegotiation)

	var hdr packetHeader
	_, err = decode(&hdr, cap[0])
	assertNotError(t, err, "Couldn't decode VN")
	// Check the error.
	assertEquals(t, hdr.Version, kQuicGreaseVersion2)
	assertEquals(t, hdr.ConnectionID, client.clientConnId)
}
