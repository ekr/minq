package minq

import (
	"fmt"
	"io"
	"io/ioutil"
	"testing"
	"time"
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

func testTlsConfig() *TlsConfig {
	t := NewTlsConfig("localhost")
	return &t
}

type csPair struct {
	client *Connection
	server *Connection
}

func newCsPair(t *testing.T) *csPair {
	cTrans, sTrans := newTestTransportPair(true)

	client := NewConnection(cTrans, RoleClient, testTlsConfig(), nil)
	assertNotNil(t, client, "Couldn't make client")

	server := NewConnection(sTrans, RoleServer, testTlsConfig(), nil)
	assertNotNil(t, server, "Couldn't make server")

	return &csPair{
		client,
		server,
	}
}

func (pair *csPair) handshake(t *testing.T) {
	err := pair.client.sendClientInitial()
	assertNotError(t, err, "Couldn't send client initial packet")

	for pair.client.state != StateEstablished || pair.server.state != StateEstablished {
		err = inputAll(pair.server)
		assertNotError(t, err, "Error processing CI")

		err = inputAll(pair.client)
		assertNotError(t, err, "Error processing SH")
	}
}

func TestSendCI(t *testing.T) {
	cTrans, _ := newTestTransportPair(true)

	client := NewConnection(cTrans, RoleClient, testTlsConfig(), nil)
	assertNotNil(t, client, "Couldn't make client")

	err := client.sendClientInitial()
	assertNotError(t, err, "Couldn't send client initial packet")
}

func TestSendReceiveCIOnly(t *testing.T) {
	cTrans, sTrans := newTestTransportPair(true)

	client := NewConnection(cTrans, RoleClient, testTlsConfig(), nil)
	assertNotNil(t, client, "Couldn't make client")

	server := NewConnection(sTrans, RoleServer, testTlsConfig(), nil)
	assertNotNil(t, server, "Couldn't make server")

	err := client.sendClientInitial()
	assertNotError(t, err, "Couldn't send client initial packet")

	err = inputAll(server)

	assertNotError(t, err, "Error processing CI")
}

func TestSendReceiveDupCI(t *testing.T) {
	cTrans, sTrans := newTestTransportPair(true)

	client := NewConnection(cTrans, RoleClient, testTlsConfig(), nil)
	assertNotNil(t, client, "Couldn't make client")

	server := NewConnection(sTrans, RoleServer, testTlsConfig(), nil)
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

	client := NewConnection(cTrans, RoleClient, testTlsConfig(), nil)
	assertNotNil(t, client, "Couldn't make client")

	server := NewConnection(sTrans, RoleServer, testTlsConfig(), nil)
	assertNotNil(t, server, "Couldn't make server")

	err := client.sendClientInitial()
	assertNotError(t, err, "Couldn't send client initial packet")

	err = inputAll(server)
	assertNotError(t, err, "Error processing CI")

	err = inputAll(client)
	assertNotError(t, err, "Error processing SH")

	err = inputAll(server)
	assertNotError(t, err, "Error processing CFIN")

	fmt.Println("Handshake should be complete")

	err = inputAll(client)
	assertNotError(t, err, "Error processing NST")

	err = inputAll(server)
	assertNotError(t, err, "Error processing CFIN")

	fmt.Println("Checking client state")
	assertEquals(t, client.state, StateEstablished)
	fmt.Println("Checking server state")
	assertEquals(t, server.state, StateEstablished)

	// All the server's and client's data should be acked.
	n := server.outstandingQueuedBytes()
	assertEquals(t, 0, n)

	// But the client still has-unacked-data
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

func drain(t *testing.T, c *Connection) {
	// Reach into the connection and frob the timer so that we don't have to wait.
	c.closingEnd = time.Now().Add(-1 * time.Microsecond)
	_, err := c.CheckTimer()
	assertEquals(t, err, ErrorConnIsClosed)
	assertEquals(t, c.GetState(), StateClosed)
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
	ss := pair.server.GetStream(4)
	b, err := ioutil.ReadAll(ss)
	assertEquals(t, ErrorWouldBlock, err)
	assertNotNil(t, b, "Read data from server")
	assertByteEquals(t, []byte(testString), b)

	// Write data S->C
	for i := range b {
		b[i] ^= 0xff
	}
	ss.Write(b)

	// Read data C->S
	err = inputAll(pair.client)
	b2, err := ioutil.ReadAll(cs)
	assertEquals(t, ErrorWouldBlock, err)
	assertNotNil(t, b2, "Read data from client")
	assertByteEquals(t, b, b2)

	// Check that we only create streams in one direction
	cs = pair.client.CreateStream()
	assertEquals(t, uint64(8), cs.Id())
	assertNotNil(t, pair.client.GetStream(8), "Stream 8 should exist")
	assertX(t, pair.client.GetStream(2) == nil, "Stream 2 should not exist")

	// Close the client.
	pair.client.Close()
	assertEquals(t, pair.client.GetState(), StateClosing)

	// Read the close.
	err = inputAll(pair.server)
	assertNotError(t, err, "Read close")
	assertEquals(t, pair.server.GetState(), StateClosing)

	drain(t, pair.client)
	drain(t, pair.server)
}

type testReceiveHandler struct {
	t    *testing.T
	buf  []byte
	done bool
}

var _ ConnectionHandler = &testReceiveHandler{}

func newTestReceiveHandler(t *testing.T) *testReceiveHandler {
	return &testReceiveHandler{t: t}
}

func (h *testReceiveHandler) StateChanged(s State) {
}

func (h *testReceiveHandler) NewStream(s Stream) {
}

func (h *testReceiveHandler) NewRecvStream(s RecvStream) {
}

func (h *testReceiveHandler) StreamReadable(s RecvStream) {
	for {
		b := make([]byte, 1024)

		n, err := s.Read(b)
		switch err {
		case nil:
			break
		case ErrorWouldBlock:
			return
		case ErrorStreamIsClosed, ErrorConnIsClosed, io.EOF:
			h.done = true
			return
		default:
			assertX(h.t, false, "Unknown error")
			return
		}
		b = b[:n]
		h.buf = append(h.buf, b...)
	}
}

func TestSendReceiveBigData(t *testing.T) {
	pair := newCsPair(t)
	pair.handshake(t)
	buf := make([]byte, 100000)

	for i := range buf {
		buf[i] = byte(i & 0xff)
	}

	handler := newTestReceiveHandler(t)
	pair.server.SetHandler(handler)

	// Write data C->S
	cs := pair.client.CreateStream()
	remaining := buf
	for !handler.done {
		if len(remaining) > 0 {
			n, err := cs.Write(remaining)
			assertNotError(t, err, "write should work")
			remaining = remaining[n:]
			if len(remaining) == 0 {
				cs.Close()
			}
		}
		inputAll(pair.server)
		inputAll(pair.client)
	}

	assertByteEquals(t, buf, handler.buf)
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
	ss := pair.server.GetStream(4)
	b := make([]byte, 1024)
	n, err := ss.Read(b)
	assertNotError(t, err, "Error reading")
	b = b[:n]
	assertByteEquals(t, []byte(testString), b)

	// Write data S->C
	for i := range b {
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

func TestSendReceiveStreamFin(t *testing.T) {
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

	// Now close the stream.
	cs.Close()

	// Verify that we cannot write.
	n, err := cs.Write(testString)
	assertEquals(t, ErrorStreamIsClosed, err)
	assertEquals(t, 0, n)

	// Read data C->S
	err = inputAll(pair.server)
	assertNotError(t, err, "Couldn't read input packets")
	ss := pair.server.GetStream(4)
	b := make([]byte, 1024)
	n, err = ss.Read(b)
	assertNotError(t, err, "Couldn't read from client")
	b = b[:n]
	assertByteEquals(t, []byte(testString), b)

	b = make([]byte, 1024)
	n, err = ss.Read(b)
	assertEquals(t, err, io.EOF)
	assertEquals(t, 0, n)
}

func TestSendReceiveStreamRst(t *testing.T) {
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

	// Now reset the stream.
	cs.Reset(kQuicErrorNoError)

	// Verify that we cannot write.
	n, err := cs.Write(testString)
	assertEquals(t, ErrorStreamIsClosed, err)
	assertEquals(t, 0, n)

	// Read data C->S. Should result in no data.
	err = inputAll(pair.server)
	assertNotError(t, err, "Couldn't read input packets")
	ss := pair.server.GetStream(4)
	b := make([]byte, 1024)
	n, err = ss.Read(b)
	assertEquals(t, err, io.EOF)
	assertEquals(t, 0, n)
}

func TestVersionNegotiationPacket(t *testing.T) {
	cTrans, sTrans := newTestTransportPair(true)

	client := NewConnection(cTrans, RoleClient, testTlsConfig(), nil)
	assertNotNil(t, client, "Couldn't make client")
	// Set the client version to something bogus.
	client.version = kQuicGreaseVersion2

	server := NewConnection(sTrans, RoleServer, testTlsConfig(), nil)
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
	assertEquals(t, hdr.Version, VersionNumber(0))
	assertByteEquals(t, hdr.DestinationConnectionID, client.clientConnectionId)
	assertByteEquals(t, hdr.SourceConnectionID, client.serverConnectionId)
}

func TestCantMakeRemoteStreams(t *testing.T) {
	cTrans, _ := newTestTransportPair(true)
	client := NewConnection(cTrans, RoleClient, testTlsConfig(), nil)

	send := client.ensureSendStream(3) // 3 is a RecvStream for the client
	assertEquals(t, nil, send)

	recv := client.ensureRecvStream(2) // 2 is a SendStream for the client
	assertEquals(t, nil, recv)
}

func TestStatelessRetry(t *testing.T) {
	cTrans, sTrans := newTestTransportPair(true)

	client := NewConnection(cTrans, RoleClient, testTlsConfig(), nil)
	assertNotNil(t, client, "Couldn't make client")

	hrrConfig := *testTlsConfig()
	hrrConfig.ForceHrr = true

	server := NewConnection(sTrans, RoleServer, &hrrConfig, nil)
	assertNotNil(t, server, "Couldn't make server")

	err := client.sendClientInitial()
	assertNotError(t, err, "Couldn't send client initial packet")

	// Send the Stateless Retry
	err = inputAll(server)
	assertNotError(t, err, "Error processing CI")

	// Process SR, send CI
	err = inputAll(client)
	assertNotError(t, err, "Error processing SR")

	// Send the Stateless Retry
	err = inputAll(server)
	assertNotError(t, err, "Error processing CI")

	// Process server flight
	err = inputAll(client)
	assertNotError(t, err, "Error processing SH...FIN")

	// Process CFIN
	err = inputAll(server)
	assertNotError(t, err, "Error processing CFIN")

	assertEquals(t, StateEstablished, client.state)
	assertEquals(t, StateEstablished, server.state)
}

func TestSessionResumption(t *testing.T) {
	cTrans, sTrans := newTestTransportPair(true)

	cconf := testTlsConfig()
	client := NewConnection(cTrans, RoleClient, cconf, nil)
	assertNotNil(t, client, "Couldn't make client")

	sconf := testTlsConfig()
	server := NewConnection(sTrans, RoleServer, sconf, nil)
	assertNotNil(t, server, "Couldn't make server")

	pair := csPair{client, server}
	pair.handshake(t)

	// Consume NST.
	err := inputAll(pair.client)
	assertNotError(t, err, "Couldn't read NST")

	/*
		// Now rehandshake.
		client = NewConnection(cTrans, RoleClient, cconf, nil)
		assertNotNil(t, client, "Couldn't make client")
		server = NewConnection(sTrans, RoleServer, sconf, nil)
		assertNotNil(t, server, "Couldn't make server")
		pair = csPair{client, server}
		pair.handshake(t)
	*/
}

type streamCatcher struct {
	lastStream Stream
	lastRecv   RecvStream
}

var _ ConnectionHandler = &streamCatcher{}

func (sc *streamCatcher) StateChanged(s State)        {}
func (sc *streamCatcher) StreamReadable(s RecvStream) {}

func (sc *streamCatcher) NewStream(s Stream) {
	sc.lastStream = s
}

func (sc *streamCatcher) NewRecvStream(s RecvStream) {
	sc.lastRecv = s
}

func TestUnidirectionalStream(t *testing.T) {
	cTrans, sTrans := newTestTransportPair(true)

	cconf := testTlsConfig()
	client := NewConnection(cTrans, RoleClient, cconf, nil)
	assertNotNil(t, client, "Couldn't make client")

	var catcher streamCatcher
	sconf := testTlsConfig()
	server := NewConnection(sTrans, RoleServer, sconf, &catcher)
	assertNotNil(t, server, "Couldn't make server")

	pair := csPair{client, server}
	pair.handshake(t)

	testString := []byte("abcdef")
	cstream := client.CreateSendStream()
	assertEquals(t, cstream, client.GetSendStream(2))
	n, err := cstream.Write(testString)
	assertNotError(t, err, "write should work")
	assertEquals(t, n, len(testString))

	err = inputAll(server)
	assertNotError(t, err, "packets should be OK")

	sstream := catcher.lastRecv
	assertEquals(t, sstream, server.GetRecvStream(cstream.Id()))

	d, err := ioutil.ReadAll(sstream)
	assertEquals(t, ErrorWouldBlock, err)
	assertNotNil(t, d, "Read data from client")
	assertByteEquals(t, d, testString)

	err = cstream.Close()
	assertNotError(t, err, "close just works")
	err = cstream.Close()
	assertNotError(t, err, "close is idempotent")

	err = inputAll(server)
	assertNotError(t, err, "packets should be OK")

	n, err = sstream.Read(d)
	assertEquals(t, err, io.EOF)
	assertEquals(t, n, 0)
	assertEquals(t, sstream.RecvState(), RecvStreamStateDataRead)
}

func TestUnidirectionalStreamRst(t *testing.T) {
	cTrans, sTrans := newTestTransportPair(true)

	var catcher streamCatcher
	cconf := testTlsConfig()
	client := NewConnection(cTrans, RoleClient, cconf, &catcher)
	assertNotNil(t, client, "Couldn't make client")

	sconf := testTlsConfig()
	server := NewConnection(sTrans, RoleServer, sconf, nil)
	assertNotNil(t, server, "Couldn't make server")

	pair := csPair{client, server}
	pair.handshake(t)

	testString := []byte("abcdef")
	sstream := server.CreateSendStream()
	assertEquals(t, sstream, server.GetSendStream(3))
	n, err := sstream.Write(testString)
	assertNotError(t, err, "write should work")
	assertEquals(t, n, len(testString))

	err = inputAll(client)
	assertNotError(t, err, "packets should be OK")

	cstream := catcher.lastRecv
	assertEquals(t, cstream, client.GetRecvStream(sstream.Id()))

	d, err := ioutil.ReadAll(cstream)
	assertEquals(t, ErrorWouldBlock, err)
	assertNotNil(t, d, "Read data from server")
	assertByteEquals(t, d, testString)

	err = sstream.Reset(kQuicErrorNoError)
	assertNotError(t, err, "reset works")

	err = inputAll(client)
	assertNotError(t, err, "packets should be OK")

	n, err = cstream.Read(d)
	assertEquals(t, err, io.EOF)
	assertEquals(t, n, 0)
	assertEquals(t, cstream.RecvState(), RecvStreamStateResetRecvd)
}

func TestUnidirectionalStreamRstImmediate(t *testing.T) {
	pair := newCsPair(t)
	pair.handshake(t)

	sstream := pair.server.CreateSendStream()
	err := sstream.Reset(kQuicErrorNoError)
	assertNotError(t, err, "reset works")

	err = inputAll(pair.client)
	assertNotError(t, err, "packets should be OK")

	cstream := pair.client.GetRecvStream(sstream.Id())
	var d [3]byte
	n, err := cstream.Read(d[:])
	assertEquals(t, err, io.EOF)
	assertEquals(t, n, 0)
	assertEquals(t, cstream.RecvState(), RecvStreamStateResetRecvd)
}

func TestUnidirectionalStopSending(t *testing.T) {
	pair := newCsPair(t)
	pair.handshake(t)

	testString := []byte("abcdef")
	cstream := pair.client.CreateSendStream()
	n, err := cstream.Write(testString)
	assertNotError(t, err, "write should work")
	assertEquals(t, n, len(testString))

	err = inputAll(pair.server)
	assertNotError(t, err, "packets should be OK")

	sstream := pair.server.GetRecvStream(cstream.Id())

	d, err := ioutil.ReadAll(sstream)
	assertEquals(t, ErrorWouldBlock, err)
	assertNotNil(t, d, "Read data from client")
	assertByteEquals(t, d, testString)

	err = sstream.StopSending(0)
	assertNotError(t, err, "stop sending just works")

	err = inputAll(pair.client)
	assertNotError(t, err, "packets should be OK")

	assertEquals(t, cstream.SendState(), SendStreamStateResetSent)

	err = inputAll(pair.server)
	assertNotError(t, err, "packets should be OK")

	n, err = sstream.Read(d)
	assertEquals(t, err, io.EOF)
	assertEquals(t, n, 0)
	assertEquals(t, sstream.RecvState(), RecvStreamStateResetRecvd)
}

func TestBidirectionalStopSending(t *testing.T) {
	pair := newCsPair(t)
	pair.handshake(t)

	// Open a stream at the client and start using it (until it is used, it can't
	// exist at the server).
	testString := []byte("abcdef")
	cstream := pair.client.CreateStream()
	n, err := cstream.Write(testString)
	assertNotError(t, err, "write should work")
	assertEquals(t, n, len(testString))

	// Feed packets to the server.
	err = inputAll(pair.server)
	assertNotError(t, err, "packets should be OK")

	// The server then reads from the stream.
	sstream := pair.server.GetStream(cstream.Id())
	d, err := ioutil.ReadAll(sstream)
	assertEquals(t, err, ErrorWouldBlock)
	assertNotNil(t, d, "Read data from client")
	assertByteEquals(t, d, testString)

	// Now to test.  The server sends STOP_SENDING.
	testString2 := []byte("zyxwvut")
	err = sstream.StopSending(0)
	assertNotError(t, err, "stop sending just works")
	assertEquals(t, sstream.RecvState(), RecvStreamStateRecv) // no change

	// But it also continues to write to the stream.
	n, err = sstream.Write(testString2)
	assertNotError(t, err, "write should work")
	assertEquals(t, n, len(testString2))
	assertEquals(t, sstream.SendState(), SendStreamStateSend) // no change

	// After reading, the client should have responded to STOP_SENDING with RST_STREAM.
	err = inputAll(pair.client)
	assertNotError(t, err, "packets should be OK")
	assertEquals(t, cstream.SendState(), SendStreamStateResetSent)
	assertEquals(t, cstream.RecvState(), RecvStreamStateRecv)

	// Writing at the client now fails.
	n, err = cstream.Write(testString)
	assertEquals(t, err, ErrorStreamIsClosed)
	assertEquals(t, n, 0)

	// Reading can continue.
	d, err = ioutil.ReadAll(cstream)
	assertEquals(t, err, ErrorWouldBlock)
	assertByteEquals(t, d, testString2)
	assertEquals(t, sstream.RecvState(), RecvStreamStateRecv)

	sstream.Close()

	err = inputAll(pair.client)
	assertNotError(t, err, "packets should be OK")

	n, err = cstream.Read(d)
	assertEquals(t, err, io.EOF)
	assertEquals(t, n, 0)
	assertEquals(t, cstream.RecvState(), RecvStreamStateDataRead)
}

func TestStreamIdBlocked(t *testing.T) {
	pair := newCsPair(t)
	pair.handshake(t)

	for i := 0; i < kConcurrentStreamsBidi; i++ {
		assertNotNil(t, pair.server.CreateStream(),
			"create and discard a bidirectional stream")
	}
	assertEquals(t, nil, pair.server.CreateStream())

	for i := 0; i < kConcurrentStreamsUni; i++ {
		assertNotNil(t, pair.client.CreateSendStream(),
			"create and discard a unidirectional stream")
	}
	assertEquals(t, nil, pair.client.CreateSendStream())
	// TODO: check that both sides send STREAM_ID_BLOCKED
}

func fillConnectionCongestionWindow(c *Connection) ([]SendStream, []int, []byte) {
	writeBuf := make([]byte, 1024)
	for i := range writeBuf {
		writeBuf[i] = byte(i & 0xff)
	}
	cstreams := make([]SendStream, int(kConcurrentStreamsUni))
	outstanding := make([]int, int(kConcurrentStreamsUni))
	for i := range cstreams {
		s := c.CreateSendStream()
		cstreams[i] = s
		var err error
		for err == nil {
			var n int
			n, err = s.Write(writeBuf)
			outstanding[i] += n
		}
	}
	return cstreams, outstanding, writeBuf
}

func TestConnectionLevelFlowControl(t *testing.T) {
	pair := newCsPair(t)
	pair.handshake(t)

	cstreams,
		outstanding,
		writeBuf := fillConnectionCongestionWindow(pair.client)

	// At this point, the client has exhausted its connection flow control credit.
	// Let it send frames and have the server read some more.
	inputAll(pair.server)

	// Read a little bit from the server side.
	readBuf := make([]byte, len(writeBuf))
	sstream := pair.server.GetRecvStream(cstreams[0].Id())
	for outstanding[0] > 0 {
		n, err := sstream.Read(readBuf)
		assertNotError(t, err, "if we wrote it, it should be read")
		assertEquals(t, n, len(writeBuf))
		assertByteEquals(t, readBuf, writeBuf[:n])
		outstanding[0] -= n
	}

	// Now let the MAX_DATA frame propagate and check that we can write again.
	pair.server.sendQueued(false)
	inputAll(pair.client)

	assertX(t, (uint64(kConcurrentStreamsUni-1)*kInitialMaxStreamData) > kInitialMaxData,
		"should be able to fill connection flow control without using the last stream")
	// Use the last stream, which shouldn't have written anything.
	last := len(outstanding) - 1
	assertEquals(t, outstanding[last], 0)
	n, err := cstreams[last].Write(writeBuf)
	assertNotError(t, err, "should write successfully")
	assertEquals(t, n, len(writeBuf))
}

func TestConnectionLevelFlowControlRst(t *testing.T) {
	pair := newCsPair(t)
	pair.handshake(t)

	cstreams,
		outstanding,
		writeBuf := fillConnectionCongestionWindow(pair.client)

	// Connection flow control should be exhausted now.
	// Now reset one of those streams.
	cstreams[0].Reset(kQuicErrorNoError)
	inputAll(pair.server)

	// Now let the MAX_DATA frame propagate and check that we can write again.
	pair.server.sendQueued(false)
	inputAll(pair.client)

	// Use the last stream, which shouldn't have written anything.
	last := len(outstanding) - 1
	assertEquals(t, outstanding[last], 0)
	n, err := cstreams[last].Write(writeBuf)
	assertNotError(t, err, "should write successfully")
	assertEquals(t, n, len(writeBuf))
}
