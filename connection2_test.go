package minq

import (
	"testing"
)

func inputAll2(c *Connection2) error {
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

type testConn2Handler struct {
	lastCreated  *Stream
	lastReadable *Stream
}

func (h *testConn2Handler) StateChanged(s State) {
}

func (h *testConn2Handler) NewStream(s *Stream) {
	h.lastCreated = s
}

func (h *testConn2Handler) StreamReadable(s *Stream) {
	h.lastReadable = s
}

func TestConn2SendReceiveData(t *testing.T) {
	testString := []byte("abcdef")
	testString2 := []byte("ghijkl")
	cTrans, sTrans := newTestTransportPair(true)

	c2handler := &testConn2Handler{}

	client := NewConnection2(cTrans, RoleClient, testTlsConfig, c2handler)
	assertNotNil(t, client, "Couldn't make client")

	server := NewConnection(sTrans, RoleServer, testTlsConfig, nil)
	assertNotNil(t, server, "Couldn't make server")

	err := client.sendClientInitial()
	assertNotError(t, err, "Couldn't send client initial packet")

	for client.state != StateEstablished && server.state != StateEstablished {
		err = inputAll(server)
		assertNotError(t, err, "Error processing CI")

		err = inputAll2(client)
		assertNotError(t, err, "Error processing SH")
	}

	// Force the client to get the ACK from the server
	server.CheckTimer()
	err = inputAll2(client)
	assertNotError(t, err, "Error reading ACK")

	// Write data C->S
	cs := client.CreateStream()
	assertNotNil(t, cs, "Failed to create a stream")
	cs.Write(testString)

	// Read data S->C
	inputAll(server)
	c2s_r := server.GetRecvStream(1)
	b := c2s_r.readAll()
	assertNotNil(t, b, "Read data from server")
	assertByteEquals(t, []byte(testString), b)

	// Write data S->C
	s2c_w := server.CreateRelatedSendStream(c2s_r)
	for i, _ := range b {
		b[i] ^= 0xff
	}
	s2c_w.Write(b)

	// Read data S->C
	err = inputAll2(client)
	assertX(t, nil == c2handler.lastCreated, "No handlers created")
	assertEquals(t, cs, c2handler.lastReadable)
	assertNotError(t, err, "Couldn't read input packets")
	b2 := make([]byte, 1000)
	n, err := cs.Read(b2)
	assertNotError(t, err, "Should be able to read")
	assertEquals(t, len(b), n)
	b2 = b2[:n]
	assertByteEquals(t, b, b2)

	// Now test a stream made in the opposite direction.
	s2c_w2 := server.CreateSendStream()
	s2c_w2.Write(testString)

	// Read data S->C on the new stream. This should make
	// stream #2.
	err = inputAll2(client)
	assertNotError(t, err, "Inputall on client")
	cs2 := client.GetStream(4)
	assertEquals(t, cs2, c2handler.lastCreated)
	assertEquals(t, cs2, c2handler.lastReadable)
	assertNotNil(t, cs2, "Should be able to get stream 2")

	// Now read the data.
	b2 = make([]byte, 1000)
	n, err = cs2.Read(b2)
	assertNotError(t, err, "Should be able to read")
	assertEquals(t, len(testString), n)
	b2 = b2[:n]
	assertByteEquals(t, testString, b2)

	// Write the response.
	cs2.Write(testString2)

	// Read the data on the server
	inputAll(server)
	c2s_r2 := server.GetRecvStream(2)
	b = c2s_r2.readAll()
	assertNotNil(t, b, "Read data from server")
	assertByteEquals(t, []byte(testString2), b)

}
