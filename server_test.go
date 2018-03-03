package minq

import (
	"net"
	"testing"
	"time"
)

// fake TransportFactory that comes populated with
// a set of pre-fab transports keyed by name.
type testTransportFactory struct {
	transports map[string]*testTransport
}

func (f *testTransportFactory) MakeTransport(remote *net.UDPAddr) (Transport, error) {
	return f.transports[remote.String()], nil
}

func (f *testTransportFactory) addTransport(remote *net.UDPAddr, t *testTransport) {
	f.transports[remote.String()] = t
}

func serverInputAll(t *testing.T, trans *testTransport, s *Server, u net.UDPAddr) (*Connection, error) {
	var clast *Connection

	for {
		p, err := trans.Recv()
		if err != nil && err != ErrorWouldBlock {
			return nil, err
		}

		if p == nil {
			return clast, nil
		}

		c, err := s.Input(&u, p)
		if err != nil {
			return nil, err
		}

		if clast == nil {
			clast = c
		}
		assertEquals(t, c, clast)
	}
}

func TestServer(t *testing.T) {
	// Have the client and server do a handshake.
	u, _ := net.ResolveUDPAddr("udp", "127.0.0.1:4443") // Just a fixed address

	cTrans, sTrans := newTestTransportPair(true)
	factory := &testTransportFactory{make(map[string]*testTransport)}
	factory.addTransport(u, sTrans)

	server := NewServer(factory, testTlsConfig(), nil)
	assertNotNil(t, server, "Couldn't make server")

	client := NewConnection(cTrans, RoleClient, testTlsConfig(), nil)
	assertNotNil(t, client, "Couldn't make client")

	n, err := client.CheckTimer()
	assertEquals(t, 1, n)
	assertNotError(t, err, "Couldn't send client initial")

	s1, err := serverInputAll(t, sTrans, server, *u)
	assertNotError(t, err, "Couldn't consume client initial")

	err = inputAll(client)
	assertNotError(t, err, "Error processing SH")

	s2, err := serverInputAll(t, sTrans, server, *u)
	assertNotError(t, err, "Error processing CFIN")
	// Make sure we get the same server back.
	assertEquals(t, s1, s2)

	// Now make a new client and ensure we get a different server connection
	u2, _ := net.ResolveUDPAddr("udp", "127.0.0.1:4444") // Just a fixed address
	cTrans2, sTrans2 := newTestTransportPair(true)
	factory.addTransport(u2, sTrans2)
	client = NewConnection(cTrans2, RoleClient, testTlsConfig(), nil)
	assertNotNil(t, client, "Couldn't make client")

	n, err = client.CheckTimer()
	assertEquals(t, 1, n)
	assertNotError(t, err, "Couldn't send client initial")

	s3, err := serverInputAll(t, sTrans2, server, *u2)
	assertNotError(t, err, "Couldn't consume client initial")

	assertX(t, s1 != s3, "Got the same server connection back with a different address")
	assertEquals(t, 2, len(server.addrTable))
}

func TestServerIdleTimeout(t *testing.T) {
	// Have the client and server do a handshake.
	u, _ := net.ResolveUDPAddr("udp", "127.0.0.1:4443") // Just a fixed address

	cTrans, sTrans := newTestTransportPair(true)
	factory := &testTransportFactory{make(map[string]*testTransport)}
	factory.addTransport(u, sTrans)

	server := NewServer(factory, testTlsConfig(), nil)
	assertNotNil(t, server, "Couldn't make server")

	client := NewConnection(cTrans, RoleClient, testTlsConfig(), nil)
	assertNotNil(t, client, "Couldn't make client")

	n, err := client.CheckTimer()
	assertEquals(t, 1, n)
	assertNotError(t, err, "Couldn't send client initial")

	_, err = serverInputAll(t, sTrans, server, *u)
	assertNotError(t, err, "Couldn't consume client initial")

	assertEquals(t, 1, server.ConnectionCount())

	// Now wait 15 seconds to make sure that the connection
	// gets garbage collected.

	time.Sleep(time.Second * 15)
	server.CheckTimer()
	assertEquals(t, 0, server.ConnectionCount())
}
