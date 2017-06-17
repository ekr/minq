package minq

import (
	"net"
)

// TransportFactory makes transports bound to a specific remote
// address.
type TransportFactory interface {
	makeTransport(remote net.UDPAddr) Transport
}

// Server represents a QUIC server.
type Server struct {
	transFactory TransportFactory
	tls          TlsConfig
	addrTable    map[string]*Connection
	idTable      map[connectionId]*Connection
}

func (s *Server) input(addr net.UDPAddr, data []byte) (*Connection, error) {
	var hdr PacketHeader

	_, err := decode(&hdr, data)
	if err != nil {
		return nil, err
	}

	var conn *Connection

	if hdr.hasConnId() {
		conn = s.idTable[hdr.ConnectionID]
	}

	if conn == nil {
		conn = s.addrTable[addr.String()]
	}

	if conn == nil {
		conn = NewConnection(s.transFactory.makeTransport(addr), kRoleServer, s.tls)
	}

	return conn, conn.input(data)
}

func NewServer(factory TransportFactory, tls TlsConfig) *Server {
	return &Server{
		factory,
		tls,
		make(map[string]*Connection),
		make(map[connectionId]*Connection),
	}
}
