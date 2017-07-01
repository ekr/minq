package minq

import (
	"net"
)

// TransportFactory makes transports bound to a specific remote
// address.
type TransportFactory interface {
	makeTransport(remote *net.UDPAddr) (Transport, error)
}

// Server represents a QUIC server.
type Server struct {
	handler      ServerHandler
	transFactory TransportFactory
	tls          TlsConfig
	addrTable    map[string]*Connection
	idTable      map[connectionId]*Connection
}

type ServerHandler interface {
	NewConnection(c *Connection)
}

func (s *Server) Input(addr *net.UDPAddr, data []byte) (*Connection, error) {
	logf(logTypeServer, "Received packet from %v", addr)
	var hdr packetHeader

	_, err := decode(&hdr, data)
	if err != nil {
		return nil, err
	}

	var conn *Connection

	if hdr.hasConnId() {
		logf(logTypeServer, "Received conn id %v", hdr.ConnectionID)
		conn = s.idTable[hdr.ConnectionID]
		if conn != nil {
			logf(logTypeServer, "Found by conn id")
		}
	}

	if conn == nil {
		conn = s.addrTable[addr.String()]
	}

	if conn == nil {
		logf(logTypeServer, "New server connection from addr %v", addr)
		trans, err := s.transFactory.makeTransport(addr)
		if err != nil {
			return nil, err
		}
		conn = NewConnection(trans, RoleServer, s.tls, nil)
		s.idTable[conn.serverConnId] = conn
		s.addrTable[addr.String()] = conn

		if s.handler != nil {
			s.handler.NewConnection(conn)
		}
	}

	return conn, conn.Input(data)
}

func NewServer(factory TransportFactory, tls TlsConfig, handler ServerHandler) *Server {
	return &Server{
		handler,
		factory,
		tls,
		make(map[string]*Connection),
		make(map[connectionId]*Connection),
	}
}
