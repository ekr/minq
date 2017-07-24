package main

import (
	"flag"
	"fmt"
	"github.com/ekr/minq"
	"net"
	"time"
)

var addr string
var serverName string

type conn struct {
	conn *minq.Connection
	last time.Time
}

func (c *conn) checkTimer() {
	t := time.Now()
	if t.After(c.last.Add(time.Second)) {
		c.conn.CheckTimer()
		c.last = time.Now()
	}
}

var conns = make(map[minq.ConnectionId]*conn)

type serverHandler struct {
}

func (h *serverHandler) NewConnection(c *minq.Connection) {
	fmt.Println("New connection")
	c.SetHandler(&connHandler{})
	conns[c.Id()] = &conn{c, time.Now()}
}

type connHandler struct {
}

func (h *connHandler) StateChanged(s minq.State) {
	fmt.Println("State changed to ", s)
}

func (h *connHandler) NewStream(s *minq.Stream) {
	fmt.Println("Created new stream id=", s.Id())
}

func (h *connHandler) StreamReadable(s *minq.Stream) {
	fmt.Println("Ready to read for stream id=", s.Id())
	b := make([]byte, 1024)

	n, err := s.Read(b)
	if err != nil {
		fmt.Println("Error reading")
		return
	}
	b = b[:n]

	fmt.Printf("Read %v bytes from peer %x\n", n, b)

	// Flip the case so we can distinguish echo
	for i, _ := range b {
		if b[i] > 0x40 {
			b[i] ^= 0x20
		}
	}

	s.Write(b)
}

func main() {
	flag.StringVar(&addr, "addr", "localhost:4433", "[host:port]")
	flag.StringVar(&serverName, "server-name", "localhost", "[SNI]")
	flag.Parse()

	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		fmt.Println("Invalid UDP addr: ", err)
		return
	}

	usock, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		fmt.Println("Couldn't listen on UDP: ", err)
		return
	}

	server := minq.NewServer(minq.NewUdpTransportFactory(usock), minq.NewTlsConfig(serverName), &serverHandler{})

	for {
		b := make([]byte, 8192)

		usock.SetDeadline(time.Now().Add(time.Second))
		n, addr, err := usock.ReadFromUDP(b)
		if err != nil {
			e, o := err.(net.Error)
			if !o || !e.Timeout() {
				fmt.Println("Error reading from UDP socket: ", err)
				return
			}
			n = 0
		}

		// If we read data, process it.
		if n > 0 {
			if n == len(b) {
				fmt.Println("Underread from UDP socket")
				return
			}
			b = b[:n]

			_, err = server.Input(addr, b)
			if err != nil {
				fmt.Println("server.Input returned error: ", err)
				return
			}
		}

		// Check all the timers
		for _, c := range conns {
			c.checkTimer()
		}
	}
}
