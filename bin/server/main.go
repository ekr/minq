package main

import (
	"flag"
	"fmt"
	"net"

	"github.com/ekr/minq"
)

var addr string

type serverHandler struct {
}

func (h *serverHandler) NewConnection(c *minq.Connection) {
	fmt.Println("New connection")
	c.SetHandler(&connHandler{})
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
	s.Write(b)
}

func main() {
	flag.StringVar(&addr, "addr", "localhost:4433", "[host:port]")
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

	server := minq.NewServer(minq.NewUdpTransportFactory(usock), minq.TlsConfig{}, &serverHandler{})

	for {
		b := make([]byte, 8192)

		n, addr, err := usock.ReadFromUDP(b)
		if err != nil {
			fmt.Println("Error reading from UDP socket: ", err)
			return
		}

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
}
