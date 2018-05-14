package main

import (
	"flag"
	"fmt"
	"github.com/ekr/minq"
	"net"
	"time"
)

var addr string
var server bool

type connHandler struct {
}

func (h *connHandler) StateChanged(s minq.State) {
	fmt.Println("State changed to ", s)
}

func (h *connHandler) NewStream(s *minq.Stream) {
}

func (h *connHandler) StreamReadable(s *minq.Stream) {
}

func readUDP(s *net.UDPConn) ([]byte, error) {
	b := make([]byte, 8192)

	s.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := s.ReadFromUDP(b)
	if err != nil {
		e, o := err.(net.Error)
		if o && e.Timeout() {
			return nil, minq.ErrorWouldBlock
		}
		fmt.Println("Error reading from UDP socket: ", err)
		return nil, err
	}

	if n == len(b) {
		fmt.Println("Underread from UDP socket")
		return nil, err
	}
	b = b[:n]
	return b, nil
}

func main() {
	flag.StringVar(&addr, "addr", "localhost:4433", "[host:port]")
	flag.BoolVar(&server, "server", false, "Run as server]")
	flag.Parse()

	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		fmt.Println("Invalid UDP addr", err)
		return
	}

	usock, err := net.ListenUDP("udp", nil)
	if err != nil {
		fmt.Println("Couldn't create connected UDP socket")
		return
	}

	role := minq.RoleClient
	if server {
		_, port, err := net.SplitHostPort(usock.LocalAddr().String())
		if err != nil {
			return
		}
		fmt.Println(port)
		role = minq.RoleServer
	}
	fmt.Printf("Remote addr=%v\n", addr)
	utrans := minq.NewUdpTransport(usock, uaddr)
	config := minq.NewTlsConfig("localhost")

	conn := minq.NewConnection(utrans, role, &config, nil)

	// Start things off.
	fmt.Println("Starting")
	_, err = conn.CheckTimer()

	for conn.GetState() != minq.StateEstablished {
		b, err := readUDP(usock)
		if err != nil {
			if err == minq.ErrorWouldBlock {
				_, err = conn.CheckTimer()
				if err != nil {
					return
				}
				continue
			}
			return
		}

		err = conn.Input(b)
		if err != nil {
			fmt.Println("Error", err)
			return
		}
	}

	fmt.Println("Connection established")
}
