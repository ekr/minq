package main

import (
	"flag"
	"fmt"
	"github.com/ekr/minq"
	"net"
	"os"
	"time"
)

var addr string
var serverName string

type connHandler struct {
}

func (h *connHandler) StateChanged(s minq.State) {
	fmt.Println("State changed to ", s)
}

func (h *connHandler) NewStream(s *minq.Stream) {
}

func (h *connHandler) StreamReadable(s *minq.Stream) {
	b := make([]byte, 1024)

	n, err := s.Read(b)
	if err != nil {
		fmt.Println("Error reading")
		return
	}
	b = b[:n]

	os.Stdout.Write(b)
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
	flag.StringVar(&serverName, "server-name", "", "SNI")
	flag.Parse()

	// Default to the host component of addr.
	if serverName == "" {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			fmt.Println("Couldn't split host/port", err)
		}
		serverName = host
	}

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

	utrans := minq.NewUdpTransport(usock, uaddr)

	conn := minq.NewConnection(utrans, minq.RoleClient,
		minq.NewTlsConfig(serverName), &connHandler{})

	// Start things off.
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

	str := conn.CreateStream()

	udpin := make(chan []byte)
	stdin := make(chan []byte)

	// Read from the UDP socket.
	go func() {
		for {
			b, err := readUDP(usock)
			if err == minq.ErrorWouldBlock {
				udpin <- make([]byte, 0)
				continue
			}
			udpin <- b
			if b == nil {
				return
			}
		}
	}()

	// Read from stdin.
	go func() {
		for {
			b := make([]byte, 1024)
			n, err := os.Stdin.Read(b)
			if err != nil {
				stdin <- nil
				return
			}
			b = b[:n]
			stdin <- b
		}
	}()

	for {
		select {
		case u := <-udpin:
			if len(u) == 0 {
				_, err = conn.CheckTimer()
			} else {
				err = conn.Input(u)
			}
			if err != nil {
				fmt.Println("Error", err)
				return
			}
		case i := <-stdin:
			if i == nil {
				conn.Close()
				return
			}
			str.Write(i)
			if err != nil {
				fmt.Println("Error", err)
				return
			}
		}

	}
}
