package main

import (
	"flag"
	"fmt"
	"github.com/ekr/minq"
	"net"
	"os"
)

var addr string

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

	// Flip the case so we can distinguish echo
	for i, _ := range b {
		if b[i] > 0x40 {
			b[i] ^= 0x20
		}
	}
	os.Stdout.Write(b)
}

func readUDP(s *net.UDPConn) []byte {
	b := make([]byte, 8192)

	n, _, err := s.ReadFromUDP(b)
	if err != nil {
		fmt.Println("Error reading from UDP socket: ", err)
		return nil
	}

	if n == len(b) {
		fmt.Println("Underread from UDP socket")
		return nil
	}
	b = b[:n]
	return b
}

func main() {
	flag.StringVar(&addr, "addr", "localhost:4433", "[host:port]")
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

	utrans := minq.NewUdpTransport(usock, uaddr)

	conn := minq.NewConnection(utrans, minq.RoleClient, minq.TlsConfig{}, &connHandler{})

	// Start things off.
	_, err = conn.CheckTimer()

	for conn.GetState() != minq.StateEstablished {
		b := readUDP(usock)
		if b == nil {
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
			b := readUDP(usock)
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
			err = conn.Input(u)
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
