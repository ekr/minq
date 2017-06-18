package main

import (
	"flag"
	"fmt"
	"net"
	
	"github.com/ekr/minq"	
)

var addr string

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
	
	conn := minq.NewConnection(utrans, minq.RoleClient, minq.TlsConfig{})

	// Start things off.
	_, err = conn.CheckTimer()

	for !conn.Established() {
		b := make([]byte, 8192)
		
		n, _, err := usock.ReadFromUDP(b)
		if err != nil {
			fmt.Println("Error reading from UDP socket: ", err)
			return
		}

		if n == len(b) {
			fmt.Println("Underread from UDP socket")
			return
		}
		b = b[:n]
		
		err = conn.Input(b)
		if err != nil {
			fmt.Println("Error in QUIC handshake: ", err)
			return
		}
	}

	fmt.Println("Connection established")
}
