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
		fmt.Println("Invalid UDP addr: ", err)
		return
	}

	usock, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		fmt.Println("Couldn't listen on UDP: ", err)
		return
	}

	server := minq.NewServer(minq.NewUdpTransportFactory(usock), minq.TlsConfig{})
		
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

		conn, err := server.Input(addr, b)
		if err != nil {
			fmt.Println("server.Input returned error: ", err)
			return
		}

		if conn.Established() {
			fmt.Println("Connection established to ", addr)
		}
	}
}
