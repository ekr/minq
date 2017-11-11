package main

import (
	"flag"
	"fmt"
	"github.com/ekr/minq"
	"net"
	"os"
	"runtime/pprof"
	"time"
)

var addr string
var serverName string
var doHttp string
var httpCount int
var heartbeat int
var cpuProfile string

type connHandler struct {
	bytesRead int
}

func (h *connHandler) StateChanged(s minq.State) {
	fmt.Println("State changed to ", minq.StateName(s))
}

func (h *connHandler) NewStream(s *minq.Stream) {
}

func (h *connHandler) StreamReadable(s *minq.Stream) {
	for {
		b := make([]byte, 1024)

		n, err := s.Read(b)
		switch err {
		case nil:
			break
		case minq.ErrorWouldBlock:
			return
		case minq.ErrorStreamIsClosed, minq.ErrorConnIsClosed:
			fmt.Println("<CLOSED>")
			return
		default:
			fmt.Println("Error: ", err)
			return
		}
		b = b[:n]
		h.bytesRead += n
		os.Stdout.Write(b)
		os.Stderr.Write([]byte(fmt.Sprintf("Total bytes read = %d\n", h.bytesRead)))
	}
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
	fmt.Println("PID=", os.Getpid())
	flag.StringVar(&addr, "addr", "localhost:4433", "[host:port]")
	flag.StringVar(&serverName, "server-name", "", "SNI")
	flag.StringVar(&doHttp, "http", "", "Do HTTP/0.9 with provided URL")
	flag.IntVar(&httpCount, "httpCount", 1, "Number of parallel HTTP requests to start")
	flag.IntVar(&heartbeat, "heartbeat", 0, "heartbeat frequency [ms]")
	flag.StringVar(&cpuProfile, "cpuprofile", "", "write cpu profile to file")
	flag.Parse()

	if cpuProfile != "" {
		f, err := os.Create(cpuProfile)
		if err != nil {
			fmt.Printf("Could not create CPU profile file %v err=%v\n", cpuProfile, err)
			return
		}
		pprof.StartCPUProfile(f)
		fmt.Println("CPU profiler started")
		defer pprof.StopCPUProfile()
	}

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

	fmt.Printf("Client conn id=%x\n", conn.ClientId())

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

	// Make all the streams we need
	streams := make([]*minq.Stream, httpCount)
	for i := 0; i < httpCount; i++ {
		streams[i] = conn.CreateStream()
	}

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

	if heartbeat > 0 && doHttp == "" {
		ticker := time.NewTicker(time.Millisecond * time.Duration(heartbeat))
		go func() {
			for t := range ticker.C {
				stdin <- []byte(fmt.Sprintf("Heartbeat at %v\n", t))
			}
		}()
	}

	if doHttp == "" {
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
	} else {
		req := "GET " + doHttp + "\r\n"
		for _, str := range streams {
			str.Write([]byte(req))
			str.Close()
		}
	}

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
			streams[0].Write(i)
			if err != nil {
				fmt.Println("Error", err)
				return
			}
		}

	}
}
