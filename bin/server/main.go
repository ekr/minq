package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/ekr/minq"
	"io/ioutil"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"runtime/pprof"
)

var addr string
var serverName string
var keyFile string
var certFile string
var logFile string
var logOut *os.File
var doHttp bool
var statelessReset bool
var cpuProfile string

// Shared data structures.
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

// An echo server.
type echoServerHandler struct {
}

func (h *echoServerHandler) NewConnection(c *minq.Connection) {
	fmt.Println("New connection")
	c.SetHandler(&echoConnHandler{})
	conns[c.Id()] = &conn{c, time.Now()}
}

type echoConnHandler struct {
}

func (h *echoConnHandler) StateChanged(s minq.State) {
	fmt.Println("State changed to ", s)
}

func (h *echoConnHandler) NewStream(s *minq.Stream) {
	fmt.Println("Created new stream id=", s.Id())
}

func (h *echoConnHandler) StreamReadable(s *minq.Stream) {
	fmt.Println("Ready to read for stream id=", s.Id())
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

	fmt.Printf("Read %v bytes from peer %x\n", n, b)

	// Flip the case so we can distinguish echo
	for i, _ := range b {
		if b[i] > 0x40 {
			b[i] ^= 0x20
		}
	}

	s.Write(b)
}

// An HTTP 0.9 Handler
type httpServerHandler struct {
}

func (h *httpServerHandler) NewConnection(c *minq.Connection) {
	fmt.Println("New connection")
	c.SetHandler(&httpConnHandler{make(map[uint32]*httpStream, 0)})
	conns[c.Id()] = &conn{c, time.Now()}
}

type httpStream struct {
	s      *minq.Stream
	buf    []byte
	closed bool
}

type httpConnHandler struct {
	streams map[uint32]*httpStream
}

func (h *httpConnHandler) StateChanged(s minq.State) {
	fmt.Println("State changed to ", s)
}

func (h *httpConnHandler) NewStream(s *minq.Stream) {
	h.streams[s.Id()] = &httpStream{s, nil, false}
}

func (h *httpStream) Respond(val []byte) {
	h.s.Write(val)
	h.s.Close()
	h.closed = true
}

func (h *httpStream) Error(err string) {
	h.Respond([]byte(err))
}

// We expect the URL to be one of two things:
//
// A number, in which case we respond with that number of
// Xs, up to 10,000
// A non-number, in which case we respond with 10 repetitions
// of that value.
func (h *httpConnHandler) StreamReadable(s *minq.Stream) {
	fmt.Println("Ready to read for stream id=", s.Id())
	st := h.streams[s.Id()]
	if st.closed {
		return
	}

	b := make([]byte, 1024)
	n, err := s.Read(b)
	if err != nil && err != minq.ErrorWouldBlock {
		fmt.Println("Error reading")
		return
	}
	b = b[:n]
	fmt.Printf("Read %v bytes from peer %x\n", n, b)

	st.buf = append(st.buf, b...)

	// See if we received a complete LF
	str := string(st.buf)
	idx := strings.IndexRune(str, '\n')
	if idx == -1 {
		return
	}
	str = str[:idx]

	// OK, we have a complete line.
	toks := strings.Split(str, " ")
	if toks[0] != "GET" {
		st.Error(fmt.Sprintf("Bogus method: %v", toks[0]))
		return
	}
	if len(toks) < 2 {
		st.Error("No resource")
		return
	}

	val := strings.TrimSpace(toks[1])

	if val[0] != '/' {
		st.Error(fmt.Sprintf("Bad value: %v", val))
		return
	}
	val = val[1:]

	count, err := strconv.ParseUint(val, 10, 32)
	var rsp []byte
	if err == nil {
		if count > 10000 {
			count = 10000
		}
		rsp = bytes.Repeat([]byte{'X'}, int(count))
	} else {
		rspstr := ""
		for i := 0; i < 10; i++ {
			rspstr += val
			rspstr += "--"
		}
		rspstr += "\n"
		rsp = []byte(rspstr)
	}
	st.Respond(rsp)
}

func logFunc(format string, args ...interface{}) {
	fmt.Fprintf(logOut, format, args...)
	fmt.Fprintf(logOut, "\n")
}

func main() {
	flag.StringVar(&addr, "addr", "localhost:4433", "[host:port]")
	flag.StringVar(&serverName, "server-name", "localhost", "[SNI]")
	flag.StringVar(&keyFile, "key", "", "Key file")
	flag.StringVar(&certFile, "cert", "", "Cert file")
	flag.StringVar(&logFile, "log", "", "Log file")
	flag.BoolVar(&doHttp, "http", false, "Do HTTP/0.9")
	flag.BoolVar(&statelessReset, "stateless-reset", false, "Do stateless reset")
	flag.StringVar(&cpuProfile, "cpuprofile", "", "write cpu profile to file")
	flag.Parse()

	var key crypto.Signer
	var certChain []*x509.Certificate

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

	config := minq.NewTlsConfig(serverName)
	config.ForceHrr = statelessReset

	if keyFile != "" && certFile == "" {
		fmt.Println("Can't specify -key without -cert")
		return
	}

	if keyFile == "" && certFile != "" {
		fmt.Println("Can't specify -cert without -key")
		return
	}

	if keyFile != "" && certFile != "" {
		keyPEM, err := ioutil.ReadFile(keyFile)
		if err != nil {
			fmt.Printf("Couldn't open keyFile %v err=%v", keyFile, err)
			return
		}
		key, err = helpers.ParsePrivateKeyPEM(keyPEM)
		if err != nil {
			fmt.Println("Couldn't parse private key: ", err)
			return
		}

		certPEM, err := ioutil.ReadFile(certFile)
		if err != nil {
			fmt.Printf("Couldn't open certFile %v err=%v", certFile, err)
			return
		}
		certChain, err = helpers.ParseCertificatesPEM(certPEM)
		if err != nil {
			fmt.Println("Couldn't parse certificates: ", err)
			return
		}
		config.CertificateChain = certChain
		config.Key = key
	}

	if logFile != "" {
		var err error
		logOut, err = os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println("Couldn't open file")
			return
		}
		minq.SetLogOutput(logFunc)
	}
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

	var handler minq.ServerHandler
	if doHttp {
		handler = &httpServerHandler{}
	} else {
		handler = &echoServerHandler{}
	}
	server := minq.NewServer(minq.NewUdpTransportFactory(usock), config, handler)

	stdin := make(chan []byte)
	go func() {
		for {
			b := make([]byte, 1024)
			n, err := os.Stdin.Read(b)
			if err == io.EOF {
				fmt.Println("EOF received")
				close(stdin)
				return
			} else if err != nil {
				fmt.Println("Error reading from stdin")
				return
			}
			b = b[:n]
			stdin <- b
		}
	}()


	for {

		select {
		case _, open := <- stdin:
			if open == false {
				fmt.Println("Shutdown signal received from stdin. Goodnight.")
				return
			}
		default:
		}

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

		// Check the timers.
		server.CheckTimer()
	}
}
