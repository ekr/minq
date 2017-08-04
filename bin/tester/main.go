package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/ekr/minq"
	"io/ioutil"
	"strings"
)

var infile string
var serverName string
var dehex bool

type stdoutTransport struct {
}

func (t *stdoutTransport) Send(p []byte) error {
	fmt.Printf("Output=%v", hex.Dump(p))
	return nil
}

type connHandler struct {
}

func (h *connHandler) StateChanged(s minq.State) {
	fmt.Println("State changed to ", s)
}

func (h *connHandler) NewStream(s *minq.Stream) {
	fmt.Println("New stream")
}

func (h *connHandler) StreamReadable(s *minq.Stream) {
	fmt.Println("Stream readable")
}

func main() {
	flag.StringVar(&infile, "infile", "input", "input file")
	flag.StringVar(&serverName, "server-name", "", "SNI")
	flag.BoolVar(&dehex, "hex", true, "file is in hex")
	flag.Parse()

	in, err := ioutil.ReadFile(infile)
	if err != nil {
		fmt.Println("Couldn't read file")
	}

	if dehex {
		s := string(in)
		s = strings.Replace(s, " ", "", -1)
		s = strings.Replace(s, "\n", "", -1)
		in, err = hex.DecodeString(s)
		if err != nil {
			fmt.Println("Couldn't hex decode input")
		}

	}

	strans := &stdoutTransport{}
	conn := minq.NewConnection(strans, minq.RoleServer,
		minq.NewTlsConfig(serverName), &connHandler{})
	err = conn.Input(in)
	if err != nil {
		fmt.Println("Couldn't process input: ", err)
	}
}
