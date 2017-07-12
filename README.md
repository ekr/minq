![A mink forming a Q](/minq.png)

minq -- A minimal QUIC stack
============================
Minq is a minimal implementation of QUIC, as documented at
https://quicwg.github.io/. Minq partly implements draft-04
(it advertises -04 but it's actually more like the editor's copy).

Currently it will do:

- A 1-RTT handshake (with self-generated and unverified certificates)
- Some ACK processing
- Primitive retransmission (manual, no timers)
- 1-RTT application data
- Exchange of stream close (though this doesn't really have much impact)

Important missing pieces for the first implementation draft include:

- Version negotiation
- ALPN
- Handling ACK ranges
- Real timeout and retransmission support

Other defects include:

- Doesn't properly clean up state, so things will just grow without bound
- TLS configuration and verification
- A huge other pile of unknown and known defects.


## WARNING

Minq is absolutely not ready for any kind of production use and should
only be used for testing.



## Quick Start (untested but should be rightish)


    cd ${GOPATH}
    go get github.com/ekr/minq
    cd github.com/bifurcation/mint
    git remote add ekr https://www.github.com/ekr/mint
    git fetch ekr
    git checkout minq_head
    cd ../../ekr/minq
    go test


## Test Programs

There are two test programs that live in ```minq/bin/client``` and
```minq/bin/server```. The server is an echo server that upcases the
returned data. The client is just a passthrough.

Doing

    go run minq/bin/server/main.go
    go run minq/bin/client/main.go

In separate windows should have the desired result.


## Logging

To enable logging, set the ```MINQ_LOG``` environment variable, as
in ```MINQ_LOG=connection go test```. Valid values are:

    // Pre-defined log types
    const (
    	logTypeAead       = "aead"
    	logTypeCodec      = "codec"
    	logTypeConnBuffer = "connbuffer"
    	logTypeConnection = "connection"
    	logTypeAck        = "ack"
    	logTypeFrame      = "frame"
    	logTypeHandshake  = "handshake"
    	logTypeTls        = "tls"
    	logTypeTrace      = "trace"
    	logTypeServer     = "server"
    	logTypeUdp        = "udp"
    )


## Mint

Minq depends on Mint (https://www.github.com/bifurcation/mint) for TLS.
There are some changes to Mint to support QUIC that haven't been
merged yet, so in the meantime you will want the following branch:
https://github.com/ekr/mint/tree/minq_head

