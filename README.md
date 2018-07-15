![A mink forming a Q](/minq.png)

minq -- A minimal QUIC stack
============================
Minq is a minimal implementation of QUIC, as documented at
https://quicwg.github.io/. Minq partly implements draft-05
(it advertises -04 but it's actually more like the editor's copy)
with TLS 1.3 draft-20 or draft-21.

Currently it will do:

- A 1-RTT handshake (with self-generated and unverified certificates)
- Some ACK processing
- Primitive retransmission (manual, no timers)
- 1-RTT application data
- Exchange of stream close (though this doesn't really have much impact)

Important missing pieces for the first implementation draft include:

- Handling ACK ranges
- Real timeout and retransmission support

Other defects include:

- Doesn't properly clean up state, so things will just grow without bound
- TLS configuration and verification
- A huge other pile of unknown and known defects.


## WARNING

Minq is absolutely not suitable for any kind of production use and should
only be used for testing. In particular, it explicitly doesn't validate
certificates.



## Quick Start (untested but should be rightish)

    cd ${GOPATH}/src
    go get github.com/ekr/minq
    cd github.com/bifurcation/mint
    git remote add ekr https://github.com/ekr/mint
    git fetch ekr
    git checkout ekr/quic_record_layer
    cd ../../ekr/minq
    go test

This should produce something like this:

    Result =  010002616263
    Result2 =  010002616263
    Result =  0102616263
    Result2 =  0102616263
    {1 2 [97 98 99]}
    {1 1 [8 16]}
    {3 2 [8 16 24 32]}
    Checking client state
    Checking server state
    Encoded frame  ab00deadbeef0000000000000001
    Encoded frame  bb0100deadbeef00000000000000010e00000001
    Result =  820123456789abcdefdeadbeefff000001
    Result2 =  820123456789abcdefdeadbeefff000001
    PASS
    ok  	github.com/ekr/minq	1.285s

It's the "ok" at the end that's important.

There are two test programs that live in ```minq/bin/client``` and
```minq/bin/server```. The server is an echo server that upcases the
returned data. The client is just a passthrough.

In ```${GOPATH}/src/github.com/ekr```, doing

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

Multiple log levels can be separated by commas.

## Mint

Minq depends on Mint (https://www.github.com/bifurcation/mint) for TLS.
Right now we are on the following branch:

https://github.com/ekr/mint/tree/quic_record_layer

This branch is more experimental than usual.

