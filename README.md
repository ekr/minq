![A mink forming a Q](/minq.png)

minq -- A minimal QUIC stack
============================
Minq is a minimal implementation of QUIC, as documented at
https://quicwg.github.io/. Minq partly implements draft-04.

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
- Proper handling of ACKs of ACKs (right now ACKs grow without bound).

Other defects include:

- Doesn't properly clean up state
- TLS configuration and verification


## Mint Versions

Minq depends on Mint (https://www.github.com/bifurcation/mint) for TLS.
There are some changes to Mint to support QUIC that haven't been
merged yet, so in the meantime you will want the following branch:
https://github.com/ekr/mint/tree/expose_internals


## WARNING

Minq is absolutely not ready for any kind of production use and should only be used for testing.


