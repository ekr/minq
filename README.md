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

Other defects include:

- Doesn't properly clean up state
- TLS configuration and verification

**WARNING: Minq is absolutely not ready for any kind production use and should only be used for testing. **