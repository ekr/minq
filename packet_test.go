package minq

import (
	"crypto"
	"encoding/hex"
	"fmt"
	"github.com/bifurcation/mint"
	"testing"
)

var (
	testCid7    = ConnectionId([]byte{7, 7, 7, 7, 7, 7, 7})
	testCid4    = ConnectionId([]byte{4, 4, 4, 4})
	testCid5    = ConnectionId([]byte{5, 5, 5, 5, 5})
	testVersion = VersionNumber(0xdeadbeef)
	testPn      = uint64(0xff000001)
)

// Packet header tests.
func packetHeaderEDE(t *testing.T, p *packetHeader, cidLen uintptr) {
	res, err := encode(p)
	assertNotError(t, err, "Could not encode")
	fmt.Println("Encoded = ", hex.EncodeToString(res))

	var p2 packetHeader
	p2.shortCidLength = cidLen
	_, err = decode(&p2, res)
	assertNotError(t, err, "Could not decode")
	fmt.Println("Decoded = ", p2)

	res2, err := encode(&p2)
	assertNotError(t, err, "Could not re-encode")
	fmt.Println("Encoded2 =", hex.EncodeToString(res2))
	assertByteEquals(t, res, res2)
}

func TestLongHeader(t *testing.T) {
	p := newPacket(packetTypeInitial, testCid7, testCid4, testVersion,
		testPn, make([]byte, 65), 16)
	p.Token = []byte{1, 2, 3}
	p.TokenLength = uint8(len(p.Token))
	packetHeaderEDE(t, &p.packetHeader, 0)
}

func TestShortHeader(t *testing.T) {
	p := newPacket(packetTypeProtectedShort, testCid7, testCid4, testVersion,
		testPn, make([]byte, 65), 16)

	// We have to provide assistance to the decoder for short headers.
	// Otherwise, it can't know long the destination connection ID is.
	packetHeaderEDE(t, &p.packetHeader, uintptr(len(p.DestinationConnectionID)))
}

func testPNEDecrypt(t *testing.T, pbytes []byte, pn uint64, pnLen int, pnef pneCipherFactory) {
	// Now decode the packet.
	hdr2 := packetHeader{shortCidLength: kCidDefaultLength}

	hdrlen2, err := decode(&hdr2, pbytes)
	assertNotError(t, err, "Couldn't decode encrypted packet")

	dpn := make([]byte, 4)
	err = xorPacketNumber(&hdr2, int(hdrlen2), dpn, pbytes, pnef)
	assertNotError(t, err, "Couldn't XOR the packet number")
	assertEquals(t, 4, len(dpn))

	pn2, l2, err := decodePacketNumber(dpn)
	assertNotError(t, err, "Couldn't decode packet number")
	assertEquals(t, l2, pnLen)
	assertEquals(t, pn2, pn)
}

func DISABLE_TestPNEVector(t *testing.T) {
	kPacketHex := "ffff00000d52deded38ae772dc18ccad2d479900449750f9a1eb1c2a7f2b6e0b9ab295ba41b16e97edc7d8aa861ded8fd10ac741199fb3dd084dec6c93c3e5c2653dc5875faf7a8cdb33df4c212967296923cbb4eb9a7bc8d7bbd57d4cbb3e2d225f2ef7c9c31edaf760fb93014582f506e5eafe9af0eb45cbd1221e49510fbc3468eec2435eb9221890c0eab6066afd14aecb53b05f55795d1ecdf32e7f0d7da3b5a3e7aa217c1b87ab47576d7b1e0cad5a910ed20ff5ecd42b68441bbd86b1464c562292aa4f0aac6522cd98ebe91fdcae62c43b6a3132bcdd285a66551c5539fcf034d688832b8b8aa6a755a25138bcf49193c05ab0bb15045d71e0f18207b5f4c135369277b18bc8a9507ca841fb50194546a435827373bf4e319b24d9eaa504b7d16f8319c7b226b959c8e9fe99211272b85b033899c0f28ee3b77a0b1d79192fdae151cad61722b8c3fe8e9c57b72fe8a5da4a224867b5b8f4b910d376fc816168cac1914d72bc55a30fb407c783c414ba5ea35486281b793f168c2ce89665478f68a4d6894ed379266638f51ecf620a64e3453d2a9bf9b31abcb86a2bf6681ca2fcecaabf06ef6599ea883ff96b088be354cc529d32e50fc0d2a6a95fb1333e92319e0ee40c88b814425ce23d52bedf29d419c6fe63d665976015655bf568d8c12622166b254381233833d0f77c9fa00f08fbebbfe238decc3b2aceab8574d1d9dd31febcf891b0830c6b2e9c0c0891c95a32d58a6336d95bcbd23ff220c50860f9c0dda2816104fbb21eefaa93ab676272950c58c63179b38e60cc468b944a01fc0c1addbc6ba4edb77e73c33aa894c60c8b37fd3237d97b2830e5d53165130cd78e59dd2fb61feaa3f9b89ea8cd18e368fda3ece0d74025c39123e52c4baf8157b4b4f8bc4e20d20de5d12298c07800a5b40b1bb665b1421584f54277ba3b9ea1b66106a6a01c5341f88e8923d552e643a4305a9a186387892d35a42e6f0f03f39cbb58a173fda6aab9e20db1e2807098519ba7f2e314058ed1e9dbbc0a721d2e1b64c81865028f179aef1885b838500841859c5a43be530bdaec1d37011a984866576e5440d21732ecaf9217f1a3d88b895a47d117911d6cd7a80b422a4798db5e0ce0718cf407ea29b334c33fea424ba3ed78a0fa37e7d8c3ca926e45bd00b9c9486699821d0892b1afcd4191f8239691d00c1e852f66efa0d69bbd4c4b935c9388af1a207741e739794ba738a40ba74dc4d79f319d8bff32966a071172c1947f29577179fb58d8e1d5d815a3b287a3df52fead008f4287972aa60ed89a5ef2eee873ab26aacf9631ea2852956d771bb2de2f323d34c240ac95fb66c497494e6e547ded7bab0f75f548d1c092e7c02d94797f37cfa755166bc64957005d33dd414755e9cc1e50cd7bc8e39f8de0d03ac1cfc4354d34d7d2bf9aeaf8fd432e4756396c11286e8d2901deb017e62a34658761850f5b83c8cd9fecf4ec0263b28dcf11821ac8107ca69384f585056e612a97a88e79944bf508b0108b68c92193d1e82ae92253b25ffeb41b498e91371bd2442825102d4b65ebb10e359d04811381b6fb8a83ab40e4d40c27e95f705113e546268e1e3f797fe8bf9ae7edd651c71500b8bd2e8f35baa639a38df7f15e2e9b3e877ab904fa6541f074cf1b8de686ac3bdc9586bb54bf1a5f01f67a"
	kPacket := unhex(kPacketHex)

	hdr2 := packetHeader{shortCidLength: kCidDefaultLength}
	_, err := decode(&hdr2, kPacket)
	assertNotError(t, err, "Couldn't decode encrypted packet")

	params := mint.CipherSuiteParams{
		Suite:  mint.TLS_AES_128_GCM_SHA256,
		Cipher: nil,
		Hash:   crypto.SHA256,
		KeyLen: 16,
		IvLen:  12,
	}

	cs, err := generateCleartextKeys(hdr2.DestinationConnectionID, clientCtSecretLabel,
		&params)
	assertNotError(t, err, "Couldn't generate cleartext keys")
	testPNEDecrypt(t, kPacket, 1, 4, cs.pne)
}

func testPNE(t *testing.T, pt packetType) {
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	payload := make([]byte, 65)
	p := newPacket(pt, testCid5, testCid4, testVersion,
		0xfe, payload, 16)

	hdr, err := encode(&p.packetHeader)
	assertNotError(t, err, "Couldn't encode packet header")

	pnbytes := encodePacketNumber(p.PacketNumber, 2)

	pbytes := append(hdr, pnbytes...)
	pbytes = append(pbytes, payload...)

	pnef := newPneCipherFactoryAES(key)

	// Encode the packet in place.
	err = xorPacketNumber(&p.packetHeader, len(hdr), pbytes[len(hdr):len(hdr)+len(pnbytes)], pbytes, pnef)
	assertNotError(t, err, "Couldn't XOR the packet number")

	// Now decode the packet.
	testPNEDecrypt(t, pbytes, p.PacketNumber, len(pnbytes), pnef)
}

func TestPNE(t *testing.T) {
	t.Run("Long", func(t *testing.T) {
		testPNE(t, packetTypeInitial)
	})
	t.Run("Short", func(t *testing.T) {
		testPNE(t, packetTypeProtectedShort)
	})
}

/*
* TODO(ekr@rtfm.com): Rewrite this code and merge it into
* connection.go
// Mock for connection state
type ConnectionStateMock struct {
	aead aeadFNV
}

func (c *ConnectionStateMock) established() bool    { return false }
func (c *ConnectionStateMock) zeroRttAllowed() bool { return false }
func (c *ConnectionStateMock) expandPacketNumber(pn uint64) uint64 {
	return pn
}

func TestEDEPacket(t *testing.T) {
	var c ConnectionStateMock

	p := Packet{
		kTestpacketHeader,
		[]byte{'a', 'b', 'c', 'd', 'e', 'f', 'g'},
	}

	encoded, err := encodePacket(&c, &c.aead, &p)
	assertNotError(t, err, "Could not encode packet")

	p2, err := decodePacket(&c, &c.aead, encoded)
	assertNotError(t, err, "Could not decode packet")

	encoded2, err := encodePacket(&c, &c.aead, p2)
	assertNotError(t, err, "Could not re-encode packet")

	assertByteEquals(t, encoded, encoded2)
}
*/

func testPacketNumberED(t *testing.T, pn uint64, l int) {
	b := encodePacketNumber(pn, l)
	assertEquals(t, l, len(b))

	pn2, l2, err := decodePacketNumber(b)
	assertNotError(t, err, "Error decoding packet number")
	assertEquals(t, l2, l)

	mask := uint64(0)
	for i := 0; i < l; i++ {
		mask <<= 8
		mask |= 0xff
	}
	assertEquals(t, mask&pn, pn2)
}

func TestPacketNumberED(t *testing.T) {
	val := uint64(0x04030201)

	for _, i := range []int{1, 2, 4} {
		t.Run(fmt.Sprintf("%v", i), func(t *testing.T) {
			testPacketNumberED(t, val, i)
		})
	}
}
