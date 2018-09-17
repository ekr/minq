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

func DISABLED_TestPNEVector(t *testing.T) {
	kPacketHex := "ffff00000d5006b858ec6f80452b0044efa5d8d307c2973fa0d63fd9b03a4e163b990dd778894a9edc8eacfbe4aa6fbf4a22ec7f906b5e8b8ae12e5fcc7924dfeee813842bb2149b805e55895084e8393200bb3fc618af7d08281485d914ce42303f5d772b200508a0c00253e332e36a84f657321ac4c8e2cc8a117e95871f12b1f36be8c4b76fa433dc4d3142e6547f4598bf4b192130aea6fc20da5158b2162b5a899957da05ded5c70907298fd885847f22a1ecb0a814fe0170e23cad20af64f05cc13c74e91824101afdcf5f1532fc2fde936a3a159f76283a26c738f778c76e6ca41fa7f134401d39027fd81de17a8021a9c0aaa9b4478fe5c0647941618f3bee410caf94c248d2a64b5e45845cd77de13a5ed94034d2bc5f457887351993c1ecfa34fd0c658fea3f8086d26808eef976262ecf0ad646b627945511dde83e26609cd5cfd7ed9f6207d76618b44c48bf623bf420dc7c127e5d5f529f083b71a17b17da329bfc38a74bf8cfcf315c7c070b71ebfae3ab351341a767adfdd9e57c738f5de9da53711e886d1472310b917a1c9798e3e9b13c7c74beb8d1b82345bea1349415679a9c64b0433b68c871ae08092a1f6106bc06337cd343866ee8185c03fcf3bb0666453f847905547199414c1e57535747be61cdf6778378f121d68df0181ee9e8d9932c1c593c0f8c0a1af0f5262b86205002dced9ecdaee2d0aa07dd4c14f98571e4bea72f8474f63697043e936ebb2bf9716ed0efbdc13005a75cee3a49babc61b9677764510eb19828df4e10fb38b79a1efbf04cc2d571949d5403f797361743dcc5e3bf3b4396f7ae1a3affbc9f72e540d920363970307e0725fa838d611803251a4a08ccca1983d5b29a583758be63343e88f5591d885b8af695f33adbdd0d941d260287e32ef5a98fd55ac137211021fdc23b5d7a5469f578bf7aff6529117996f9ebab5e6dc7b047b356332fea82fdd620eb86f3c1d3855c8b8075da59a7662f4a11b977d996b8b3c7657ad4a82a20a7f76ce376c0320086ed029dd615399307983113cc0aa973ecba691e7e4cdc80aefa7e8c8347baba050eaca7dc35a21aa854e531dc7758d7d10b8c8e42c1be3bbf266d055ac25c37279ebefa28bbe89a34ad1ab3d23d7a66d1c216a57650e6ec9fc8ba7adfb38e57f20c467166c8fe7944e67f82138160002004812c78ba4b5f0da917da4cc14cf8fc10dba3f533facb11ef06d8b8f178ea9c5e8acbbca7b7f0e1f6b7a70ec2d5108cc41178056295793bed357accbb03c0582dc69bc77a34030f38cce256c5a9cec6e862146e3f0463f10dd5833257d0a0359166a7e2027d98eaf26cf0d5a4a05f6ef8b742f5d314a31deeeabe4ebc3106547e79c6cb933105d907b4c8c60443e97a154694bab5edfc781a438675b9de6ed03c77f51458eab61ca2e80ac02cc8c037d8fb3cf129d7107f618d66032cc02238a211f78bfa44e7c1bbcfcc627771c188d1b3713ce5e75cd2325a0a2ba08268cad13b27d97696ef678b592d0ac80ad1bacb4a1ba75bea8c477f39fc32c2aa20f352bb0da1c49b7d3927bcd9dfaf229237081d5fa08924fefd923ff0ac6baad6864b7c10dc73379a5ebd9e4678a0c26517656e8e51fca2a51a33fb2cdd5d76d12674c240ba9a4893c1af69b8f2c4adf37c4a47551eb2006a732f6b3b2f338c078ede33946dfe4a55bf644d3b98848693ada1fcb6fc16cac339ee65c24dc64b0ae92005354af00ade71e6c5e2efd85c46131d948ff14096b0f06a41d83c8522f30beb4eaaf4a6f908fe2a6ee754c896"
	kPacket := unhex(kPacketHex)
	kPNLen := 4
	kPN := 0

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
	testPNEDecrypt(t, kPacket, uint64(kPN), kPNLen, cs.pne)
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
