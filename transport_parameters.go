package minq

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/bifurcation/mint"
	"github.com/bifurcation/mint/syntax"
)

const (
	kQuicTransportParamtersXtn = mint.ExtensionType(0xffa5)
)

type TransportParameterId uint16

const (
	kTpIdInitialMaxStreamDataBidiLocal  = TransportParameterId(0x0000)
	kTpIdInitialMaxData                 = TransportParameterId(0x0001)
	kTpIdInitialMaxBidiStreams          = TransportParameterId(0x0002)
	kTpIdIdleTimeout                    = TransportParameterId(0x0003)
	kTpPreferredAddress                 = TransportParameterId(0x0004)
	kTpIdMaxPacketSize                  = TransportParameterId(0x0005)
	kTpIdStatelessResetToken            = TransportParameterId(0x0006)
	kTpIdAckDelayExponent               = TransportParameterId(0x0007)
	kTpIdInitialMaxUniStreams           = TransportParameterId(0x0008)
	kTpIdDisableMigration               = TransportParameterId(0x0009)
	kTpIdInitialMaxStreamDataBidiRemote = TransportParameterId(0x0010)
	kTpIdInitialMaxStreamDataUni        = TransportParameterId(0x0011)
)

const (
	kTpDefaultAckDelayExponent = byte(3)
)

type tpDef struct {
	parameter TransportParameterId
	val       uint32
	size      uintptr
}

var (
	kInitialMaxData             = uint64(65536)
	kInitialMaxStreamData       = uint64(8192)
	kConcurrentStreamsBidi      = 16
	kConcurrentStreamsUni       = 16
	kTransportParameterDefaults = []tpDef{
		{kTpIdInitialMaxStreamDataBidiLocal, uint32(kInitialMaxStreamData), 4},
		{kTpIdInitialMaxStreamDataBidiRemote, uint32(kInitialMaxStreamData), 4},
		{kTpIdInitialMaxStreamDataUni, uint32(kInitialMaxStreamData), 4},
		{kTpIdInitialMaxData, uint32(kInitialMaxData), 4},
		{kTpIdInitialMaxBidiStreams, uint32(kConcurrentStreamsBidi), 2},
		{kTpIdIdleTimeout, 5, 2},
		{kTpIdInitialMaxUniStreams, uint32(kConcurrentStreamsUni), 2},
	}
)

type transportParameters struct {
	maxStreamDataUni        uint32
	maxStreamDataBidiLocal  uint32
	maxStreamDataBidiRemote uint32
	maxData                 uint32
	maxStreamsBidi          int
	maxStreamsUni           int
	idleTimeout             uint16
	ackDelayExp             uint8
}

type TransportParameterList []transportParameter

type transportParameter struct {
	Parameter TransportParameterId
	Value     []byte `tls:"head=2"`
}

type clientHelloTransportParameters struct {
	InitialVersion VersionNumber
	Parameters     TransportParameterList `tls:"head=2"`
}

type encryptedExtensionsTransportParameters struct {
	NegotiatedVersion VersionNumber
	SupportedVersions []VersionNumber        `tls:"head=1"`
	Parameters        TransportParameterList `tls:"head=2"`
}

func (tp *TransportParameterList) addUintParameter(id TransportParameterId, val uint32, size uintptr) error {
	var buf bytes.Buffer
	uintEncodeInt(&buf, uint64(val), size)
	*tp = append(*tp, transportParameter{
		id,
		buf.Bytes(),
	})
	return nil
}

func (tp *TransportParameterList) getParameter(id TransportParameterId) []byte {
	for _, ex := range *tp {
		if ex.Parameter == id {
			return ex.Value
		}
	}
	return nil
}

func (tp *TransportParameterList) getUintParameter(id TransportParameterId, size uintptr) (uint32, error) {
	assert(size <= 4)

	b := tp.getParameter(id)
	if b == nil {
		logf(logTypeHandshake, "Missing transport parameter %v", id)
		return 0, ErrorMissingValue
	}

	if len(b) != int(size) {
		logf(logTypeHandshake, "Bogus transport parameter %v", id)
		return 0, ErrorInvalidEncoding
	}

	buf := bytes.NewReader(b)
	tmp, err := uintDecodeInt(buf, size)
	if err != nil {
		return 0, err
	}

	return uint32(tmp), nil
}

func (tp *TransportParameterList) getUintParameterOrDefault(id TransportParameterId, size uintptr, def uint32) (uint32, error) {
	assert(size <= 4)

	b := tp.getParameter(id)
	if b == nil {
		logf(logTypeHandshake, "Missing transport parameter %v", id)
		return def, nil
	}

	if len(b) != int(size) {
		logf(logTypeHandshake, "Bogus transport parameter %v", id)
		return 0, ErrorInvalidEncoding
	}

	buf := bytes.NewReader(b)
	tmp, err := uintDecodeInt(buf, size)
	if err != nil {
		return 0, err
	}

	return uint32(tmp), nil
}

func (tp *TransportParameterList) addOpaqueParameter(id TransportParameterId, b []byte) error {
	*tp = append(*tp, transportParameter{
		id,
		b,
	})
	return nil
}

func (tp *TransportParameterList) createCommonTransportParameters() error {
	for _, p := range kTransportParameterDefaults {
		err := tp.addUintParameter(p.parameter, p.val, p.size)
		if err != nil {
			return err
		}
	}

	return nil
}

// Implement mint.AppExtensionHandler.
type transportParametersXtnBody struct {
	body []byte
}

func (t transportParametersXtnBody) Type() mint.ExtensionType {
	return kQuicTransportParamtersXtn
}

func (t transportParametersXtnBody) Marshal() ([]byte, error) {
	return t.body, nil
}

func (t *transportParametersXtnBody) Unmarshal(data []byte) (int, error) {
	t.body = data
	return len(t.body), nil
}

type transportParametersHandler struct {
	log        loggingFunction
	role       Role
	version    VersionNumber
	peerParams *transportParameters
}

func newTransportParametersHandler(log loggingFunction, role Role, version VersionNumber) *transportParametersHandler {
	return &transportParametersHandler{log, role, version, nil}
}

func (h *transportParametersHandler) setDummyPeerParams() {
	h.peerParams = &transportParameters{
		uint32(kInitialMaxStreamData),
		uint32(kInitialMaxStreamData),
		uint32(kInitialMaxStreamData),
		uint32(kInitialMaxData),
		kConcurrentStreamsBidi,
		kConcurrentStreamsUni,
		600,
		uint8(1),
	}
}

func (h *transportParametersHandler) Send(hs mint.HandshakeType, el *mint.ExtensionList) error {
	if h.role == RoleClient {
		h.log(logTypeHandshake, "Sending transport parameters")
		if hs != mint.HandshakeTypeClientHello {
			return nil
		}
		b, err := h.createClientHelloTransportParameters()
		if err != nil {
			return err
		}
		h.log(logTypeTrace, "ClientHelloTransportParameters=%s", hex.EncodeToString(b))
		el.Add(&transportParametersXtnBody{b})
		return nil
	}

	if h.peerParams == nil {
		return nil
	}

	if hs != mint.HandshakeTypeEncryptedExtensions {
		return nil
	}

	h.log(logTypeHandshake, "Sending transport parameters message")
	b, err := h.createEncryptedExtensionsTransportParameters()
	if err != nil {
		return err
	}
	el.Add(&transportParametersXtnBody{b})
	return nil
}

func (h *transportParametersHandler) Receive(hs mint.HandshakeType, el *mint.ExtensionList) error {
	h.log(logTypeHandshake, "%p TransportParametersHandler message=%d", h, hs)
	// First see if the other side sent the extension.
	var body transportParametersXtnBody
	found, err := el.Find(&body)

	if err != nil {
		return fmt.Errorf("Invalid transport parameters")
	}

	if found {
		h.log(logTypeTrace, "Retrieved transport parameters len=%d %v", len(body.body), hex.EncodeToString(body.body))
	}

	var params *TransportParameterList

	switch hs {
	case mint.HandshakeTypeEncryptedExtensions:
		if h.role != RoleClient {
			return fmt.Errorf("EncryptedExtensions received but not a client")
		}
		if !found {
			h.log(logTypeHandshake, "Missing transport parameters")
			return fmt.Errorf("Missing transport parameters")
		}
		var eeParams encryptedExtensionsTransportParameters
		_, err = syntax.Unmarshal(body.body, &eeParams)
		if err != nil {
			h.log(logTypeHandshake, "Failed to decode parameters")
			return err
		}
		params = &eeParams.Parameters
		// TODO(ekr@rtfm.com): Process version #s
	case mint.HandshakeTypeClientHello:
		if h.role != RoleServer {
			return fmt.Errorf("ClientHello received but not a server")
		}
		if !found {
			h.log(logTypeHandshake, "Missing transport parameters")
			return fmt.Errorf("Missing transport parameters")
		}

		// TODO(ekr@rtfm.com): Process version #s
		var chParams clientHelloTransportParameters
		_, err = syntax.Unmarshal(body.body, &chParams)
		if err != nil {
			h.log(logTypeHandshake, "Couldn't unmarshal %v", err)
			return err
		}
		params = &chParams.Parameters
	default:
		if found {
			return fmt.Errorf("Received quic_transport_parameters in inappropriate message %v", hs)
		}
		return nil
	}

	// Now try to process each param.
	// TODO(ekr@rtfm.com): Enforce that each param appears only once.
	var tp transportParameters
	h.log(logTypeHandshake, "Reading transport parameters values")

	tp.maxStreamDataBidiLocal, err = params.getUintParameterOrDefault(kTpIdInitialMaxStreamDataBidiLocal, 4, 0)
	if err != nil {
		return err
	}

	tp.maxStreamDataBidiRemote, err = params.getUintParameterOrDefault(kTpIdInitialMaxStreamDataBidiRemote, 4, 0)
	if err != nil {
		return err
	}

	tp.maxStreamDataUni, err = params.getUintParameterOrDefault(kTpIdInitialMaxStreamDataUni, 4, 0)
	if err != nil {
		return err
	}

	tp.maxData, err = params.getUintParameterOrDefault(kTpIdInitialMaxData, 4, 0)
	if err != nil {
		return err
	}

	tmp, err := params.getUintParameterOrDefault(kTpIdInitialMaxBidiStreams, 2, 0)
	if err != nil {
		return err
	}
	tp.maxStreamsBidi = int(tmp)

	if h.role == RoleClient {
		tp.maxStreamsBidi++ // Allow for stream 0.
	}

	tmp, err = params.getUintParameterOrDefault(kTpIdInitialMaxUniStreams, 2, 0)
	if err != nil {
		return err
	}
	tp.maxStreamsUni = int(tmp)

	tmp, err = params.getUintParameter(kTpIdIdleTimeout, 2)
	if err != nil {
		return err
	}
	tp.idleTimeout = uint16(tmp)

	tmp, err = params.getUintParameterOrDefault(kTpIdAckDelayExponent, 1, 0)
	if err != nil {
		return err
	}

	h.peerParams = &tp

	h.log(logTypeHandshake, "Finished reading transport parameters")
	return nil
}

func (h *transportParametersHandler) createClientHelloTransportParameters() ([]byte, error) {
	chtp := clientHelloTransportParameters{
		h.version,
		nil,
	}

	err := chtp.Parameters.createCommonTransportParameters()
	if err != nil {
		return nil, err
	}

	b, err := syntax.Marshal(chtp)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (h *transportParametersHandler) createEncryptedExtensionsTransportParameters() ([]byte, error) {
	eetp := encryptedExtensionsTransportParameters{
		h.version,
		[]VersionNumber{
			h.version,
		},
		nil,
	}

	err := eetp.Parameters.createCommonTransportParameters()
	if err != nil {
		return nil, err
	}

	b := make([]byte, 16)
	_, err = rand.Read(b)
	if err != nil {
		return nil, err
	}

	eetp.Parameters.addOpaqueParameter(kTpIdStatelessResetToken, b)

	b, err = syntax.Marshal(eetp)
	if err != nil {
		return nil, err
	}
	return b, nil
}
