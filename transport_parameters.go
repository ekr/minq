package minq

import (
	"bytes"
	"fmt"
	"github.com/bifurcation/mint"
	"github.com/bifurcation/mint/syntax"
)

const (
	kQuicTransportParamtersXtn = mint.ExtensionType(26)
)

type TransportParameterId uint16

const (
	kTpIdInitialMaxStreamsData = TransportParameterId(0x0000)
	kTpIdInitialMaxData        = TransportParameterId(0x0001)
	kTpIdInitialMaxStreamId    = TransportParameterId(0x0002)
	kTpIdIdleTimeout           = TransportParameterId(0x0003)
	kTpIdOmitConnectionId      = TransportParameterId(0x0004)
	kTpIdMaxPacketSize         = TransportParameterId(0x0005)
)

type tpDef struct {
	parameter TransportParameterId
	val       uint32
	size      uintptr
}

var (
	kTransportParameterDefaults = []tpDef{
		{kTpIdInitialMaxStreamsData, 8192, 4},
		{kTpIdInitialMaxData, 8192, 4},
		{kTpIdInitialMaxStreamId, 16, 4},
		{kTpIdIdleTimeout, 10, 2},
	}
)

type TransportParameterList []transportParameter

type transportParameter struct {
	parameter TransportParameterId
	value     []byte `tls:"head=2"`
}

type clientHelloTransportParameters struct {
	NegotiatedVersion VersionNumber
	InitialVersion    VersionNumber
	Parameters        TransportParameterList `tls:"head=2"`
}

type encryptedExtensionsTransportParameters struct {
	SupportedVersions []VersionNumber        `tls:"head=1"`
	Parameters        TransportParameterList `tls:"head=2"`
}

type newSessionTicketTransportParameters struct {
	Parameters []transportParameter `tls:"head=2"`
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

func (t transportParametersXtnBody) Unmarshal(data []byte) (int, error) {
	t.body = data
	return len(t.body), nil
}

type transportParametersHandler struct {
	role     uint8
	version  VersionNumber
	peerBody *transportParametersXtnBody
}

func newTransportParametersHandler(role uint8, version VersionNumber) *transportParametersHandler {
	return &transportParametersHandler{role, version, nil}
}

func (h *transportParametersHandler) Send(hs mint.HandshakeType, el *mint.ExtensionList) error {
	if h.role == RoleClient {
		logf(logTypeHandshake, "Sending transport parameters")
		if hs != mint.HandshakeTypeClientHello {
			return nil
		}
		b, err := h.createClientHelloTransportParameters()
		if err != nil {
			return err
		}
		el.Add(transportParametersXtnBody{b})
		return nil
	}

	if h.peerBody == nil {
		return nil
	}

	if hs != mint.HandshakeTypeEncryptedExtensions {
		return nil
	}

	logf(logTypeHandshake, "Sending transport parameters message")
	b, err := h.createEncryptedExtensionsTransportParameters()
	if err != nil {
		return err
	}
	el.Add(transportParametersXtnBody{b})
	return nil
}

func (h *transportParametersHandler) Receive(hs mint.HandshakeType, el *mint.ExtensionList) error {
	logf(logTypeHandshake, "Received transport parameters")
	// First see if the other side sent the extension.
	var body transportParametersXtnBody
	ok := el.Find(&body)

	// TODO(ekr@rtfm.com): In future, require this.
	if !ok {
		return nil
	}

	h.peerBody = &body

	if h.role == RoleClient {
		if hs != mint.HandshakeTypeEncryptedExtensions && hs != mint.HandshakeTypeNewSessionTicket {
			return fmt.Errorf("Received quic_transport_parameters in inappropriate message %v", hs)
		}
	} else {
		if hs != mint.HandshakeTypeClientHello {
			return fmt.Errorf("Received quic_transport_parameters in inappropriate message %v", hs)
		}
	}
	// TODO(ekr@rtfm.com): Actually do something with the extension

	return nil
}

func (h *transportParametersHandler) createClientHelloTransportParameters() ([]byte, error) {
	chtp := clientHelloTransportParameters{
		h.version,
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
		[]VersionNumber{
			h.version,
		},
		nil,
	}

	err := eetp.Parameters.createCommonTransportParameters()
	if err != nil {
		return nil, err
	}

	b, err := syntax.Marshal(eetp)
	if err != nil {
		return nil, err
	}
	return b, nil
}
