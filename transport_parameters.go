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
	kTpIdStatelessResetToken   = TransportParameterId(0x0006)
)

type tpDef struct {
	parameter TransportParameterId
	val       uint32
	size      uintptr
}

// TODO(ekr@rtfm.com): Hack until we generate MAX_STREAM_DATA
var kInitialMaxStreamData = uint32(8192)
var (
	kTransportParameterDefaults = []tpDef{
		{kTpIdInitialMaxStreamsData, kInitialMaxStreamData, 4},
		{kTpIdInitialMaxData, 8192, 4},
		{kTpIdInitialMaxStreamId, 16, 4},
		{kTpIdIdleTimeout, 10, 2},
	}
)

type transportParameters struct {
	maxStreamsData uint32
	maxData        uint32
	maxStreamId    uint32
	idleTimeout    uint16
}

type TransportParameterList []transportParameter

type transportParameter struct {
	Parameter TransportParameterId
	Value     []byte `tls:"head=2"`
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
	Parameters TransportParameterList `tls:"head=2"`
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
		return 0, ErrorMissingValue
	}

	if len(b) != int(size) {
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
	role       uint8
	version    VersionNumber
	peerParams *transportParameters
}

func newTransportParametersHandler(log loggingFunction, role uint8, version VersionNumber) *transportParametersHandler {
	return &transportParametersHandler{log, role, version, nil}
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

	logf(logTypeHandshake, "Sending transport parameters message")
	b, err := h.createEncryptedExtensionsTransportParameters()
	if err != nil {
		return err
	}
	el.Add(&transportParametersXtnBody{b})
	return nil
}

func (h *transportParametersHandler) Receive(hs mint.HandshakeType, el *mint.ExtensionList) error {
	logf(logTypeHandshake, "TransportParametersHandler message=%d", hs)
	// First see if the other side sent the extension.
	var body transportParametersXtnBody
	ok := el.Find(&body)

	h.log(logTypeTrace, "Retrieved transport parameters len=%d %v", len(body.body), hex.EncodeToString(body.body))
	var params *TransportParameterList

	if h.role == RoleClient {
		if hs == mint.HandshakeTypeEncryptedExtensions {
			if !ok {
				h.log(logTypeHandshake, "Missing transport parameters")
				return fmt.Errorf("Missing transport parameters")
			}
			var eeParams encryptedExtensionsTransportParameters
			_, err := syntax.Unmarshal(body.body, &eeParams)
			if err != nil {
				return err
			}
			params = &eeParams.Parameters
			// TODO(ekr@rtfm.com): Process version #s
		} else if hs == mint.HandshakeTypeNewSessionTicket {
			if !ok {
				h.log(logTypeHandshake, "Missing transport parameters")
				return fmt.Errorf("Missing transport parameters")
			}
			var nstParams newSessionTicketTransportParameters
			_, err := syntax.Unmarshal(body.body, &nstParams)
			if err != nil {
				return err
			}
			params = &nstParams.Parameters
		} else {
			if ok {
				return fmt.Errorf("Received quic_transport_parameters in inappropriate message %v", hs)
			}
			return nil
		}
	} else {
		if hs == mint.HandshakeTypeClientHello {
			if !ok {
				h.log(logTypeHandshake, "Missing transport parameters")
				return fmt.Errorf("Missing transport parameters")
			}

			// TODO(ekr@rtfm.com): Process version #s
			var chParams clientHelloTransportParameters
			_, err := syntax.Unmarshal(body.body, &chParams)
			if err != nil {
				h.log(logTypeHandshake, "Couldn't unmarshal %v", err)
				return err
			}
			params = &chParams.Parameters
		} else {
			if ok {
				return fmt.Errorf("Received quic_transport_parameters in inappropriate message %v", hs)
			}
			return nil
		}
	}

	// Now try to process each param.
	// TODO(ekr@rtfm.com): Enforce that each param appears only once.
	var tp transportParameters
	var err error
	h.log(logTypeHandshake, "Reading transport parameters values")
	tp.maxStreamsData, err = params.getUintParameter(kTpIdInitialMaxStreamsData, 4)
	if err != nil {
		return err
	}
	tp.maxData, err = params.getUintParameter(kTpIdInitialMaxData, 4)
	if err != nil {
		return err
	}
	tp.maxStreamId, err = params.getUintParameter(kTpIdInitialMaxStreamId, 4)
	if err != nil {
		return err
	}
	var tmp uint32
	tmp, err = params.getUintParameter(kTpIdIdleTimeout, 2)
	if err != nil {
		return err
	}
	tp.idleTimeout = uint16(tmp)

	h.peerParams = &tp

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
