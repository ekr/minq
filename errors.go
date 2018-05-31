package minq

import (
	"fmt"
)

// Errors which don't necesarily cause connection teardown.
type intError struct {
	err   string
	sub   string
	fatal bool
}

func (e intError) Error() string {
	return e.err
}

func fatalError(format string, args ...interface{}) error {
	return intError{
		fmt.Sprintf(format, args...),
		"",
		true,
	}
}

func internalError(format string, args ...interface{}) error {
	str := fmt.Sprintf(format, args...)
	if debug {
		panic("Internal error: " + str)
	}

	return intError{
		str,
		"",
		true,
	}
}

func nonFatalError(format string, args ...interface{}) error {
	return intError{
		fmt.Sprintf(format, args...),
		"",
		false,
	}
}

func err2string(err interface{}) string {
	switch e := err.(type) {
	case error:
		return e.Error()
	case string:
		return e
	default:
		panic("Bogus argument to err2string")
	}
}

func wrapE(err interface{}, sub interface{}) error {
	return intError{
		err2string(err),
		err2string(sub),
		isFatalError(err),
	}
}

// An error is fatal if either.
//
// It's a regular error (i.e., not an intError)
// e.fatal is true
func isFatalError(e interface{}) bool {
	if e == nil {
		return false
	}

	i, ok := e.(intError)
	if !ok {
		return true
	}

	return i.fatal
}

// Return codes.
var ErrorWouldBlock = nonFatalError("Would have blocked (QUIC)")
var ErrorDestroyConnection = fatalError("Terminate connection")
var ErrorReceivedVersionNegotiation = fatalError("Received a version negotiation packet advertising a different version than ours")
var ErrorConnIsClosed = fatalError("Connection is closed")
var ErrorConnIsClosing = nonFatalError("Connection is closing")
var ErrorStreamReset = fatalError("Stream was reset")
var ErrorStreamIsClosed = fatalError("Stream is closed")
var ErrorInvalidPacket = nonFatalError("Invalid packet")
var ErrorConnectionTimedOut = fatalError("Connection timed out")
var ErrorMissingValue = fatalError("Expected value is missing")
var ErrorInvalidEncoding = fatalError("Invalid encoding")
var ErrorProtocolViolation = fatalError("Protocol violation")
var ErrorFrameFormatError = fatalError("Frame format error")
var ErrorFlowControlError = fatalError("Flow control error")

// Protocol errors
type ErrorCode uint16

const (
	kQuicErrorNoError           = ErrorCode(0x0000)
	kQuicErrorProtocolViolation = ErrorCode(0x000A)
)
