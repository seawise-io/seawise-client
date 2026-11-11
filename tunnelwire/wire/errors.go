package wire

import (
	"errors"
	"fmt"
)

// Code classifies a wire error. Vectors name these codes.
type Code string

const (
	CodeTooLarge       Code = "too_large"
	CodeEmpty          Code = "empty"
	CodeTruncated      Code = "truncated"
	CodeTimeout        Code = "timeout"
	CodeMalformed      Code = "malformed"
	CodeUnknownField   Code = "unknown_field"
	CodeDuplicateField Code = "duplicate_field"
	CodeWireType       Code = "wire_type"
	CodeBadValue       Code = "bad_value"
	CodeSchema         Code = "schema"
	CodeNoBody         Code = "no_body"
	CodeMultipleBodies Code = "multiple_bodies"
	CodeUnsupported    Code = "unsupported"
	CodeDirection      Code = "direction"
	CodeSeq            Code = "seq"
	CodeNotNegotiated  Code = "not_negotiated"
	CodeWrongPeer      Code = "wrong_peer"
)

// Error is a wire error with a code and the field it concerns.
type Error struct {
	Code  Code
	Field string
}

func (e *Error) Error() string {
	if e.Field == "" {
		return fmt.Sprintf("tunnelwire: %s", e.Code)
	}
	return fmt.Sprintf("tunnelwire: %s: %s", e.Code, e.Field)
}

func fail(c Code, field string) error { return &Error{Code: c, Field: field} }

// CodeOf returns the code of a wire error, or "" for any other error.
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
