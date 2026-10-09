// Package protocol implements the signed formats in docs/device-protocol.md:
// request proofs, frp login tokens, key rotation, key sets, instructions and
// signed time. Verification is strict and reports stable error codes shared
// with the server's implementation through testdata/vectors.
package protocol

import (
	"errors"
	"fmt"
)

// Code is a stable verification error code.
type Code string

const (
	CodeTooLarge       Code = "too_large"
	CodeMalformed      Code = "malformed"
	CodeBadAlg         Code = "bad_alg"
	CodeBadTyp         Code = "bad_typ"
	CodeBadKey         Code = "bad_key"
	CodeBadSignature   Code = "bad_signature"
	CodeUnknownKey     Code = "unknown_key"
	CodeKeyRevoked     Code = "key_revoked"
	CodeWrongKeyRole   Code = "wrong_key_role"
	CodeWrongServer    Code = "wrong_server"
	CodeExpired        Code = "expired"
	CodeNotYetValid    Code = "not_yet_valid"
	CodeBeforeKeyValid Code = "before_key_valid"
	CodeReplayed       Code = "replayed"
	CodeWrongHTM       Code = "wrong_htm"
	CodeWrongHTU       Code = "wrong_htu"
	CodeBodyMismatch   Code = "body_mismatch"
	CodeBadNonce       Code = "bad_nonce"
	CodeNonceMismatch  Code = "nonce_mismatch"
	CodeRollback       Code = "rollback"
)

// Error is a verification failure. Detail never quotes token content.
type Error struct {
	Code   Code
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return string(e.Code)
	}
	return string(e.Code) + ": " + e.Detail
}

// Is matches another *Error with the same code, so errors.Is(err,
// &Error{Code: CodeExpired}) works.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

func fail(code Code, format string, args ...any) error {
	return &Error{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// CodeOf returns the code of a verification error, or "" for other errors.
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
