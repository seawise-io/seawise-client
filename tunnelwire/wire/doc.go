// Package wire implements the seawise-tunnel/1 framing and the strict
// decoding and validation of every message on the control stream (stream 0),
// the data-stream header and reply, and the relay prefix.
//
// Decoding is strict: unknown field numbers, repeated singular fields, more
// than one oneof member, non-minimal varints, values that protobuf would
// truncate and unknown enum values are refused before the message is
// unmarshalled, and every size cap is checked before any allocation.
package wire
