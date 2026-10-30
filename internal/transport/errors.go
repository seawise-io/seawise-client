package transport

import (
	"errors"
	"time"

	"github.com/seawise-io/seawise-client/tunnelwire/ladder"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
	"github.com/seawise-io/seawise-client/tunnelwire/wire"
)

// Kind tells the session manager what a failed dial means.
type Kind int

const (
	// Local: nothing was dialled (kill switch, edge list, configuration).
	// It never counts as a carriage failure.
	Local Kind = iota + 1
	// Blocked: the carriage did not come up, or broke before HelloAck.
	Blocked
	// Transient: the edge asked to retry later; the carriage works.
	Transient
	// Refused: the edge refused in a way that holds the agent.
	Refused
	// Auth: the edge refused the device's proof or standing.
	Auth
)

func (k Kind) String() string {
	switch k {
	case Local:
		return "local"
	case Blocked:
		return "blocked"
	case Transient:
		return "transient"
	case Refused:
		return "refused"
	case Auth:
		return "auth"
	}
	return "unknown"
}

// Dial-failure causes, as the ladder names them.
const (
	CauseDial         = "dial"
	CauseTLS          = "tls"
	CauseALPN         = "alpn"
	CauseSubprotocol  = "subprotocol"
	CauseAckSignature = "ack_signature"
	CauseEdgeTooOld   = "edge_too_old"
)

// Local failures.
var (
	ErrKillSwitch   = errors.New("transport: kill switch is on")
	ErrNoEdgeList   = errors.New("transport: no verified edge list")
	ErrEdgeUnlisted = errors.New("transport: tunnel name is not in the signed edge list")
	ErrProxy        = errors.New("transport: unusable proxy setting")
)

// Error is a failed dial. Its text never holds proxy credentials, key
// material or the edge's refusal detail.
type Error struct {
	Kind   Kind
	Cause  string // ladder cause for Blocked, or edge_too_old
	Reason string // fixed fine-grained reason
	// Code and RetryAfter are set for a HelloRefuse.
	Code       pb.RefuseCode
	RetryAfter time.Duration
	Err        error
}

func (e *Error) Error() string {
	s := "transport: " + e.Kind.String()
	if e.Cause != "" {
		s += " " + e.Cause
	}
	if e.Code != pb.RefuseCode_REFUSE_UNSPECIFIED {
		s += " " + e.Code.String()
	}
	if e.Reason != "" {
		s += " (" + e.Reason + ")"
	}
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

func (e *Error) Unwrap() error { return e.Err }

// Event is the ladder input for this failure at a time in milliseconds;
// false for a Local failure, which the ladder never sees.
func (e *Error) Event(at int64) (ladder.Event, bool) {
	switch {
	case e.Kind == Local:
		return ladder.Event{}, false
	case e.Code != pb.RefuseCode_REFUSE_UNSPECIFIED:
		return ladder.Event{At: at, Kind: ladder.EvRefused, Code: e.Code.String()}, true
	}
	return ladder.Event{At: at, Kind: ladder.EvDialFailed, Cause: e.Cause}, true
}

// KindOf returns the kind of a dial error, 0 for nil or a foreign error.
func KindOf(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return 0
}

func local(reason string, err error) *Error {
	return &Error{Kind: Local, Reason: reason, Err: err}
}

func blocked(cause, reason string, err error) *Error {
	return &Error{Kind: Blocked, Cause: cause, Reason: reason, Err: err}
}

// refusal classifies a HelloRefuse.
func refusal(r *pb.HelloRefuse) *Error {
	e := &Error{Kind: Transient, Reason: "hello_refused", Code: r.GetCode(),
		RetryAfter: time.Duration(min(r.GetRetryAfterMs(), wire.MaxRefuseRetryMs)) * time.Millisecond}
	switch r.GetCode() {
	case pb.RefuseCode_INVALID_PROOF, pb.RefuseCode_KEY_REVOKED, pb.RefuseCode_NOT_ENROLLED, pb.RefuseCode_ACCOUNT_SUSPENDED:
		e.Kind = Auth
	case pb.RefuseCode_VERSION_TOO_OLD, pb.RefuseCode_PROTOCOL_DISABLED, pb.RefuseCode_TOO_MANY_ROUTES:
		e.Kind = Refused
	}
	return e
}
