package protocol

import (
	"crypto"
	"encoding/json"
	"regexp"
)

// Instruction operations.
const (
	OpUnpair                = "unpair"
	OpDeleteApp             = "delete_app"
	OpDisableApp            = "disable_app"
	OpSetVisitorEnforcement = "set_visitor_enforcement"
)

const (
	maxInstructionLife = 3600
	// RepeatInterval is how far apart two copies of an instruction must be
	// issued before the agent acts on it.
	RepeatInterval = 600
)

var localIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// InstructionArgs holds the arguments of every operation; each op uses at
// most one field.
type InstructionArgs struct {
	LocalID string `json:"local_id,omitempty"`
	Mode    string `json:"mode,omitempty"`
}

// Instruction is a signed instruction from SeaWise to one agent.
type Instruction struct {
	InsID    string          `json:"ins_id"`
	ServerID string          `json:"server_id"`
	Op       string          `json:"op"`
	Args     InstructionArgs `json:"args"`
	IAT      int64           `json:"iat"`
	EXP      int64           `json:"exp"`
}

type instructionWire struct {
	InsID    string          `json:"ins_id"`
	ServerID string          `json:"server_id"`
	Op       string          `json:"op"`
	Args     json.RawMessage `json:"args"`
	IAT      int64           `json:"iat"`
	EXP      int64           `json:"exp"`
}

var instructionMembers = []string{"ins_id", "server_id", "op", "args", "iat", "exp"}

func (in *Instruction) check() error {
	if err := checkID("ins_id", in.InsID); err != nil {
		return err
	}
	if err := checkServerID(in.ServerID); err != nil {
		return err
	}
	if err := checkTime("iat", in.IAT); err != nil {
		return err
	}
	if err := checkTime("exp", in.EXP); err != nil {
		return err
	}
	if in.EXP <= in.IAT || in.EXP-in.IAT > maxInstructionLife {
		return fail(CodeMalformed, "exp must be within %d seconds after iat", maxInstructionLife)
	}
	a := in.Args
	switch in.Op {
	case OpUnpair:
		if a != (InstructionArgs{}) {
			return fail(CodeMalformed, "unpair takes no arguments")
		}
	case OpDeleteApp, OpDisableApp:
		if a.Mode != "" || !localIDRe.MatchString(a.LocalID) {
			return fail(CodeMalformed, "%s needs a valid local_id", in.Op)
		}
	case OpSetVisitorEnforcement:
		if a.LocalID != "" || (a.Mode != "observe" && a.Mode != "enforce") {
			return fail(CodeMalformed, "mode must be observe or enforce")
		}
	default:
		return fail(CodeMalformed, "unknown op")
	}
	return nil
}

func argMembers(op string) []string {
	switch op {
	case OpDeleteApp, OpDisableApp:
		return []string{"local_id"}
	case OpSetVisitorEnforcement:
		return []string{"mode"}
	}
	return nil
}

// NewInstruction signs an instruction with a control key.
func NewInstruction(control crypto.Signer, in Instruction) (string, error) {
	if err := in.check(); err != nil {
		return "", err
	}
	return signJWS(control, TypInstr, false, in)
}

// VerifyInstruction checks an instruction for serverID. now is the agent's
// corrected clock; executed reports whether an ins_id was already carried
// out. The repetition rule is applied by the caller.
func VerifyInstruction(token string, ks *KeySet, serverID string, now int64, executed func(insID string) bool) (*Instruction, error) {
	t, err := parseJWS(token, TypInstr, "kid", maxTokenSize)
	if err != nil {
		return nil, err
	}
	pub, err := ks.Lookup(t.kid, RoleControl)
	if err != nil {
		return nil, err
	}
	if err := t.verify(pub); err != nil {
		return nil, err
	}
	var w instructionWire
	if err := decodeObject(t.payload, &w, instructionMembers); err != nil {
		return nil, err
	}
	in := Instruction{InsID: w.InsID, ServerID: w.ServerID, Op: w.Op, IAT: w.IAT, EXP: w.EXP}
	if err := decodeObject(w.Args, &in.Args, argMembers(w.Op)); err != nil {
		return nil, err
	}
	if err := in.check(); err != nil {
		return nil, err
	}
	if in.ServerID != serverID {
		return nil, fail(CodeWrongServer, "instruction is for another server")
	}
	if in.IAT > now+leewaySec {
		return nil, fail(CodeNotYetValid, "iat is in the future")
	}
	if now > in.EXP+leewaySec {
		return nil, fail(CodeExpired, "instruction expired")
	}
	if executed(in.InsID) {
		return nil, fail(CodeReplayed, "instruction already executed")
	}
	return &in, nil
}

// SignedTime is a time statement from a control key, bound to the agent's
// heartbeat nonce.
type SignedTime struct {
	ServerID string `json:"server_id"`
	Time     int64  `json:"time"`
	Nonce    string `json:"nonce"`
}

func (st *SignedTime) check() error {
	if err := checkServerID(st.ServerID); err != nil {
		return err
	}
	if err := checkTime("time", st.Time); err != nil {
		return err
	}
	return checkID("nonce", st.Nonce)
}

// NewSignedTime signs a time statement with a control key.
func NewSignedTime(control crypto.Signer, st SignedTime) (string, error) {
	if err := st.check(); err != nil {
		return "", err
	}
	return signJWS(control, TypTime, false, st)
}

// VerifySignedTime checks a time statement for serverID against the nonce
// the agent sent.
func VerifySignedTime(token string, ks *KeySet, serverID, nonce string) (*SignedTime, error) {
	t, err := parseJWS(token, TypTime, "kid", maxTokenSize)
	if err != nil {
		return nil, err
	}
	pub, err := ks.Lookup(t.kid, RoleControl)
	if err != nil {
		return nil, err
	}
	if err := t.verify(pub); err != nil {
		return nil, err
	}
	var st SignedTime
	if err := decodeObject(t.payload, &st, []string{"server_id", "time", "nonce"}); err != nil {
		return nil, err
	}
	if err := st.check(); err != nil {
		return nil, err
	}
	if st.ServerID != serverID {
		return nil, fail(CodeWrongServer, "time is for another server")
	}
	if st.Nonce != nonce {
		return nil, fail(CodeNonceMismatch, "nonce does not match the request")
	}
	return &st, nil
}
