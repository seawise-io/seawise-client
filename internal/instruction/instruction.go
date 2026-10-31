// Package instruction verifies and carries out instructions signed by a
// SeaWise control key: only allowlisted ops, only for this server, only
// after two copies issued at least 600 s apart while the TUF metadata is
// fresh, and never twice.
package instruction

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/seawise-io/seawise-client/tunnelwire/claims"

	"github.com/seawise/client/internal/protocol"
	"github.com/seawise/client/internal/store"
)

// StateFile keeps copies, bindings and executed ids.
const StateFile = "instructions.json"

// Limits.
const (
	MaxCopies = 24
	MaxOpen   = 256
	// Retention keeps a record this long after its last copy expires.
	Retention = 24 * time.Hour
	leeway    = 300
)

// Outcome is the answer to an accepted copy.
type Outcome string

const (
	OutcomePending     Outcome = "pending"
	OutcomeExecuted    Outcome = "executed"
	OutcomeUnsupported Outcome = "unsupported"
	OutcomeReplayed    Outcome = "replayed"
)

// Refusal codes besides the protocol codes.
const (
	CodeNoKeySet   = "no_key_set"
	CodeConflict   = "ins_conflict"
	CodeExhausted  = "ins_exhausted"
	CodeBusy       = "busy"
	CodeExecFailed = "exec_failed"
	CodeStore      = "store_failed"
)

// Refusal is a refused copy.
type Refusal struct {
	Code string
	Err  error
}

func (r *Refusal) Error() string {
	if r.Err == nil {
		return r.Code
	}
	return r.Code + ": " + r.Err.Error()
}

func (r *Refusal) Unwrap() error { return r.Err }

func refuse(code string, err error) error { return &Refusal{Code: code, Err: err} }

// CodeOf returns the refusal code of err, or "".
func CodeOf(err error) string {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Code
	}
	return ""
}

// Config configures a Processor.
type Config struct {
	Dir      string
	ServerID string
	KeySet   func() *protocol.KeySet
	// Fresh reports whether the TUF metadata is unexpired at t.
	Fresh     func(t time.Time) bool
	Now       func() time.Time
	Unpair    func(ctx context.Context) error
	DeleteApp func(ctx context.Context, localID string) error
	Logger    *slog.Logger
}

const (
	statePending     = "pending"
	stateExecuting   = "executing"
	stateExecuted    = "executed"
	stateUnsupported = "unsupported"
)

type record struct {
	Op    string                   `json:"op"`
	Args  protocol.InstructionArgs `json:"args"`
	IATs  []int64                  `json:"iats"`
	EXP   int64                    `json:"exp"`
	State string                   `json:"state"`
}

type stateFile struct {
	Schema  int                `json:"schema"`
	Floor   int64              `json:"floor"`
	Records map[string]*record `json:"records"`
}

// Status counts the records.
type Status struct {
	Pending     int `json:"pending"`
	Executed    int `json:"executed"`
	Unsupported int `json:"unsupported"`
}

// Processor handles signed instructions for one server.
type Processor struct {
	cfg Config
	log *slog.Logger

	mu sync.Mutex
	st stateFile
}

// New loads the stored state and finishes any execution a crash cut short.
// Unreadable state is an error: replay protection cannot be guessed.
func New(cfg Config) (*Processor, error) {
	switch {
	case cfg.Dir == "":
		return nil, errors.New("instruction folder not set")
	case !claims.ValidUUID(cfg.ServerID):
		return nil, errors.New("server id is not a canonical uuid")
	case cfg.KeySet == nil || cfg.Fresh == nil || cfg.Unpair == nil || cfg.DeleteApp == nil:
		return nil, errors.New("key set, freshness and executors are required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	if err := store.CheckDir(cfg.Dir); err != nil {
		return nil, err
	}
	p := &Processor{cfg: cfg, log: cfg.Logger.With("component", "instructions"), st: stateFile{Schema: 1, Records: map[string]*record{}}}
	b, err := store.ReadOwned(filepath.Join(cfg.Dir, StateFile))
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if p.st, err = parseState(b); err != nil {
			return nil, err
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, r := range p.st.Records {
		if r.State == stateExecuting {
			_ = p.execute(context.Background(), id, r)
		}
	}
	return p, nil
}

func parseState(b []byte) (stateFile, error) {
	var s stateFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return s, fmt.Errorf("%s: malformed", StateFile)
	}
	if s.Schema != 1 || s.Floor < 0 || len(s.Records) > MaxOpen {
		return s, fmt.Errorf("%s: invalid", StateFile)
	}
	if s.Records == nil {
		s.Records = map[string]*record{}
	}
	for _, r := range s.Records {
		if r == nil || len(r.IATs) > MaxCopies {
			return s, fmt.Errorf("%s: invalid record", StateFile)
		}
		switch r.State {
		case statePending, stateExecuting, stateExecuted, stateUnsupported:
		default:
			return s, fmt.Errorf("%s: invalid record", StateFile)
		}
	}
	return s, nil
}

func (p *Processor) save() error {
	b, err := json.Marshal(p.st)
	if err != nil {
		return err
	}
	err = store.WriteFileAtomic(filepath.Join(p.cfg.Dir, StateFile), b, 0o600)
	if err != nil && !errors.Is(err, store.ErrNotDurable) {
		return refuse(CodeStore, err)
	}
	return nil
}

// now is the agent clock, never below the highest verified issue time
// minus the leeway, so a clock moved back cannot revive pruned ids.
func (p *Processor) now() int64 {
	return max(p.cfg.Now().Unix(), p.st.Floor)
}

// Submit handles one copy of an instruction.
func (p *Processor) Submit(ctx context.Context, token string) (Outcome, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ks := p.cfg.KeySet()
	if ks == nil {
		return "", refuse(CodeNoKeySet, errors.New("no verified key set"))
	}
	now := p.now()
	in, err := protocol.VerifyInstruction(token, ks, p.cfg.ServerID, now, func(id string) bool {
		r := p.st.Records[id]
		return r != nil && r.State == stateExecuted
	})
	if protocol.CodeOf(err) == protocol.CodeReplayed {
		return OutcomeReplayed, nil
	}
	if err != nil {
		p.log.Warn("instruction refused", "error", err)
		return "", refuse(string(protocol.CodeOf(err)), err)
	}
	p.prune(now)
	r := p.st.Records[in.InsID]
	if r == nil {
		if len(p.st.Records) >= MaxOpen {
			return "", refuse(CodeBusy, errors.New("too many open instructions"))
		}
		r = &record{Op: in.Op, Args: in.Args, State: statePending}
	} else if r.Op != in.Op || r.Args != in.Args {
		p.log.Warn("instruction refused: ins_id bound to other content", "ins_id", in.InsID)
		return "", refuse(CodeConflict, errors.New("ins_id is bound to another op or args"))
	}
	if !slices.Contains(r.IATs, in.IAT) {
		if len(r.IATs) >= MaxCopies {
			return "", refuse(CodeExhausted, fmt.Errorf("more than %d copies", MaxCopies))
		}
		r.IATs = append(r.IATs, in.IAT)
		slices.Sort(r.IATs)
	}
	r.EXP = max(r.EXP, in.EXP)
	if in.Op == protocol.OpDisableApp || in.Op == protocol.OpSetVisitorEnforcement {
		r.State = stateUnsupported
	}
	p.st.Records[in.InsID] = r
	p.st.Floor = max(p.st.Floor, in.IAT-leeway)
	if err := p.save(); err != nil {
		return "", err
	}
	switch {
	case r.State == stateUnsupported:
		p.log.Info("instruction not supported by this agent", "ins_id", in.InsID, "op", in.Op)
		return OutcomeUnsupported, nil
	case r.State == stateExecuting:
	case r.IATs[len(r.IATs)-1]-r.IATs[0] < protocol.RepeatInterval:
		return OutcomePending, nil
	case !p.cfg.Fresh(time.Unix(now, 0)):
		p.log.Warn("instruction waits: signed update information is not fresh", "ins_id", in.InsID, "op", in.Op)
		return OutcomePending, nil
	default:
		r.State = stateExecuting
		if err := p.save(); err != nil {
			r.State = statePending
			return "", err
		}
	}
	if err := p.execute(ctx, in.InsID, r); err != nil {
		return "", err
	}
	return OutcomeExecuted, nil
}

func (p *Processor) execute(ctx context.Context, id string, r *record) error {
	var err error
	switch r.Op {
	case protocol.OpUnpair:
		err = p.cfg.Unpair(ctx)
	case protocol.OpDeleteApp:
		err = p.cfg.DeleteApp(ctx, r.Args.LocalID)
	default:
		err = fmt.Errorf("op %s cannot be carried out", r.Op)
	}
	if err != nil {
		p.log.Warn("instruction failed", "ins_id", id, "op", r.Op, "error", err)
		return refuse(CodeExecFailed, err)
	}
	r.State = stateExecuted
	p.log.Warn("signed instruction carried out", "ins_id", id, "op", r.Op)
	return p.save()
}

func (p *Processor) prune(now int64) {
	for id, r := range p.st.Records {
		if r.State != stateExecuting && r.EXP+int64(Retention/time.Second) < now {
			delete(p.st.Records, id)
		}
	}
}

// Status counts the stored records.
func (p *Processor) Status() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	var s Status
	for _, r := range p.st.Records {
		switch r.State {
		case stateExecuted:
			s.Executed++
		case stateUnsupported:
			s.Unsupported++
		default:
			s.Pending++
		}
	}
	return s
}
