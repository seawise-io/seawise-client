package instruction

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/seawise/client/internal/protocol"
)

const server = "7c9e6679-7425-40de-944b-e07fc1f90ae7"

var t0 = time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)

type vk struct {
	Name, Seed, X string
}

func keys(t *testing.T) map[string]ed25519.PrivateKey {
	t.Helper()
	b, err := os.ReadFile("../../testdata/vectors/keyset.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Keys []vk `json:"keys"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	out := map[string]ed25519.PrivateKey{}
	for _, k := range f.Keys {
		s, _ := hex.DecodeString(k.Seed)
		out[k.Name] = ed25519.NewKeyFromSeed(s)
	}
	return out
}

func entry(k ed25519.PrivateKey, role, status string) protocol.KeySetEntry {
	p := k.Public().(ed25519.PublicKey)
	return protocol.KeySetEntry{KID: protocol.KeyID(p), Role: role, X: base64.RawURLEncoding.EncodeToString(p), Status: status}
}

type env struct {
	t        *testing.T
	k        map[string]ed25519.PrivateKey
	ks       *protocol.KeySet
	dir      string
	now      time.Time
	fresh    bool
	unpairs  int
	deleted  []string
	failNext error
}

func newEnv(t *testing.T) *env {
	t.Helper()
	k := keys(t)
	tok, err := protocol.NewKeySet(k["root-primary"], 1, t0.Unix(), []protocol.KeySetEntry{
		entry(k["control-1"], protocol.RoleControl, protocol.StatusActive),
		entry(k["control-old"], protocol.RoleControl, protocol.StatusRevoked),
		entry(k["visitor-1"], protocol.RoleVisitor, protocol.StatusActive),
	})
	if err != nil {
		t.Fatal(err)
	}
	ks, err := protocol.VerifyKeySet(tok, []ed25519.PublicKey{k["root-primary"].Public().(ed25519.PublicKey)}, 0, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, k: k, ks: ks, dir: filepath.Join(t.TempDir(), "instructions"), now: t0, fresh: true}
}

func (e *env) proc() *Processor {
	e.t.Helper()
	p, err := New(e.config())
	if err != nil {
		e.t.Fatal(err)
	}
	return p
}

func (e *env) config() Config {
	return Config{
		Dir: e.dir, ServerID: server,
		KeySet: func() *protocol.KeySet { return e.ks },
		Fresh:  func(time.Time) bool { return e.fresh },
		Now:    func() time.Time { return e.now },
		Unpair: func(context.Context) error {
			if err := e.failNext; err != nil {
				e.failNext = nil
				return err
			}
			e.unpairs++
			return nil
		},
		DeleteApp: func(_ context.Context, id string) error {
			if err := e.failNext; err != nil {
				e.failNext = nil
				return err
			}
			e.deleted = append(e.deleted, id)
			return nil
		},
	}
}

func (e *env) sign(key, insID, srv, op string, args protocol.InstructionArgs, iat time.Time) string {
	e.t.Helper()
	tok, err := protocol.NewInstruction(e.k[key], protocol.Instruction{InsID: insID, ServerID: srv, Op: op, Args: args, IAT: iat.Unix(), EXP: iat.Unix() + 3600})
	if err != nil {
		e.t.Fatal(err)
	}
	return tok
}

func (e *env) copyAt(insID, op string, args protocol.InstructionArgs, iat time.Time) string {
	return e.sign("control-1", insID, server, op, args, iat)
}

// raw signs arbitrary claims, for ops the signing helper refuses.
func (e *env) raw(claims string) string {
	k := e.k["control-1"]
	h := fmt.Sprintf(`{"typ":"sw-instr+jwt","alg":"EdDSA","kid":%q}`, protocol.KeyID(k.Public().(ed25519.PublicKey)))
	in := base64.RawURLEncoding.EncodeToString([]byte(h)) + "." + base64.RawURLEncoding.EncodeToString([]byte(claims))
	return in + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(k, []byte(in)))
}

const ins1 = "aW5zdHJ1Y3Rpb24tb25lLTAx"

var app = protocol.InstructionArgs{LocalID: "3f2b8c1e-5d4a-4b7e-9c6f-1a2b3c4d5e6f"}

func submit(t *testing.T, p *Processor, tok string) (Outcome, error) {
	t.Helper()
	return p.Submit(context.Background(), tok)
}

func TestTwoCopiesApartExecute(t *testing.T) {
	e := newEnv(t)
	p := e.proc()
	first := e.copyAt(ins1, protocol.OpDeleteApp, app, t0)
	if o, err := submit(t, p, first); o != OutcomePending || err != nil {
		t.Fatalf("first copy: %s %v", o, err)
	}
	// The same copy again is not a second copy.
	e.now = t0.Add(700 * time.Second)
	if o, _ := submit(t, p, first); o != OutcomePending {
		t.Fatalf("same copy twice: %s", o)
	}
	// 599 s apart is too close.
	if o, _ := submit(t, p, e.copyAt(ins1, protocol.OpDeleteApp, app, t0.Add(599*time.Second))); o != OutcomePending || len(e.deleted) != 0 {
		t.Fatalf("599 s apart: %s %v", o, e.deleted)
	}
	if o, err := submit(t, p, e.copyAt(ins1, protocol.OpDeleteApp, app, t0.Add(600*time.Second))); o != OutcomeExecuted || err != nil {
		t.Fatalf("600 s apart: %s %v", o, err)
	}
	if len(e.deleted) != 1 || e.deleted[0] != app.LocalID {
		t.Fatalf("deleted %v", e.deleted)
	}
	// Later copies, also after a restart, are replays.
	later := e.copyAt(ins1, protocol.OpDeleteApp, app, t0.Add(650*time.Second))
	if o, err := submit(t, p, later); o != OutcomeReplayed || err != nil {
		t.Fatalf("after execution: %s %v", o, err)
	}
	if o, _ := submit(t, e.proc(), later); o != OutcomeReplayed || len(e.deleted) != 1 {
		t.Fatalf("after restart: %s %v", o, e.deleted)
	}
	if st := p.Status(); st.Executed != 1 || st.Pending != 0 {
		t.Fatalf("status %+v", st)
	}
}

func TestUnpairExecutes(t *testing.T) {
	e := newEnv(t)
	p := e.proc()
	e.now = t0.Add(time.Hour)
	submit(t, p, e.copyAt(ins1, protocol.OpUnpair, protocol.InstructionArgs{}, t0.Add(10*time.Minute)))
	if o, err := submit(t, p, e.copyAt(ins1, protocol.OpUnpair, protocol.InstructionArgs{}, t0.Add(20*time.Minute))); o != OutcomeExecuted || err != nil || e.unpairs != 1 {
		t.Fatalf("unpair: %s %v %d", o, err, e.unpairs)
	}
}

func TestPendingCopiesSurviveRestart(t *testing.T) {
	e := newEnv(t)
	submit(t, e.proc(), e.copyAt(ins1, protocol.OpDeleteApp, app, t0))
	e.now = t0.Add(11 * time.Minute)
	if o, _ := submit(t, e.proc(), e.copyAt(ins1, protocol.OpDeleteApp, app, t0.Add(11*time.Minute))); o != OutcomeExecuted {
		t.Fatalf("second copy after restart: %s", o)
	}
}

func TestStaleMetadataDefersExecution(t *testing.T) {
	e := newEnv(t)
	p := e.proc()
	e.fresh = false
	e.now = t0.Add(11 * time.Minute)
	submit(t, p, e.copyAt(ins1, protocol.OpDeleteApp, app, t0))
	second := e.copyAt(ins1, protocol.OpDeleteApp, app, t0.Add(10*time.Minute))
	if o, err := submit(t, p, second); o != OutcomePending || err != nil || len(e.deleted) != 0 {
		t.Fatalf("stale: %s %v %v", o, err, e.deleted)
	}
	e.fresh = true
	if o, _ := submit(t, p, second); o != OutcomeExecuted {
		t.Fatalf("fresh again: %s", o)
	}
}

func TestUnsupportedOps(t *testing.T) {
	e := newEnv(t)
	p := e.proc()
	for i, c := range []struct {
		op   string
		args protocol.InstructionArgs
	}{{protocol.OpDisableApp, app}, {protocol.OpSetVisitorEnforcement, protocol.InstructionArgs{Mode: "enforce"}}} {
		id := fmt.Sprintf("dW5zdXBwb3J0ZWQtb3AtMDAw%d", i)
		for n := 0; n < 2; n++ {
			o, err := submit(t, p, e.copyAt(id, c.op, c.args, t0.Add(time.Duration(n)*time.Minute)))
			if o != OutcomeUnsupported || err != nil {
				t.Fatalf("%s copy %d: %s %v", c.op, n, o, err)
			}
		}
	}
	if e.unpairs != 0 || len(e.deleted) != 0 {
		t.Fatal("unsupported op changed something")
	}
}

func TestRefusals(t *testing.T) {
	e := newEnv(t)
	p := e.proc()
	other := "11111111-2222-4333-8444-555555555555"
	cases := map[string]struct {
		tok  string
		code string
	}{
		"unknown op":   {e.raw(fmt.Sprintf(`{"ins_id":%q,"server_id":%q,"op":"wipe_disk","args":{},"iat":%d,"exp":%d}`, ins1, server, t0.Unix(), t0.Unix()+60)), "malformed"},
		"other server": {e.sign("control-1", ins1, other, protocol.OpUnpair, protocol.InstructionArgs{}, t0), "wrong_server"},
		"revoked key":  {e.sign("control-old", ins1, server, protocol.OpUnpair, protocol.InstructionArgs{}, t0), "key_revoked"},
		"visitor key":  {e.sign("visitor-1", ins1, server, protocol.OpUnpair, protocol.InstructionArgs{}, t0), "wrong_key_role"},
		"unknown key":  {e.sign("control-2", ins1, server, protocol.OpUnpair, protocol.InstructionArgs{}, t0), "unknown_key"},
		"expired":      {e.copyAt(ins1, protocol.OpUnpair, protocol.InstructionArgs{}, t0.Add(-2*time.Hour)), "expired"},
		"future":       {e.copyAt(ins1, protocol.OpUnpair, protocol.InstructionArgs{}, t0.Add(10*time.Minute)), "not_yet_valid"},
		"garbage":      {"x.y.z", "malformed"},
	}
	for name, c := range cases {
		o, err := submit(t, p, c.tok)
		if o != "" || CodeOf(err) != c.code {
			t.Errorf("%s: %q %v, want %s", name, o, err, c.code)
		}
	}
	if st := p.Status(); st.Pending != 0 {
		t.Fatalf("refused tokens were stored: %+v", st)
	}
	e.ks = nil
	if _, err := submit(t, p, e.copyAt(ins1, protocol.OpUnpair, protocol.InstructionArgs{}, t0)); CodeOf(err) != CodeNoKeySet {
		t.Fatalf("no key set: %v", err)
	}
}

func TestContentBinding(t *testing.T) {
	e := newEnv(t)
	p := e.proc()
	submit(t, p, e.copyAt(ins1, protocol.OpDeleteApp, app, t0))
	other := protocol.InstructionArgs{LocalID: "another-app"}
	if _, err := submit(t, p, e.copyAt(ins1, protocol.OpDeleteApp, other, t0.Add(-time.Minute))); CodeOf(err) != CodeConflict {
		t.Fatalf("other args: %v", err)
	}
	if _, err := submit(t, p, e.copyAt(ins1, protocol.OpUnpair, protocol.InstructionArgs{}, t0.Add(-time.Minute))); CodeOf(err) != CodeConflict {
		t.Fatalf("other op: %v", err)
	}
}

func TestCopyCap(t *testing.T) {
	e := newEnv(t)
	p := e.proc()
	e.fresh = false
	for i := 0; i < MaxCopies; i++ {
		if o, err := submit(t, p, e.copyAt(ins1, protocol.OpDeleteApp, app, t0.Add(-time.Duration(i)*time.Second))); o != OutcomePending || err != nil {
			t.Fatalf("copy %d: %s %v", i, o, err)
		}
	}
	if _, err := submit(t, p, e.copyAt(ins1, protocol.OpDeleteApp, app, t0.Add(-time.Duration(MaxCopies)*time.Second))); CodeOf(err) != CodeExhausted {
		t.Fatalf("copy %d: %v", MaxCopies+1, err)
	}
}

func TestOpenIDCap(t *testing.T) {
	e := newEnv(t)
	p := e.proc()
	for i := 0; i < MaxOpen; i++ {
		id := fmt.Sprintf("b3Blbi1pbnN0cnVjdGlvbi0%05d", i)
		if _, err := submit(t, p, e.copyAt(id, protocol.OpDeleteApp, app, t0)); err != nil {
			t.Fatalf("id %d: %v", i, err)
		}
	}
	if _, err := submit(t, p, e.copyAt("b3Blbi1pbnN0cnVjdGlvbi0zzzzz", protocol.OpDeleteApp, app, t0)); CodeOf(err) != CodeBusy {
		t.Fatalf("over the cap: %v", err)
	}
}

func TestFailedExecutionRetried(t *testing.T) {
	e := newEnv(t)
	p := e.proc()
	e.now = t0.Add(11 * time.Minute)
	submit(t, p, e.copyAt(ins1, protocol.OpDeleteApp, app, t0))
	e.failNext = errors.New("disk full")
	second := e.copyAt(ins1, protocol.OpDeleteApp, app, t0.Add(10*time.Minute))
	if o, err := submit(t, p, second); o != "" || CodeOf(err) != CodeExecFailed {
		t.Fatalf("failed execution: %s %v", o, err)
	}
	// A restart finishes the started execution.
	p2 := e.proc()
	if len(e.deleted) != 1 {
		t.Fatalf("not finished on restart: %v", e.deleted)
	}
	if o, _ := submit(t, p2, second); o != OutcomeReplayed {
		t.Fatalf("after restart: %s", o)
	}
}

// A clock set back after an executed id was pruned must not make its old
// copies valid again.
func TestNoReplayAfterPruneAndClockBack(t *testing.T) {
	e := newEnv(t)
	p := e.proc()
	e.now = t0.Add(11 * time.Minute)
	first := e.copyAt(ins1, protocol.OpDeleteApp, app, t0)
	submit(t, p, first)
	submit(t, p, e.copyAt(ins1, protocol.OpDeleteApp, app, t0.Add(10*time.Minute)))
	// Much later, another instruction moves the floor and prunes.
	late := t0.Add(Retention + 48*time.Hour)
	e.now = late
	submit(t, p, e.copyAt("bGF0ZXItaW5zdHJ1Y3Rpb24tMDE", protocol.OpDeleteApp, app, late))
	if st := p.Status(); st.Executed != 0 {
		t.Fatalf("not pruned: %+v", st)
	}
	e.now = t0.Add(5 * time.Minute)
	p2 := e.proc()
	if o, err := submit(t, p2, first); o == OutcomeExecuted || o == OutcomePending || err == nil {
		t.Fatalf("old copy after clock back: %s %v", o, err)
	}
	if len(e.deleted) != 1 {
		t.Fatalf("executed twice: %v", e.deleted)
	}
}

func TestStateFile(t *testing.T) {
	e := newEnv(t)
	submit(t, e.proc(), e.copyAt(ins1, protocol.OpDeleteApp, app, t0))
	path := filepath.Join(e.dir, StateFile)
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", info, err)
	}
	// Unreadable replay state fails closed.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(e.config()); err == nil {
		t.Fatal("group-readable state accepted")
	}
	b, _ := os.ReadFile(path)
	_ = os.Remove(path)
	elsewhere := filepath.Join(t.TempDir(), "x")
	_ = os.WriteFile(elsewhere, b, 0o600)
	_ = os.Symlink(elsewhere, path)
	if _, err := New(e.config()); err == nil {
		t.Fatal("symlinked state accepted")
	}
	_ = os.Remove(path)
	_ = os.WriteFile(path, []byte("{"), 0o600)
	if _, err := New(e.config()); err == nil {
		t.Fatal("corrupt state accepted")
	}
}

func TestConfig(t *testing.T) {
	e := newEnv(t)
	for name, mod := range map[string]func(*Config){
		"no dir":       func(c *Config) { c.Dir = "" },
		"bad server":   func(c *Config) { c.ServerID = "x" },
		"no key set":   func(c *Config) { c.KeySet = nil },
		"no fresh":     func(c *Config) { c.Fresh = nil },
		"no unpair":    func(c *Config) { c.Unpair = nil },
		"no deleteapp": func(c *Config) { c.DeleteApp = nil },
	} {
		c := e.config()
		mod(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// The floor trails the newest issue time by the leeway, so a copy that is
// still valid on the agent clock is not refused as expired.
func TestFloorTrailsByLeeway(t *testing.T) {
	e := newEnv(t)
	p := e.proc()
	submit(t, p, e.copyAt(ins1, protocol.OpDeleteApp, app, t0))
	old := e.copyAt("b2xkZXItaW5zdHJ1Y3Rpb24tMDE", protocol.OpDeleteApp, app, t0.Add(-3850*time.Second))
	if o, err := submit(t, p, old); o != OutcomePending || err != nil {
		t.Fatalf("copy valid within the leeway: %s %v", o, err)
	}
}

func TestPruneBoundary(t *testing.T) {
	e := newEnv(t)
	p := e.proc()
	submit(t, p, e.copyAt(ins1, protocol.OpDeleteApp, app, t0))
	exp := t0.Add(time.Hour)
	other := func(at time.Time, id string) {
		e.now = at
		if _, err := submit(t, p, e.copyAt(id, protocol.OpUnpair, protocol.InstructionArgs{}, at)); err != nil {
			t.Fatal(err)
		}
	}
	other(exp.Add(Retention), "cHJ1bmUtYm91bmRhcnktMDAx")
	if st := p.Status(); st.Pending != 2 {
		t.Fatalf("pruned at the boundary: %+v", st)
	}
	other(exp.Add(Retention+time.Second), "cHJ1bmUtYm91bmRhcnktMDAy")
	if st := p.Status(); st.Pending != 2 {
		t.Fatalf("not pruned after the boundary: %+v", st)
	}
}

func TestStatusCounts(t *testing.T) {
	e := newEnv(t)
	p := e.proc()
	submit(t, p, e.copyAt(ins1, protocol.OpDisableApp, app, t0))
	submit(t, p, e.copyAt("cGVuZGluZy1pbnN0cnVjdGlvbi0x", protocol.OpDeleteApp, app, t0))
	if st := p.Status(); st != (Status{Pending: 1, Unsupported: 1}) {
		t.Fatalf("%+v", st)
	}
}

func TestParseStateLimits(t *testing.T) {
	recs := map[string]*record{}
	for i := 0; i < MaxOpen; i++ {
		iats := make([]int64, MaxCopies)
		recs[fmt.Sprint(i)] = &record{Op: protocol.OpUnpair, IATs: iats, State: statePending}
	}
	b, _ := json.Marshal(stateFile{Schema: 1, Records: recs})
	if _, err := parseState(b); err != nil {
		t.Fatalf("at the limits: %v", err)
	}
	recs["x"] = &record{Op: protocol.OpUnpair, State: statePending}
	b, _ = json.Marshal(stateFile{Schema: 1, Records: recs})
	if _, err := parseState(b); err == nil {
		t.Fatal("too many records accepted")
	}
	delete(recs, "x")
	recs["0"].IATs = make([]int64, MaxCopies+1)
	b, _ = json.Marshal(stateFile{Schema: 1, Records: recs})
	if _, err := parseState(b); err == nil {
		t.Fatal("too many copies accepted")
	}
	for _, bad := range []string{`{"schema":2,"records":{}}`, `{"schema":1,"floor":-1,"records":{}}`, `{"schema":1,"records":{"a":{"state":"done"}}}`} {
		if _, err := parseState([]byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestRefusalText(t *testing.T) {
	if (&Refusal{Code: CodeBusy}).Error() != "busy" || (&Refusal{Code: CodeBusy, Err: errors.New("x")}).Error() != "busy: x" {
		t.Fatal("refusal text")
	}
	if CodeOf(errors.New("x")) != "" {
		t.Fatal("code of a plain error")
	}
}
