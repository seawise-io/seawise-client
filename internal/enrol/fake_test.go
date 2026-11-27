package enrol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/seawise-io/seawise-client/tunnelwire/claims"

	"github.com/seawise/client/internal/devicecall"
	"github.com/seawise/client/internal/protocol"
)

// fakeC12 follows the control plane's /device/v2/enroll, /enroll/confirm
// and /identity answers, with a database reduced to one server.
type fakeC12 struct {
	mu        sync.Mutex
	publicURL string
	nonceKey  []byte
	now       func() time.Time

	serverID   string
	tokenHash  string // hex SHA-256 of the live token, "" when retired
	registered map[string]bool
	seen       map[string]bool

	deviceID     string
	deviceKID    string
	deviceStatus string // "", "active", "revoked"
	fromToken    bool
	repair       bool

	enrolments int // owner emails
	switches   int

	// script answers the next calls of a path before they are processed.
	script map[string][]int
	// lose makes the next call of a path act, then drop the connection.
	lose map[string]int
	// retryAfter is sent with scripted 429s.
	retryAfter string

	calls   map[string]int
	headers []http.Header
}

func newFake(serverID, token string) *fakeC12 {
	h := sha256.Sum256([]byte(token))
	return &fakeC12{
		nonceKey: []byte(strings.Repeat("\x07", 32)), now: time.Now,
		serverID: serverID, tokenHash: hex.EncodeToString(h[:]),
		registered: map[string]bool{}, seen: map[string]bool{},
		deviceID: "d0000000-0000-4000-8000-000000000001",
		script:   map[string][]int{}, lose: map[string]int{}, calls: map[string]int{},
	}
}

func (f *fakeC12) issueNonce() string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(f.now().UnixMilli()/1000))
	body := "n1." + base64.RawURLEncoding.EncodeToString(b[:])
	m := hmac.New(sha256.New, f.nonceKey)
	m.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:16])
}

func (f *fakeC12) nonceValid(n string) bool {
	p := strings.Split(n, ".")
	if len(p) != 3 {
		return false
	}
	issued, err1 := base64.RawURLEncoding.DecodeString(p[1])
	mac, err2 := base64.RawURLEncoding.DecodeString(p[2])
	if err1 != nil || err2 != nil || len(issued) != 4 || len(mac) != 16 {
		return false
	}
	m := hmac.New(sha256.New, f.nonceKey)
	m.Write([]byte(p[0] + "." + p[1]))
	if !hmac.Equal(mac, m.Sum(nil)[:16]) {
		return false
	}
	age := f.now().UnixMilli()/1000 - int64(binary.BigEndian.Uint32(issued))
	return age >= -1 && age < 300
}

type reply struct {
	status int
	body   any
	auth   string
}

func (f *fakeC12) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	f.mu.Lock()
	f.calls[r.URL.Path]++
	f.headers = append(f.headers, r.Header.Clone())
	var rep reply
	if s := f.script[r.URL.Path]; len(s) > 0 {
		f.script[r.URL.Path] = s[1:]
		rep = reply{status: s[0], body: map[string]string{"error": "scripted"}}
		if s[0] == http.StatusTooManyRequests && f.retryAfter != "" {
			w.Header().Set("Retry-After", f.retryAfter)
		}
	} else {
		rep = f.handle(r, raw)
	}
	lose := f.lose[r.URL.Path] > 0 && rep.status == http.StatusOK
	if lose {
		f.lose[r.URL.Path]--
	}
	nonce := f.issueNonce()
	f.mu.Unlock()
	if lose {
		if hj, ok := w.(http.Hijacker); ok {
			if c, _, err := hj.Hijack(); err == nil {
				c.Close()
				return
			}
		}
		panic(http.ErrAbortHandler)
	}
	w.Header().Set("DPoP-Nonce", nonce)
	w.Header().Set("Cache-Control", "no-store")
	if rep.auth != "" {
		w.Header().Set("WWW-Authenticate", rep.auth)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(rep.status)
	_ = json.NewEncoder(w).Encode(rep.body)
}

func errBody(e, code string) map[string]string {
	if code == "" {
		return map[string]string{"error": e}
	}
	return map[string]string{"error": e, "code": code}
}

func invalidProof(code string) reply {
	return reply{401, errBody("invalid_proof", code), `DPoP error="invalid_dpop_proof"`}
}

// proof verifies the request proof; the jti is claimed by the caller.
func (f *fakeC12) proof(r *http.Request, raw []byte) (*protocol.DPoPResult, *reply) {
	h := r.Header.Values("DPoP")
	if len(h) != 1 {
		rep := invalidProof("malformed")
		return nil, &rep
	}
	res, err := protocol.VerifyDPoP(h[0], protocol.DPoPRequest{Method: r.Method, URL: f.publicURL + r.URL.RequestURI(), Body: raw}, f.nonceValid, func(string, string) bool { return true })
	if err != nil {
		code := protocol.CodeOf(err)
		if code == protocol.CodeBadNonce {
			return nil, &reply{401, errBody("use_dpop_nonce", "use_dpop_nonce"), `DPoP error="use_dpop_nonce"`}
		}
		rep := invalidProof(string(protocol.WireCode(code)))
		return nil, &rep
	}
	return res, nil
}

func (f *fakeC12) claim(res *protocol.DPoPResult) bool {
	k := res.KeyID + ":" + res.Claims.JTI
	if f.seen[k] {
		return false
	}
	f.seen[k] = true
	return true
}

func parseBody(raw []byte, max int, optional ...string) (map[string]string, bool) {
	if len(raw) > max {
		return nil, false
	}
	m, err := devicecall.StrictStrings(raw, []string{"server_id"}, optional...)
	if err != nil {
		return nil, false
	}
	for _, v := range m {
		if !claims.ValidUUID(v) {
			return nil, false
		}
	}
	return m, true
}

func (f *fakeC12) handle(r *http.Request, raw []byte) reply {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == PathEnroll:
		return f.enrol(r, raw)
	case r.Method == http.MethodPost && r.URL.Path == PathConfirm:
		return f.confirm(r, raw)
	case r.Method == http.MethodGet && r.URL.Path == PathIdentity:
		return f.identity(r, raw)
	}
	return reply{404, errBody("Not found", ""), ""}
}

func validHexToken(t []string) bool {
	return len(t) == 1 && validToken(t[0])
}

func (f *fakeC12) enrol(r *http.Request, raw []byte) reply {
	tok := r.Header.Values("X-FRP-Token")
	if !validHexToken(tok) {
		return reply{401, errBody("invalid_token", ""), ""}
	}
	res, bad := f.proof(r, raw)
	if bad != nil {
		return *bad
	}
	body, ok := parseBody(raw, 256, "boot_id")
	if !ok {
		return reply{400, errBody("invalid_request", "malformed"), ""}
	}
	h := sha256.Sum256([]byte(tok[0]))
	if f.tokenHash == "" || hex.EncodeToString(h[:]) != f.tokenHash || body["server_id"] != f.serverID {
		return reply{401, errBody("invalid_token", ""), ""}
	}
	if !f.claim(res) {
		return invalidProof("replayed")
	}
	switch {
	case f.repair:
		return reply{403, errBody("repair_required", ""), ""}
	case f.deviceStatus == "active" && f.deviceKID == res.KeyID:
	case f.deviceStatus == "active":
		return reply{409, errBody("already_enrolled", ""), ""}
	case f.registered[res.KeyID]:
		return reply{400, errBody("invalid_key", "bad_key"), ""}
	default:
		f.deviceKID, f.deviceStatus, f.fromToken = res.KeyID, "active", true
		f.registered[res.KeyID] = true
		f.enrolments++
	}
	return reply{200, map[string]string{"result": "enrolled", "server_id": f.serverID, "device_id": f.deviceID, "key_id": res.KeyID}, ""}
}

// activeKey is C11's registry authentication.
func (f *fakeC12) activeKey(res *protocol.DPoPResult) *reply {
	var rep reply
	switch {
	case f.deviceKID != res.KeyID:
		rep = invalidProof("invalid_proof")
	case f.deviceStatus != "active":
		rep = invalidProof("key_revoked")
	case !f.claim(res):
		rep = invalidProof("replayed")
	default:
		return nil
	}
	return &rep
}

func (f *fakeC12) identity(r *http.Request, raw []byte) reply {
	res, bad := f.proof(r, raw)
	if bad != nil {
		return *bad
	}
	if bad := f.activeKey(res); bad != nil {
		return *bad
	}
	return reply{200, map[string]string{"server_id": f.serverID, "device_id": f.deviceID, "key_id": res.KeyID}, ""}
}

func (f *fakeC12) confirm(r *http.Request, raw []byte) reply {
	res, bad := f.proof(r, raw)
	if bad != nil {
		return *bad
	}
	body, ok := parseBody(raw, 128)
	if !ok {
		return reply{400, errBody("invalid_request", "malformed"), ""}
	}
	if bad := f.activeKey(res); bad != nil {
		return *bad
	}
	if body["server_id"] != f.serverID {
		return reply{400, errBody("invalid_request", "wrong_server"), ""}
	}
	if !f.fromToken {
		return reply{409, errBody("not_enrolled", ""), ""}
	}
	if f.tokenHash != "" {
		f.switches++
	}
	f.tokenHash = ""
	return reply{200, map[string]string{"result": "switched"}, ""}
}

func (f *fakeC12) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[path]
}

func (f *fakeC12) with(fn func(*fakeC12)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeC12) enrolCount() int  { f.mu.Lock(); defer f.mu.Unlock(); return f.enrolments }
func (f *fakeC12) switchCount() int { f.mu.Lock(); defer f.mu.Unlock(); return f.switches }
func (f *fakeC12) kid() string      { f.mu.Lock(); defer f.mu.Unlock(); return f.deviceKID }
func (f *fakeC12) live() bool       { f.mu.Lock(); defer f.mu.Unlock(); return f.tokenHash != "" }
