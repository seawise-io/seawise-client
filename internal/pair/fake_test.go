package pair

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/seawise/client/internal/devicecall"
	"github.com/seawise/client/internal/protocol"
)

// fakePairing follows the device API's v2 pairing calls: the proof key is
// bound by pair/request and must sign status, complete and cancel.
type fakePairing struct {
	mu        sync.Mutex
	publicURL string
	nonceKey  []byte
	now       func() time.Time

	n          int
	byDevice   map[string]*fakeRequest
	newest     *fakeRequest
	registered map[string]bool // key ids of paired devices
	seen       map[string]bool

	// script answers the next calls of a path with a status before they
	// are processed; body is sent with it.
	script map[string][]scripted
	// lose makes the next successful call of a path act, then drop the
	// connection.
	lose map[string]int
	// answer rewrites a successful answer of a path.
	answer map[string]func(map[string]any)

	calls   map[string]int
	headers []http.Header
	kids    map[string][]string // path -> proof key ids
}

type scripted struct {
	status int
	body   string
	header map[string]string
}

type fakeRequest struct {
	user, device, kid, name, status string
	expires                         time.Time
	serverID, deviceID              string
}

func newFakePairing() *fakePairing {
	return &fakePairing{
		nonceKey: []byte(strings.Repeat("\x09", 32)), now: time.Now,
		byDevice: map[string]*fakeRequest{}, registered: map[string]bool{}, seen: map[string]bool{},
		script: map[string][]scripted{}, lose: map[string]int{}, answer: map[string]func(map[string]any){},
		calls: map[string]int{}, kids: map[string][]string{},
	}
}

func (f *fakePairing) with(fn func(*fakePairing)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakePairing) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[path]
}

func (f *fakePairing) keyIDs(path string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.kids[path]...)
}

// last returns the newest request.
func (f *fakePairing) last() *fakeRequest {
	return f.newest
}

func (f *fakePairing) approve() {
	f.with(func(f *fakePairing) { f.last().status = "approved" })
}

func (f *fakePairing) setStatus(s string) {
	f.with(func(f *fakePairing) { f.last().status = s })
}

func (f *fakePairing) issueNonce() string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(time.Now().Unix()))
	body := "n1." + base64.RawURLEncoding.EncodeToString(b[:])
	m := hmac.New(sha256.New, f.nonceKey)
	m.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:16])
}

func (f *fakePairing) nonceValid(n string) bool {
	p := strings.Split(n, ".")
	if len(p) != 3 {
		return false
	}
	m := hmac.New(sha256.New, f.nonceKey)
	m.Write([]byte(p[0] + "." + p[1]))
	mac, err := base64.RawURLEncoding.DecodeString(p[2])
	return err == nil && hmac.Equal(mac, m.Sum(nil)[:16])
}

type reply struct {
	status int
	body   any
	auth   string
}

func (f *fakePairing) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	f.mu.Lock()
	f.calls[r.URL.Path]++
	f.headers = append(f.headers, r.Header.Clone())
	var rep reply
	extra := map[string]string{}
	if s := f.script[r.URL.Path]; len(s) > 0 {
		f.script[r.URL.Path] = s[1:]
		rep = reply{status: s[0].status, body: json.RawMessage(s[0].body)}
		if s[0].body == "" {
			rep.body = map[string]string{"error": "scripted"}
		}
		extra = s[0].header
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
	for k, v := range extra {
		w.Header().Set(k, v)
	}
	if rep.auth != "" {
		w.Header().Set("WWW-Authenticate", rep.auth)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(rep.status)
	_ = json.NewEncoder(w).Encode(rep.body)
}

func (f *fakePairing) proof(r *http.Request, raw []byte) (*protocol.DPoPResult, *reply) {
	h := r.Header.Values("DPoP")
	if len(h) != 1 {
		return nil, &reply{401, map[string]string{"error": "invalid_proof", "code": "malformed"}, `DPoP error="invalid_dpop_proof"`}
	}
	res, err := protocol.VerifyDPoP(h[0], protocol.DPoPRequest{Method: r.Method, URL: f.publicURL + r.URL.RequestURI(), Body: raw}, f.nonceValid, func(string, string) bool { return true })
	if err != nil {
		if protocol.CodeOf(err) == protocol.CodeBadNonce {
			return nil, &reply{401, map[string]string{"error": "use_dpop_nonce", "code": "use_dpop_nonce"}, `DPoP error="use_dpop_nonce"`}
		}
		return nil, &reply{401, map[string]string{"error": "invalid_proof", "code": string(protocol.WireCode(protocol.CodeOf(err)))}, `DPoP error="invalid_dpop_proof"`}
	}
	k := res.KeyID + ":" + res.Claims.JTI
	if f.seen[k] {
		return nil, &reply{401, map[string]string{"error": "invalid_proof", "code": "replayed"}, `DPoP error="invalid_dpop_proof"`}
	}
	f.seen[k] = true
	f.kids[r.URL.Path] = append(f.kids[r.URL.Path], res.KeyID)
	return res, nil
}

func (f *fakePairing) handle(r *http.Request, raw []byte) reply {
	if r.Method != http.MethodPost {
		return reply{status: 404, body: map[string]string{"error": "Not found"}}
	}
	res, bad := f.proof(r, raw)
	if bad != nil {
		return *bad
	}
	switch r.URL.Path {
	case PathRequest:
		m, err := devicecall.StrictStrings(raw, []string{"server_name"})
		if err != nil || m["server_name"] == "" || len([]rune(m["server_name"])) > 100 {
			return reply{status: 400, body: map[string]string{"error": "Validation failed"}}
		}
		if f.registered[res.KeyID] {
			return reply{status: 400, body: map[string]string{"error": "invalid_key", "code": "bad_key"}}
		}
		f.n++
		d := sha256.Sum256([]byte(fmt.Sprint("device", f.n, res.KeyID)))
		req := &fakeRequest{
			user: strings.NewReplacer("0", "A", "1", "B").Replace(fmt.Sprintf("WXYZ%06d", f.n)), device: hex.EncodeToString(d[:16]), kid: res.KeyID,
			name: m["server_name"], status: "pending", expires: f.now().Add(15 * time.Minute),
		}
		f.byDevice[req.device], f.newest = req, req
		data := map[string]any{"user_code": req.user, "device_code": req.device, "expires_at": req.expires.UTC().Format("2006-01-02T15:04:05.000Z"), "poll_url": PathStatus, "key_id": res.KeyID}
		if fn := f.answer[PathRequest]; fn != nil {
			fn(data)
		}
		return reply{status: 200, body: map[string]any{"data": data}}
	case PathStatus, PathComplete, PathCancel:
		m, err := devicecall.StrictStrings(raw, []string{"device_code"})
		if err != nil {
			return reply{status: 400, body: map[string]string{"error": "Validation failed"}}
		}
		req := f.byDevice[m["device_code"]]
		if req != nil && req.kid != res.KeyID {
			req = nil
		}
		switch r.URL.Path {
		case PathCancel:
			if req != nil && (req.status == "pending" || req.status == "approved") {
				req.status = "cancelled"
			}
			return reply{status: 200, body: map[string]any{"data": map[string]string{"status": "cancelled"}}}
		case PathStatus:
			if req == nil {
				return reply{status: 200, body: map[string]any{"data": map[string]string{"status": "invalid"}}}
			}
			st := req.status
			if st == "completed" {
				st = "used"
			}
			data := map[string]any{"status": st, "server_name": req.name}
			if st == "expired" || st == "invalid" {
				data = map[string]any{"status": st}
			}
			return reply{status: 200, body: map[string]any{"data": data}}
		}
		if req == nil || (req.status != "approved" && req.status != "completed") {
			return reply{status: 400, body: map[string]string{"error": "Code not approved or expired"}}
		}
		if req.status == "approved" {
			req.status = "completed"
			req.serverID = fmt.Sprintf("00000000-0000-4000-8000-%012d", f.n)
			req.deviceID = fmt.Sprintf("d0000000-0000-4000-8000-%012d", f.n)
			f.registered[res.KeyID] = true
		}
		data := map[string]any{"server_id": req.serverID, "server_name": req.name, "user_id": testUser, "device_id": req.deviceID, "key_id": req.kid}
		if fn := f.answer[PathComplete]; fn != nil {
			fn(data)
		}
		return reply{status: 200, body: map[string]any{"data": data}}
	}
	return reply{status: 404, body: map[string]string{"error": "Not found"}}
}

var _ http.Handler = (*fakePairing)(nil)
