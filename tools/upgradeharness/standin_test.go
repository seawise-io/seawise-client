//go:build upgradeharness

package upgradeharness

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/seawise-io/seawise-client/tunnelwire/claims"
)

const (
	apiHost  = "api.upgrade.test"
	apiPort  = 8443
	frpsHost = "frp-1.upgrade-harness.seawise.dev"
	frpsPort = 7000
)

var apiOrigin = fmt.Sprintf("https://%s:%d", apiHost, apiPort)

// rec is one request seen by the stand-in.
type rec struct {
	At     time.Time
	Phase  string
	Method string
	Path   string
	Agent  bool // sent by the agent (its User-Agent)
	Token  string
	KeyID  string // DPoP key of a device call that passed the proof check
	Status int
	Body   string
}

func (r rec) v1() bool { return strings.HasPrefix(r.Path, "/api/") }

type serverApp struct {
	ID        string
	LocalID   string
	Name      string
	Host      string
	Port      int
	Subdomain string
	Created   time.Time
}

// standin answers as the 1.x API and the device API for one server.
type standin struct {
	mu    sync.Mutex
	phase string
	recs  []rec
	fails []string // proof or protocol errors

	serverID   string
	token      string
	deviceCode string
	apps       []*serverApp
	retired    bool
	// v1Down answers the agent's 1.x calls with 503.
	v1Down bool

	enrolOn      bool
	confirmBlock bool
	nonce        string
	challenged   map[string]bool
	jtis         map[string]bool
	enrolledKID  string
	deviceID     string
	switched     bool
	idem         map[string][]byte

	frps map[string]int
}

func newStandin() *standin {
	s := &standin{}
	s.reset()
	return s
}

// reset starts a new install: new server id and token.
func (s *standin) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.phase, s.recs, s.fails = "setup", nil, nil
	s.serverID, s.token, s.deviceCode, s.apps, s.retired, s.v1Down = uuid4(), randHex(32), randHex(16), nil, false, false
	s.enrolOn, s.confirmBlock, s.nonce = false, false, newNonce()
	s.challenged, s.jtis, s.idem, s.frps = map[string]bool{}, map[string]bool{}, map[string][]byte{}, map[string]int{}
	s.enrolledKID, s.deviceID, s.switched = "", "", false
}

func (s *standin) setPhase(p string) {
	s.mu.Lock()
	s.phase = p
	s.mu.Unlock()
}

func (s *standin) set(fn func(*standin)) {
	s.mu.Lock()
	fn(s)
	s.mu.Unlock()
}

func (s *standin) records() []rec {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]rec(nil), s.recs...)
}

func (s *standin) failures() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.fails...)
}

func (s *standin) frpsConns(phase string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.frps[phase]
}

func uuid4() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func newNonce() string {
	a, b := make([]byte, 6), make([]byte, 16)
	_, _ = rand.Read(a)
	_, _ = rand.Read(b)
	return "n1." + base64.RawURLEncoding.EncodeToString(a) + "." + base64.RawURLEncoding.EncodeToString(b)
}

// tlsFiles makes a throwaway CA and a serving certificate for the API name.
func tlsFiles() (caPEM []byte, cert tls.Certificate, err error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, cert, err
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "upgrade harness CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, cert, err
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, cert, err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: apiHost}, DNSNames: []string{apiHost},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, cert, err
	}
	cert = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), cert, nil
}

// serve starts the HTTPS API and the frps stand-in.
func (s *standin) serve(cert tls.Certificate) (func(), error) {
	ln, err := tls.Listen("tcp", fmt.Sprintf(":%d", apiPort), &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		return nil, err
	}
	srv := &http.Server{Handler: s, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	fl, err := net.Listen("tcp", fmt.Sprintf(":%d", frpsPort))
	if err != nil {
		srv.Close()
		return nil, err
	}
	go func() {
		for {
			c, err := fl.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.frps[s.phase]++
			s.mu.Unlock()
			go func() { _, _ = io.Copy(io.Discard, c); c.Close() }()
		}
	}()
	return func() { srv.Close(); fl.Close() }, nil
}

type reply struct {
	status int
	body   any
	header map[string]string
}

func data(status int, v any) reply { return reply{status: status, body: map[string]any{"data": v}} }
func fail(status int, e string) reply {
	return reply{status: status, body: map[string]string{"error": e}}
}

func (s *standin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	s.mu.Lock()
	rc := rec{At: time.Now(), Phase: s.phase, Method: r.Method, Path: r.URL.Path,
		Agent: strings.HasPrefix(r.UserAgent(), "seawise-agent/"), Token: r.Header.Get("X-FRP-Token"), Body: string(body)}
	var rp reply
	if strings.HasPrefix(r.URL.Path, "/device/") {
		rp = s.device(r, body, &rc)
	} else {
		rp = s.v1(r, body)
	}
	rc.Status = rp.status
	s.recs = append(s.recs, rc)
	s.mu.Unlock()
	for k, v := range rp.header {
		w.Header().Set(k, v)
	}
	if rp.body == nil {
		w.WriteHeader(rp.status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(rp.status)
	_ = json.NewEncoder(w).Encode(rp.body)
}

func (s *standin) failf(format string, a ...any) {
	s.fails = append(s.fails, s.phase+": "+fmt.Sprintf(format, a...))
}

func (s *standin) appJSON(a *serverApp) map[string]any {
	return map[string]any{"id": a.ID, "name": a.Name, "host": a.Host, "port": a.Port, "subdomain": a.Subdomain,
		"status": "active", "created_at": a.Created.UTC().Format(time.RFC3339), "description": nil, "icon_url": nil}
}

func (s *standin) addApp(name, host string, port int) *serverApp {
	a := &serverApp{ID: uuid4(), Name: name, Host: host, Port: port, Subdomain: "app-" + randHex(4), Created: time.Now()}
	s.apps = append(s.apps, a)
	return a
}

// v1 answers the 1.x API as the platform does for one server.
func (s *standin) v1(r *http.Request, body []byte) reply {
	p := r.URL.Path
	switch {
	case r.Method == http.MethodPost && p == "/api/servers/pair/request":
		return data(200, map[string]any{"user_code": "HARN-ESS1", "device_code": s.deviceCode,
			"expires_at": time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339), "poll_url": apiOrigin + "/api/servers/pair/status"})
	case r.Method == http.MethodPost && p == "/api/servers/pair/status":
		if !bytes.Contains(body, []byte(s.deviceCode)) {
			return fail(404, "Pairing request not found")
		}
		return data(200, map[string]any{"status": "approved", "server_name": "harness"})
	case r.Method == http.MethodPost && p == "/api/servers/pair/complete":
		if !bytes.Contains(body, []byte(s.deviceCode)) {
			return fail(404, "Pairing request not found")
		}
		return data(200, map[string]any{"server_id": s.serverID, "server_name": "harness", "frp_token": s.token,
			"frp_server_addr": frpsHost, "frp_server_port": frpsPort, "frp_use_tls": true,
			"user_id": "00000000-0000-4000-8000-0000000000aa", "user_email": "owner@upgrade.test"})
	case r.Method == http.MethodGet && p == "/api/certs/status":
		return data(200, map[string]any{"acme_directory": "", "e2e_tls_enabled": false})
	}
	if r.Header.Get("X-FRP-Token") != s.token {
		return fail(401, "Invalid token")
	}
	if s.retired {
		// The token was retired by the switch to the device key.
		return fail(403, "This server moved to client v2")
	}
	if s.v1Down && strings.HasPrefix(r.UserAgent(), "seawise-agent/") {
		return reply{status: 503, body: map[string]string{"error": "unavailable"}, header: map[string]string{"Retry-After": "2"}}
	}
	sp := "/api/servers/" + s.serverID
	switch {
	case r.Method == http.MethodPost && p == sp+"/heartbeat":
		return data(200, map[string]any{"status": "ok", "server_status": "online", "server_time": time.Now().UTC().Format(time.RFC3339Nano),
			"previous_status": "online", "gap_seconds": 10, "next_heartbeat_ms": 10000, "timeout_ms": 90000, "migrate_to": nil,
			"shard": map[string]any{"frp_server_addr": frpsHost, "frp_server_port": frpsPort}})
	case r.Method == http.MethodGet && p == sp+"/services":
		out := []any{}
		for _, a := range s.apps {
			out = append(out, s.appJSON(a))
		}
		return data(200, out)
	case r.Method == http.MethodPatch && p == sp+"/services/health":
		return data(200, map[string]any{"updated": len(s.apps)})
	case r.Method == http.MethodPost && p == sp+"/offline":
		return data(200, map[string]any{"status": "offline"})
	case r.Method == http.MethodPost && p == "/api/services/register":
		var in struct {
			Name, Host string
			Port       int
		}
		if json.Unmarshal(body, &in) != nil || in.Name == "" {
			return fail(400, "Invalid request")
		}
		a := s.addApp(in.Name, in.Host, in.Port)
		m := s.appJSON(a)
		delete(m, "description")
		delete(m, "icon_url")
		return data(201, m)
	case r.Method == http.MethodPost && p == "/api/services/register/batch":
		var in struct {
			Services []struct {
				Name, Host string
				Port       int
			}
		}
		if json.Unmarshal(body, &in) != nil || len(in.Services) == 0 {
			return fail(400, "Invalid request")
		}
		out := []any{}
		for _, sv := range in.Services {
			a := s.addApp(sv.Name, sv.Host, sv.Port)
			m := s.appJSON(a)
			delete(m, "description")
			delete(m, "icon_url")
			m["requested_name"], m["server_id"] = sv.Name, s.serverID
			out = append(out, m)
		}
		return data(201, map[string]any{"services": out})
	}
	s.failf("unexpected 1.x call %s %s", r.Method, p)
	return fail(404, "Not found")
}

// proof checks a DPoP proof as the device API does and returns the key id.
// A stale nonce gets a challenge; the first call of each route always does.
func (s *standin) proof(r *http.Request, body []byte) (string, *reply) {
	refuse := func(code string) (string, *reply) {
		s.failf("proof refused (%s) on %s %s", code, r.Method, r.URL.Path)
		return "", &reply{status: 401, body: map[string]string{"error": "invalid_proof", "code": code}}
	}
	parts := strings.Split(r.Header.Get("DPoP"), ".")
	if len(parts) != 3 {
		return refuse("malformed")
	}
	hb, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	pl, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return refuse("malformed")
	}
	var h struct {
		Typ string `json:"typ"`
		Alg string `json:"alg"`
		JWK struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
		} `json:"jwk"`
	}
	if err := json.Unmarshal(hb, &h); err != nil || h.Typ != "dpop+jwt" || h.Alg != "EdDSA" || h.JWK.Kty != "OKP" || h.JWK.Crv != "Ed25519" {
		return refuse("malformed")
	}
	x, err := base64.RawURLEncoding.DecodeString(h.JWK.X)
	if err != nil || len(x) != ed25519.PublicKeySize || !ed25519.Verify(x, []byte(parts[0]+"."+parts[1]), sig) {
		return refuse("bad_signature")
	}
	c, err := claims.ParseDPoPClaims(pl)
	if err != nil {
		return refuse("malformed")
	}
	switch {
	case c.HTM != r.Method:
		return refuse("wrong_htm")
	case c.HTU != apiOrigin+r.URL.Path:
		return refuse("wrong_htu")
	case c.BodySHA256 != claims.BodyDigest(body):
		return refuse("body_mismatch")
	case s.jtis[c.JTI]:
		return refuse("replayed")
	}
	if d := time.Since(time.Unix(c.IAT, 0)); d > 5*time.Minute || d < -5*time.Minute {
		return refuse("malformed")
	}
	s.jtis[c.JTI] = true
	route := r.Method + " " + r.URL.Path
	if c.Nonce != s.nonce || !s.challenged[route] {
		s.challenged[route] = true
		return "", &reply{status: 401, body: map[string]string{"error": "use_dpop_nonce", "code": "use_dpop_nonce"},
			header: map[string]string{"DPoP-Nonce": s.nonce, "WWW-Authenticate": `DPoP error="use_dpop_nonce"`}}
	}
	// Key id: RFC 7638 thumbprint of the OKP key.
	sum := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(x) + `"}`))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func (s *standin) device(r *http.Request, body []byte, rc *rec) reply {
	p := r.URL.Path
	if p == "/device/v2/enroll" && !s.enrolOn {
		// Route not deployed yet.
		return reply{status: 404, body: map[string]string{"error": "Not found"}}
	}
	if r.Header.Get("X-FRP-Token") != "" && p != "/device/v2/enroll" {
		s.failf("token sent on %s", p)
	}
	kid, refused := s.proof(r, body)
	if refused != nil {
		return *refused
	}
	rc.KeyID = kid
	serverBody := `{"server_id":"` + s.serverID + `"}`
	if p == "/device/v2/enroll" {
		if r.Method != http.MethodPost || string(body) != serverBody {
			s.failf("enroll body %q", body)
			return reply{status: 400, body: map[string]string{"error": "invalid_request"}}
		}
		if r.Header.Get("X-FRP-Token") != s.token || s.switched {
			return reply{status: 401, body: map[string]string{"error": "invalid_token"}}
		}
		if s.enrolledKID != "" && s.enrolledKID != kid {
			return reply{status: 409, body: map[string]string{"error": "already_enrolled"}}
		}
		if s.enrolledKID == "" {
			s.enrolledKID, s.deviceID = kid, uuid4()
		}
		return reply{status: 200, body: map[string]string{"result": "enrolled", "server_id": s.serverID, "device_id": s.deviceID, "key_id": kid}}
	}
	if kid != s.enrolledKID {
		s.failf("unknown key on %s", p)
		return reply{status: 401, body: map[string]string{"error": "invalid_proof", "code": "invalid_proof"}}
	}
	switch {
	case r.Method == http.MethodGet && p == "/device/v2/identity":
		return reply{status: 200, body: map[string]string{"server_id": s.serverID, "device_id": s.deviceID, "key_id": kid}}
	case r.Method == http.MethodPost && p == "/device/v2/enroll/confirm":
		if string(body) != serverBody {
			s.failf("confirm body %q", body)
			return reply{status: 400, body: map[string]string{"error": "invalid_request"}}
		}
		if s.confirmBlock {
			return reply{status: 503, body: map[string]string{"error": "unavailable"}}
		}
		s.switched, s.retired = true, true
		return reply{status: 200, body: map[string]string{"result": "switched"}}
	case r.Method == http.MethodGet && p == "/device/v2/apps":
		apps := []any{}
		for _, a := range s.apps {
			var lid any
			if a.LocalID != "" {
				lid = a.LocalID
			}
			apps = append(apps, map[string]any{"id": a.ID, "local_id": lid, "name": a.Name, "host": a.Host, "port": a.Port,
				"subdomain": a.Subdomain, "public_requested": false})
		}
		return reply{status: 200, body: map[string]any{"apps": apps, "deleted": []string{}}}
	case r.Method == http.MethodPost && p == "/device/v2/apps":
		return s.register(r, body)
	case r.Method == http.MethodPost && p == "/device/v2/apps/delete":
		s.failf("delete call %s", body)
		return reply{status: 400, body: map[string]string{"error": "invalid_request"}}
	case r.Method == http.MethodPost && p == "/device/v2/health":
		return reply{status: 200, body: map[string]int{"updated": 0}}
	}
	s.failf("unexpected device call %s %s", r.Method, p)
	return reply{status: 404, body: map[string]string{"error": "Not found"}}
}

// register links each item to the app with its local_id, or adopts the
// unlinked 1.x app of the same name, or creates an app.
func (s *standin) register(r *http.Request, body []byte) reply {
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		s.failf("register without an idempotency key")
	}
	if prev, ok := s.idem[key]; ok {
		return reply{status: 200, body: json.RawMessage(prev)}
	}
	var in struct {
		Apps []struct {
			LocalID string `json:"local_id"`
			Name    string `json:"name"`
			Host    string `json:"host"`
			Port    int    `json:"port"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		s.failf("register body: %v", err)
		return reply{status: 400, body: map[string]string{"error": "invalid_request"}}
	}
	items := []any{}
	for _, it := range in.Apps {
		var a *serverApp
		result := "updated"
		for _, x := range s.apps {
			if x.LocalID == it.LocalID {
				a = x
			}
		}
		if a == nil {
			for _, x := range s.apps {
				if x.LocalID == "" && x.Name == it.Name {
					a = x
				}
			}
		}
		if a == nil {
			a, result = s.addApp(it.Name, it.Host, it.Port), "created"
		}
		if a.LocalID == it.LocalID && a.Name == it.Name && a.Host == it.Host && a.Port == it.Port {
			result = "unchanged"
		}
		a.LocalID, a.Name, a.Host, a.Port = it.LocalID, it.Name, it.Host, it.Port
		items = append(items, map[string]string{"local_id": it.LocalID, "id": a.ID, "result": result, "subdomain": a.Subdomain})
	}
	out, _ := json.Marshal(map[string]any{"items": items})
	s.idem[key] = out
	return reply{status: 200, body: json.RawMessage(out)}
}
