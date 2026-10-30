package session

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"

	"github.com/seawise/client/internal/protocol"
)

func TestHTTPSHeartbeatRequestAndNonceRetry(t *testing.T) {
	var mu sync.Mutex
	var proofs []string
	var bodies [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != HeartbeatPath || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("request %s %s", r.Method, r.URL.Path)
		}
		b := make([]byte, 1024)
		n, _ := r.Body.Read(b)
		mu.Lock()
		proofs = append(proofs, r.Header.Get("DPoP"))
		bodies = append(bodies, b[:n])
		first := len(proofs) == 1
		mu.Unlock()
		if first {
			w.Header().Set("DPoP-Nonce", "server-nonce-1")
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("DPoP-Nonce", "server-nonce-2")
		_, _ = w.Write([]byte(answerJSON("state-token", "flags-token")))
	}))
	defer srv.Close()
	hb := &Heartbeat{Origin: srv.URL + "/", Key: func() crypto.Signer { return seedKey("device") }, Client: srv.Client(), Version: "2.0.0",
		Now: func() time.Time { return time.Unix(1700000000, 0) }}
	a, err := hb.HTTPS(context.Background(), "AAAAAAAAAAAAAAAAAAAAAA", true)
	if err != nil || a.State != "state-token" || a.Flags != "flags-token" {
		t.Fatal(a, err)
	}
	if len(proofs) != 2 {
		t.Fatal(len(proofs))
	}
	var body map[string]any
	if err := json.Unmarshal(bodies[1], &body); err != nil || body["nonce"] != "AAAAAAAAAAAAAAAAAAAAAA" || body["frp_connected"] != true || body["client_version"] != "2.0.0" || len(body) != 3 {
		t.Fatal(string(bodies[1]))
	}
	res, err := protocol.VerifyDPoP(proofs[1], protocol.DPoPRequest{Method: "POST", URL: srv.URL + HeartbeatPath, Body: bodies[1]},
		func(n string) bool { return n == "server-nonce-1" }, func(string, string) bool { return true })
	if err != nil || res.KeyID != deviceKeyID() {
		t.Fatal(res, err)
	}
	if hb.dpopNonce() != "server-nonce-2" {
		t.Fatal("newest nonce not kept")
	}
}

func TestHTTPSHeartbeatFailures(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"401 twice": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("DPoP-Nonce", "n")
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(http.StatusUnauthorized)
		},
		"503":       func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) },
		"unsigned":  func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"data":{"status":"ok"}}`)) },
		"too large": func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(strings.Repeat(" ", maxAnswer+1))) },
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(h)
			defer srv.Close()
			hb := &Heartbeat{Origin: srv.URL, Key: func() crypto.Signer { return seedKey("device") }, Client: srv.Client()}
			if _, err := hb.HTTPS(context.Background(), "AAAAAAAAAAAAAAAAAAAAAA", false); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	hb := &Heartbeat{Origin: "http://127.0.0.1:1", Key: func() crypto.Signer { return nil }}
	if _, err := hb.HTTPS(context.Background(), "AAAAAAAAAAAAAAAAAAAAAA", false); err == nil {
		t.Fatal("no key accepted")
	}
}

func TestParseAnswer(t *testing.T) {
	cases := map[string]struct {
		in    string
		state string
		flags string
		err   error
	}{
		"state and flags": {`{"data":{"signed_time":"s","flags":"f","other":1}}`, "s", "f", nil},
		"null flags":      {`{"data":{"signed_time":"s","flags":null}}`, "s", "", nil},
		"no flags":        {`{"data":{"signed_time":"s"}}`, "s", "", nil},
		"no state":        {`{"data":{"flags":"f"}}`, "", "", ErrUnsigned},
		"empty state":     {`{"data":{"signed_time":""}}`, "", "", ErrUnsigned},
	}
	for name, c := range cases {
		a, err := parseAnswer([]byte(c.in))
		if !errors.Is(err, c.err) || a.State != c.state || a.Flags != c.flags {
			t.Errorf("%s: %+v %v", name, a, err)
		}
	}
	for _, bad := range []string{``, `[]`, `{}`, `{"data":null}`, `{"data":{"signed_time":1}}`, `{"data":{"signed_time":"s","flags":3}}`} {
		if _, err := parseAnswer([]byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestDeviceResult(t *testing.T) {
	hb := &Heartbeat{}
	ok := []byte(answerJSON("s", ""))
	if a, retry, err := hb.Result(&pb.DeviceResult{Class: pb.ResultClass_DONE, HttpStatus: 200, Body: ok}); err != nil || retry || a.State != "s" {
		t.Fatal(a, retry, err)
	}
	if _, retry, err := hb.Result(&pb.DeviceResult{Class: pb.ResultClass_DONE, HttpStatus: 401, DpopNonce: "x"}); err != nil || !retry || hb.dpopNonce() != "x" {
		t.Fatal(retry, err)
	}
	for _, r := range []*pb.DeviceResult{
		{Class: pb.ResultClass_UNAVAILABLE},
		{Class: pb.ResultClass_DONE, HttpStatus: 401},
		{Class: pb.ResultClass_DONE, HttpStatus: 503},
	} {
		if _, retry, err := hb.Result(r); err == nil || retry {
			t.Errorf("%v: accepted", r)
		}
	}
}

func TestCallShape(t *testing.T) {
	hb := &Heartbeat{Origin: "https://api.example.test", Key: func() crypto.Signer { return seedKey("device") }, Version: "2.0.0"}
	key := make([]byte, 16)
	c, err := hb.Call(7, key, "AAAAAAAAAAAAAAAAAAAAAA", true)
	if err != nil || c.CallId != 7 || c.Method != pb.DeviceMethod_SIGNED_TIME || string(c.Body) != string(requestBody("AAAAAAAAAAAAAAAAAAAAAA", true, "2.0.0")) {
		t.Fatal(c, err)
	}
	if _, err := protocol.VerifyDPoP(c.Dpop, protocol.DPoPRequest{Method: "POST", URL: "https://api.example.test" + HeartbeatPath, Body: c.Body},
		func(n string) bool { return n == unknownNonce }, func(string, string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	hb.keepNonce("bad nonce with space")
	if hb.dpopNonce() != unknownNonce {
		t.Fatal("invalid nonce kept")
	}
}

func TestHTTPSAnswerAtCap(t *testing.T) {
	body := answerJSON("s", "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat(" ", maxAnswer-len(body)) + body))
	}))
	defer srv.Close()
	hb := &Heartbeat{Origin: srv.URL, Key: func() crypto.Signer { return seedKey("device") }, Client: srv.Client()}
	if a, err := hb.HTTPS(context.Background(), "AAAAAAAAAAAAAAAAAAAAAA", false); err != nil || a.State != "s" {
		t.Fatal(a, err)
	}
}
