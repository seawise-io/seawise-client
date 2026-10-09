package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	serverID  = "11111111-2222-4333-8444-555555555555"
	serviceID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	token     = "frp-token-value"
)

var testDomains = []string{".seawise.dev"}

type recorded struct {
	Method  string
	Path    string
	Header  http.Header
	Body    string
	Attempt int
}

type fakeServer struct {
	t       *testing.T
	srv     *httptest.Server
	mu      sync.Mutex
	reqs    []recorded
	handler func(w http.ResponseWriter, r *http.Request, n int)
	count   atomic.Int32
}

func newFake(t *testing.T, h func(w http.ResponseWriter, r *http.Request, n int)) *fakeServer {
	t.Helper()
	f := &fakeServer{t: t, handler: h}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(f.count.Add(1))
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.reqs = append(f.reqs, recorded{Method: r.Method, Path: r.URL.Path, Header: r.Header.Clone(), Body: string(b), Attempt: n})
		f.mu.Unlock()
		f.handler(w, r, n)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeServer) requests() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.reqs...)
}

func (f *fakeServer) client(t *testing.T) *Client {
	t.Helper()
	c, err := New(Config{
		BaseURL:        f.srv.URL,
		Token:          func() string { return token },
		Version:        "test",
		Timeout:        2 * time.Second,
		AllowedDomains: testDomains,
		Sleep:          func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func jsonReply(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func kindOf(t *testing.T, err error) Kind {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("error %v is not *Error", err)
	}
	return e.Kind
}

const okHeartbeat = `{"data":{"status":"ok","server_status":"online","server_time":"2026-10-08T12:00:00Z","previous_status":"online","gap_seconds":30,"next_heartbeat_ms":30000,"timeout_ms":90000}}`

func TestNewRejectsUnsafeBaseURL(t *testing.T) {
	for _, u := range []string{
		"", "http://api.seawise.io", "ftp://x", "https://user:pw@api.seawise.io",
		"https://api.seawise.io/?q=1", "https://api.seawise.io/#f", "https://api.seawise.io/v1",
		"http://localhost.evil.example", "https://", "http://127.0.0.1.nip.io",
	} {
		if _, err := New(Config{BaseURL: u, Token: func() string { return token }}); err == nil {
			t.Errorf("accepted %q", u)
		}
	}
	for _, u := range []string{"https://api.seawise.io", "https://api.seawise.io/", "http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080", "http://host.docker.internal:8080"} {
		if _, err := New(Config{BaseURL: u, Token: func() string { return token }}); err != nil {
			t.Errorf("rejected %q: %v", u, err)
		}
	}
}

func TestNoRedirect(t *testing.T) {
	var leaked atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-FRP-Token") != "" {
			leaked.Store(true)
		}
		jsonReply(w, 200, okHeartbeat)
	}))
	defer other.Close()
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	})
	_, err := f.client(t).Heartbeat(context.Background(), serverID, HeartbeatRequest{ConnectionID: "c"})
	if kindOf(t, err) != Transient {
		t.Fatalf("redirect kind: %v", err)
	}
	if leaked.Load() {
		t.Fatal("token sent to redirect target")
	}
}

func TestHeartbeatOK(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ int) { jsonReply(w, 200, okHeartbeat) })
	hb, err := f.client(t).Heartbeat(context.Background(), serverID, HeartbeatRequest{FRPConnected: true, ServiceCount: 2, ClientVersion: "v", ConnectionID: "conn"})
	if err != nil {
		t.Fatal(err)
	}
	if hb.Status != "ok" || hb.NextHeartbeat != 30*time.Second {
		t.Fatalf("heartbeat %+v", hb)
	}
	r := f.requests()[0]
	if r.Method != "POST" || r.Path != "/api/servers/"+serverID+"/heartbeat" || r.Header.Get("X-FRP-Token") != token {
		t.Fatalf("request %+v", r)
	}
	if r.Header.Get("Idempotency-Key") == "" || !strings.HasPrefix(r.Header.Get("User-Agent"), "seawise-agent/") {
		t.Fatalf("headers %v", r.Header)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(r.Body), &body); err != nil || body["connection_id"] != "conn" || body["service_count"] != float64(2) || body["frp_connected"] != true {
		t.Fatalf("body %s", r.Body)
	}
}

func TestHeartbeatNextIntervalClamped(t *testing.T) {
	for in, want := range map[string]time.Duration{"1": MinHeartbeat, "999999999": MaxHeartbeat, "45000": 45 * time.Second} {
		f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ int) {
			jsonReply(w, 200, `{"data":{"status":"ok","next_heartbeat_ms":`+in+`}}`)
		})
		hb, err := f.client(t).Heartbeat(context.Background(), serverID, HeartbeatRequest{})
		if err != nil || hb.NextHeartbeat != want {
			t.Errorf("%s: %v %v", in, hb, err)
		}
	}
}

func TestHeartbeatRemovalNeedsUnpairBody(t *testing.T) {
	cases := []struct {
		name string
		ct   string
		body string
		want Kind
	}{
		{"unpair", "application/json", `{"error":"Server not found","action":"unpair","reason":"server_deleted"}`, Removal},
		{"empty body", "application/json", ``, Transient},
		{"html", "text/html", `<html>gone</html>`, Transient},
		{"no action", "application/json", `{"error":"gone"}`, Transient},
		{"other action", "application/json", `{"action":"wipe"}`, Transient},
		{"json but wrong type", "text/plain", `{"action":"unpair"}`, Transient},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ int) {
				w.Header().Set("Content-Type", tc.ct)
				w.WriteHeader(410)
				_, _ = io.WriteString(w, tc.body)
			})
			_, err := f.client(t).Heartbeat(context.Background(), serverID, HeartbeatRequest{})
			if got := kindOf(t, err); got != tc.want {
				t.Fatalf("kind %v want %v", got, tc.want)
			}
		})
	}
}

func TestRemoval410OnlyFromHeartbeat(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		jsonReply(w, 410, `{"action":"unpair","reason":"server_deleted"}`)
	})
	c := f.client(t)
	if _, err := c.ListServices(context.Background(), serverID); kindOf(t, err) == Removal {
		t.Fatal("list 410 treated as removal")
	}
	if _, err := c.PairComplete(context.Background(), "device-code"); kindOf(t, err) != Rejected {
		t.Fatalf("pair complete 410: %v", err)
	}
}

func TestHeartbeatSuperseded(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		jsonReply(w, 409, `{"error":"Connection superseded","action":"superseded"}`)
	})
	_, err := f.client(t).Heartbeat(context.Background(), serverID, HeartbeatRequest{})
	if kindOf(t, err) != Superseded {
		t.Fatal(err)
	}
	if n := len(f.requests()); n != 1 {
		t.Fatalf("superseded retried %d times", n)
	}
}

func TestHeartbeatShardOutsideAllowed(t *testing.T) {
	for _, body := range []string{
		`{"data":{"status":"ok","shard":{"frp_server_addr":"evil.example","frp_server_port":7000}}}`,
		`{"data":{"status":"migrate","migrate_to":{"frp_server_addr":"frp-1.seawise.dev.evil.example","frp_server_port":7000}}}`,
		`{"data":{"status":"migrate","migrate_to":{"frp_server_addr":"frp-1.seawise.dev","frp_server_port":70000}}}`,
		`{"data":{"status":"migrate"}}`,
		`{"data":{"status":"wipe"}}`,
		`{"data":{}}`,
	} {
		f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ int) { jsonReply(w, 200, body) })
		if _, err := f.client(t).Heartbeat(context.Background(), serverID, HeartbeatRequest{}); kindOf(t, err) != Transient {
			t.Errorf("%s accepted: %v", body, err)
		}
	}
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		jsonReply(w, 200, `{"data":{"status":"migrate","migrate_to":{"frp_server_addr":"FRP-2.seawise.dev","frp_server_port":7000,"shard_id":"x"}}}`)
	})
	hb, err := f.client(t).Heartbeat(context.Background(), serverID, HeartbeatRequest{})
	if err != nil || hb.MigrateTo == nil || hb.MigrateTo.Addr != "frp-2.seawise.dev" || hb.MigrateTo.Port != 7000 {
		t.Fatalf("migrate: %+v %v", hb, err)
	}
}

func TestListServices(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		jsonReply(w, 200, `{"data":[{"id":"`+serviceID+`","name":"Plex","subdomain":"calm-otter","host":"192.168.1.5","port":32400,"status":"online","icon_url":null,"description":null,"created_at":"2026-01-01T00:00:00Z","future_field":{"x":1}}]}`)
	})
	got, err := f.client(t).ListServices(context.Background(), serverID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != serviceID || got[0].Host != "192.168.1.5" || got[0].Port != 32400 || got[0].Subdomain != "calm-otter" {
		t.Fatalf("list %+v", got)
	}
	if r := f.requests()[0]; r.Method != "GET" || r.Path != "/api/servers/"+serverID+"/services" {
		t.Fatalf("request %+v", r)
	}
}

func TestListNullData(t *testing.T) {
	for _, body := range []string{`{"data":null}`, `{}`, `{"data":{}}`, `{"data":"[]"}`, `[]`, `null`, `{"data":[]} {"data":[]}`, `{"data":[null]}`} {
		f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ int) { jsonReply(w, 200, body) })
		if _, err := f.client(t).ListServices(context.Background(), serverID); kindOf(t, err) != Transient {
			t.Errorf("%s: %v", body, err)
		}
	}
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ int) { jsonReply(w, 200, `{"data":[]}`) })
	got, err := f.client(t).ListServices(context.Background(), serverID)
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("empty list: %v %v", got, err)
	}
}

func TestListRejectsBadItems(t *testing.T) {
	for _, item := range []string{
		`{"id":"not-a-uuid","name":"a","host":"h","port":80}`,
		`{"id":"` + serviceID + `","name":"","host":"h","port":80}`,
		`{"id":"` + serviceID + `","name":"a","host":"","port":80}`,
		`{"id":"` + serviceID + `","name":"a","host":"h h","port":80}`,
		`{"id":"` + serviceID + `","name":"a","host":"h","port":0}`,
		`{"id":"` + serviceID + `","name":"a","host":"h","port":"80"}`,
		`{"id":"` + serviceID + `","name":"a","host":"h","port":80,"subdomain":"Bad_Label"}`,
		`{"id":"` + serviceID + `","name":"a","host":"h","port":80.5}`,
	} {
		f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ int) { jsonReply(w, 200, `{"data":[`+item+`]}`) })
		if _, err := f.client(t).ListServices(context.Background(), serverID); err == nil {
			t.Errorf("accepted %s", item)
		}
	}
}

func TestListTooMany(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"data":[`)
	for i := 0; i <= MaxListItems; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"id":"` + serviceID + `","name":"a","host":"h","port":80}`)
	}
	b.WriteString(`]}`)
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ int) { jsonReply(w, 200, b.String()) })
	if _, err := f.client(t).ListServices(context.Background(), serverID); err == nil {
		t.Fatal("accepted oversized list")
	}
}

func TestBodyTooLarge(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":[],"pad":"`+strings.Repeat("a", MaxBody)+`"}`)
	})
	if _, err := f.client(t).ListServices(context.Background(), serverID); kindOf(t, err) != Transient {
		t.Fatalf("oversized body: %v", err)
	}
}

func TestNonJSONSuccessIsTransient(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `{"data":[]}`)
	})
	if _, err := f.client(t).ListServices(context.Background(), serverID); kindOf(t, err) != Transient {
		t.Fatalf("html success: %v", err)
	}
}

func TestStatusClasses(t *testing.T) {
	for status, want := range map[int]Kind{500: Transient, 502: Transient, 503: Transient, 429: Transient, 400: Rejected, 401: Rejected, 403: Rejected, 404: Rejected, 302: Transient} {
		f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ int) { jsonReply(w, status, `{"error":"x"}`) })
		if _, err := f.client(t).ListServices(context.Background(), serverID); kindOf(t, err) != want {
			t.Errorf("%d: %v", status, err)
		}
	}
}

func TestRetryIdempotentOnly(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if n < 3 {
			jsonReply(w, 503, `{}`)
			return
		}
		jsonReply(w, 200, `{"data":[]}`)
	})
	if _, err := f.client(t).ListServices(context.Background(), serverID); err != nil {
		t.Fatal(err)
	}
	if n := len(f.requests()); n != 3 {
		t.Fatalf("list attempts %d", n)
	}

	f = newFake(t, func(w http.ResponseWriter, r *http.Request, n int) { jsonReply(w, 503, `{}`) })
	_, err := f.client(t).RegisterBatch(context.Background(), serverID, []ServiceInput{{Name: "a", Host: "h", Port: 80}})
	if err == nil || len(f.requests()) != 1 {
		t.Fatalf("batch register retried: %d %v", len(f.requests()), err)
	}
	f = newFake(t, func(w http.ResponseWriter, r *http.Request, n int) { jsonReply(w, 503, `{}`) })
	if err := f.client(t).DeleteService(context.Background(), serverID, serviceID); err == nil || len(f.requests()) != 1 {
		t.Fatalf("delete retried: %d", len(f.requests()))
	}
	f = newFake(t, func(w http.ResponseWriter, r *http.Request, n int) { jsonReply(w, 503, `{}`) })
	if err := f.client(t).Disconnect(context.Background(), serverID); err == nil || len(f.requests()) != 1 {
		t.Fatalf("disconnect retried: %d", len(f.requests()))
	}
	f = newFake(t, func(w http.ResponseWriter, r *http.Request, n int) { jsonReply(w, 400, `{}`) })
	if _, err := f.client(t).ListServices(context.Background(), serverID); err == nil || len(f.requests()) != 1 {
		t.Fatalf("rejected retried: %d", len(f.requests()))
	}
}

func TestRetryKeepsIdempotencyKey(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if n < 2 {
			jsonReply(w, 502, `{}`)
			return
		}
		jsonReply(w, 201, `{"data":{"id":"`+serviceID+`","subdomain":"calm-otter"}}`)
	})
	svc, err := f.client(t).RegisterService(context.Background(), serverID, "Plex", "192.168.1.5", 32400)
	if err != nil || svc.ID != serviceID {
		t.Fatal(svc, err)
	}
	reqs := f.requests()
	if len(reqs) != 2 || reqs[0].Header.Get("Idempotency-Key") == "" || reqs[0].Header.Get("Idempotency-Key") != reqs[1].Header.Get("Idempotency-Key") {
		t.Fatalf("idempotency keys differ: %v", reqs)
	}
}

func TestRetry429(t *testing.T) {
	var slept []time.Duration
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if n == 1 {
			w.Header().Set("Retry-After", "7")
			jsonReply(w, 429, `{}`)
			return
		}
		if n == 2 {
			w.Header().Set("Retry-After", "3600")
			jsonReply(w, 429, `{}`)
			return
		}
		jsonReply(w, 200, `{"data":[]}`)
	})
	c := f.client(t)
	c.sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	_, err := c.ListServices(context.Background(), serverID)
	if kindOf(t, err) != Transient {
		t.Fatalf("expected give-up on long Retry-After, got %v", err)
	}
	if len(slept) != 1 || slept[0] != 7*time.Second {
		t.Fatalf("slept %v", slept)
	}
}

func TestBackoffBounded(t *testing.T) {
	var slept []time.Duration
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) { jsonReply(w, 503, `{}`) })
	c := f.client(t)
	c.sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	_, _ = c.ListServices(context.Background(), serverID)
	if len(slept) != MaxAttempts-1 {
		t.Fatalf("slept %v", slept)
	}
	for _, d := range slept {
		if d < 0 || d > DefaultBackoffMax {
			t.Fatalf("backoff %v out of range", d)
		}
	}
}

func TestTimeout(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	})
	c := f.client(t)
	c.timeout = 50 * time.Millisecond
	start := time.Now()
	_, err := c.ListServices(context.Background(), serverID)
	if kindOf(t, err) != Transient || time.Since(start) > 5*time.Second {
		t.Fatalf("timeout: %v after %v", err, time.Since(start))
	}
}

func TestPathParamsValidated(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) { jsonReply(w, 200, `{"data":[]}`) })
	c := f.client(t)
	for _, id := range []string{"", "../../admin", serverID + "/x", "11111111-2222-4333-8444-55555555555g"} {
		if _, err := c.ListServices(context.Background(), id); err == nil {
			t.Errorf("accepted server id %q", id)
		}
		if err := c.DeleteService(context.Background(), serverID, id); err == nil {
			t.Errorf("accepted service id %q", id)
		}
	}
	if len(f.requests()) != 0 {
		t.Fatal("request sent with invalid id")
	}
}

func TestNoTokenNoRequest(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) { jsonReply(w, 200, okHeartbeat) })
	c := f.client(t)
	c.token = func() string { return "" }
	if _, err := c.Heartbeat(context.Background(), serverID, HeartbeatRequest{}); kindOf(t, err) != Rejected {
		t.Fatal(err)
	}
	if len(f.requests()) != 0 {
		t.Fatal("request sent without token")
	}
}

func TestPairFlow(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if r.Header.Get("X-FRP-Token") != "" {
			t.Errorf("pairing call sent token")
		}
		switch r.URL.Path {
		case "/api/servers/pair/request":
			jsonReply(w, 200, `{"data":{"user_code":"ABCD-1234","device_code":"dev","expires_at":"2026-10-08T12:15:00Z"}}`)
		case "/api/servers/pair/status":
			jsonReply(w, 200, `{"data":{"status":"approved"}}`)
		case "/api/servers/pair/complete":
			jsonReply(w, 200, `{"data":{"server_id":"`+serverID+`","server_name":"nas","user_id":"`+serviceID+`","user_email":"x@example.com","frp_token":"tok","frp_server_addr":"frp-1.seawise.dev","frp_server_port":7000,"frp_use_tls":true}}`)
		case "/api/servers/pair/cancel":
			jsonReply(w, 200, `{"data":{"ok":true}}`)
		default:
			jsonReply(w, 404, `{}`)
		}
	})
	c := f.client(t)
	ctx := context.Background()
	pr, err := c.PairRequest(ctx, "nas")
	if err != nil || pr.UserCode != "ABCD-1234" || pr.DeviceCode != "dev" || pr.ExpiresAt.IsZero() {
		t.Fatal(pr, err)
	}
	if st, err := c.PairStatus(ctx, "dev"); err != nil || st != "approved" {
		t.Fatal(st, err)
	}
	p, err := c.PairComplete(ctx, "dev")
	if err != nil || p.ServerID != serverID || p.FRPToken != "tok" || p.FRPServerAddr != "frp-1.seawise.dev" || !p.FRPUseTLS {
		t.Fatal(p, err)
	}
	if err := c.PairCancel(ctx, "dev"); err != nil {
		t.Fatal(err)
	}
}

func TestPairCompleteRejectsBadFields(t *testing.T) {
	good := map[string]any{"server_id": serverID, "server_name": "nas", "frp_token": "tok", "frp_server_addr": "frp-1.seawise.dev", "frp_server_port": 7000, "frp_use_tls": true}
	mutate := []func(m map[string]any){
		func(m map[string]any) { m["server_id"] = "x" },
		func(m map[string]any) { m["frp_token"] = "" },
		func(m map[string]any) { m["frp_token"] = "a\nb" },
		func(m map[string]any) { m["frp_server_addr"] = "evil.example" },
		func(m map[string]any) { m["frp_server_port"] = 0 },
		func(m map[string]any) { delete(m, "frp_use_tls") },
	}
	for i, mut := range mutate {
		m := map[string]any{}
		for k, v := range good {
			m[k] = v
		}
		mut(m)
		b, _ := json.Marshal(map[string]any{"data": m})
		f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) { jsonReply(w, 200, string(b)) })
		if _, err := f.client(t).PairComplete(context.Background(), "dev"); err == nil {
			t.Errorf("mutation %d accepted", i)
		}
	}
}

func TestOtherEndpoints(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		switch {
		case r.Method == "PATCH" && r.URL.Path == "/api/servers/"+serverID+"/services/health":
			jsonReply(w, 200, `{"data":{"updated":1}}`)
		case r.Method == "POST" && r.URL.Path == "/api/servers/"+serverID+"/offline":
			jsonReply(w, 200, `{"data":{"ok":true}}`)
		case r.Method == "DELETE" && r.URL.Path == "/api/servers/"+serverID+"/disconnect":
			w.WriteHeader(204)
		case r.Method == "DELETE" && r.URL.Path == "/api/servers/"+serverID+"/services/"+serviceID:
			w.WriteHeader(204)
		case r.Method == "GET" && r.URL.Path == "/api/certs/status":
			jsonReply(w, 200, `{"data":{"e2e_tls_enabled":false,"acme_directory":""}}`)
		case r.Method == "POST" && r.URL.Path == "/api/certs/issue":
			jsonReply(w, 200, `{"data":{"certificate":"PEM","domain":"calm-otter.seawise.dev","expires_at":"2027-01-01T00:00:00Z"}}`)
		case r.Method == "POST" && r.URL.Path == "/api/services/register/batch":
			jsonReply(w, 201, `{"data":{"services":[{"id":"`+serviceID+`","name":"a","requested_name":"a","host":"h","port":80,"subdomain":"calm-otter","status":"starting"}]}}`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			jsonReply(w, 404, `{}`)
		}
	})
	c := f.client(t)
	ctx := context.Background()
	if err := c.ReportHealth(ctx, serverID, []Health{{ID: serviceID, Status: "online"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.ReportHealth(ctx, serverID, []Health{{ID: serviceID, Status: "deleted"}}); err == nil {
		t.Fatal("bad health status accepted")
	}
	if err := c.MarkOffline(ctx, serverID); err != nil {
		t.Fatal(err)
	}
	if err := c.Disconnect(ctx, serverID); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteService(ctx, serverID, serviceID); err != nil {
		t.Fatal(err)
	}
	cs, err := c.CertStatus(ctx)
	if err != nil || cs.E2E {
		t.Fatal(cs, err)
	}
	cert, err := c.CertIssue(ctx, "calm-otter", []byte("CSR"))
	if err != nil || cert.PEM != "PEM" {
		t.Fatal(cert, err)
	}
	out, err := c.RegisterBatch(ctx, serverID, []ServiceInput{{Name: "a", Host: "h", Port: 80}})
	if err != nil || len(out) != 1 || out[0].Subdomain != "calm-otter" {
		t.Fatal(out, err)
	}
	if out, err := c.RegisterBatch(ctx, serverID, nil); err != nil || len(out) != 0 {
		t.Fatal(out, err)
	}
}
