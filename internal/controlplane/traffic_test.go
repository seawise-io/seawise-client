package controlplane

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Idle control traffic per device, in bytes per 30-day month, both
// directions, on the wire. MonthlyControlBudget fails the build at the
// default heartbeat. MonthlyControlTarget must hold once the server asks
// for heartbeats every TargetBeat, so the target stays one server setting
// away.
const (
	MonthlyControlBudget = 100_000_000
	MonthlyControlTarget = 50_000_000
	TargetBeat           = 60 * time.Second
)

const (
	month = 30 * 24 * time.Hour
	// tcpOverhead is IPv4 + TCP with timestamps per segment.
	tcpOverhead = 52
	// reconnectEvery charges a full new TLS connection this often, for
	// idle timeouts and network changes along the way.
	reconnectEvery = time.Hour
	trafficApps    = 10
)

type countingConn struct {
	net.Conn
	c *counters
}

type counters struct {
	in, out, segs atomic.Int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.c.in.Add(int64(n))
		c.c.segs.Add(int64(1 + n/1448))
	}
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.c.out.Add(int64(n))
		c.c.segs.Add(int64(1 + n/1448))
	}
	return n, err
}

func (c *counters) wire() int64 { return c.in.Load() + c.out.Load() + c.segs.Load()*tcpOverhead }

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// productionLikeServer answers like the API behind its edge, including the
// response headers a CDN and the framework add.
func productionLikeServer(t *testing.T) *httptest.Server {
	t.Helper()
	var list strings.Builder
	list.WriteString(`{"data":[`)
	for i := 0; i < trafficApps; i++ {
		if i > 0 {
			list.WriteString(",")
		}
		fmt.Fprintf(&list, `{"id":"aaaaaaaa-0000-4000-8000-%012d","name":"Application %d","subdomain":"calm-otter-%d","host":"192.168.100.%d","port":%d,"status":"online","icon_url":"https://cdn.example.com/icons/application-%d.png","description":null,"created_at":"2026-01-01T00:00:00.000000+00:00","is_public":false}`, i, i, i, i+10, 8000+i, i)
	}
	list.WriteString(`]}`)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Type", "application/json; charset=utf-8")
		h.Set("Server", "cloudflare")
		h.Set("Cf-Ray", randomHex(8)+"-FRA")
		h.Set("Cf-Cache-Status", "DYNAMIC")
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("Vary", "Origin, Accept-Encoding")
		h.Set("X-Request-Id", randomHex(16))
		h.Set("X-Ratelimit-Limit", "120")
		h.Set("X-Ratelimit-Remaining", "119")
		h.Set("X-Ratelimit-Reset", "57")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		if r.Method == http.MethodPost {
			fmt.Fprintf(w, `{"data":{"status":"ok","server_status":"online","server_time":"%s","previous_status":"online","gap_seconds":30,"next_heartbeat_ms":30000,"timeout_ms":90000}}`,
				time.Now().UTC().Format("2006-01-02T15:04:05.000Z"))
			return
		}
		_, _ = w.Write([]byte(list.String()))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func countingClient(t *testing.T, srv *httptest.Server, c *counters) *Client {
	t.Helper()
	tr := NewTransport(func(string) string { return "" }, srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs)
	dial := tr.DialContext
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &countingConn{Conn: conn, c: c}, nil
	}
	cl, err := New(Config{BaseURL: srv.URL, Token: func() string { return token }, HTTPClient: &http.Client{Transport: tr}})
	if err != nil {
		t.Fatal(err)
	}
	return cl
}

func heartbeatReq() HeartbeatRequest {
	return HeartbeatRequest{FRPConnected: true, ServiceCount: trafficApps, ClientVersion: "2.0.0", ConnectionID: randomHex(16)}
}

// TestControlTrafficBudget estimates a month of idle control traffic from
// measured heartbeat and service list exchanges at the default intervals.
func TestControlTrafficBudget(t *testing.T) {
	srv := productionLikeServer(t)
	ctx := context.Background()

	// First exchange on a new connection: TLS handshake and HTTP/2 setup.
	first := &counters{}
	if _, err := countingClient(t, srv, first).Heartbeat(ctx, serverID, heartbeatReq()); err != nil {
		t.Fatal(err)
	}

	c := &counters{}
	cl := countingClient(t, srv, c)
	for i := 0; i < 3; i++ {
		if _, err := cl.Heartbeat(ctx, serverID, heartbeatReq()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := cl.ListServices(ctx, serverID); err != nil {
		t.Fatal(err)
	}
	const n = 20
	before := c.wire()
	for i := 0; i < n; i++ {
		if _, err := cl.Heartbeat(ctx, serverID, heartbeatReq()); err != nil {
			t.Fatal(err)
		}
	}
	// Two pure ACKs per exchange; no keepalive probes, since the TCP
	// keepalive idle time exceeds the heartbeat interval.
	if tcpKeepAlive <= DefaultBeat {
		t.Fatalf("TCP keepalive %v would probe between heartbeats", tcpKeepAlive)
	}
	hb := (c.wire()-before)/n + 2*tcpOverhead
	before = c.wire()
	for i := 0; i < n; i++ {
		if _, err := cl.ListServices(ctx, serverID); err != nil {
			t.Fatal(err)
		}
	}
	list := (c.wire()-before)/n + 2*tcpOverhead
	handshake := first.wire() - (hb - 2*tcpOverhead)

	estimate := func(beat time.Duration) int64 {
		beats := int64(month / beat)
		return beats*hb + beats/DefaultListEvery*list + int64(month/reconnectEvery)*handshake
	}
	total := estimate(DefaultBeat)
	needed := DefaultBeat
	for estimate(needed) > MonthlyControlTarget && needed < MaxHeartbeat {
		needed += 5 * time.Second
	}
	t.Logf("per heartbeat %d B, per list (%d apps) %d B, new connection %d B; at a %v heartbeat with a list every %d: %.1f MB/month (budget %.0f MB); %.1f MB/month at a %v heartbeat (target %.0f MB, reached at %v)",
		hb, trafficApps, list, handshake, DefaultBeat, DefaultListEvery, float64(total)/1e6, float64(MonthlyControlBudget)/1e6,
		float64(estimate(TargetBeat))/1e6, TargetBeat, float64(MonthlyControlTarget)/1e6, needed)
	if total > MonthlyControlBudget {
		t.Fatalf("idle control traffic %.1f MB/month over budget %.0f MB", float64(total)/1e6, float64(MonthlyControlBudget)/1e6)
	}
	if at := estimate(TargetBeat); at > MonthlyControlTarget {
		t.Fatalf("idle control traffic %.1f MB/month at a %v heartbeat, over target %.0f MB", float64(at)/1e6, TargetBeat, float64(MonthlyControlTarget)/1e6)
	}
	// The client follows a server that asks for the target interval.
	parsed, err := parseHeartbeat([]byte(fmt.Sprintf(`{"status":"ok","next_heartbeat_ms":%d}`, TargetBeat.Milliseconds())), nil)
	if err != nil || parsed.NextHeartbeat != TargetBeat {
		t.Fatalf("server interval %v gives %+v, %v", TargetBeat, parsed, err)
	}
}
