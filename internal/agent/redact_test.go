package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRedactWriterMasksSecretsPerLine(t *testing.T) {
	var out bytes.Buffer
	w := newRedactWriter(&out, "hunter22", "tok-abcdef")
	for _, chunk := range []string{"login with tok-ab", "cdef ok\nproxy http://u:hunt", "er22@p:3128 failed\npartial"} {
		if _, err := w.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	if got := out.String(); got != "login with [redacted] ok\nproxy http://u:[redacted]@p:3128 failed\n" {
		t.Fatalf("output = %q", got)
	}
	w.Flush()
	if got := out.String(); !strings.HasSuffix(got, "partial") {
		t.Fatalf("flush lost the last line: %q", got)
	}
}

func TestRedactWriterLongLineKeepsSecretsMasked(t *testing.T) {
	var out bytes.Buffer
	w := newRedactWriter(&out, "s3cr3t-value")
	long := strings.Repeat("x", maxRedactLine-3) + "s3cr3t-value" + strings.Repeat("y", 100)
	for i := 0; i < len(long); i += 7 {
		_, _ = w.Write([]byte(long[i:min(i+7, len(long))]))
	}
	w.Flush()
	if strings.Contains(out.String(), "s3cr3t") || strings.Contains(out.String(), "cr3t-value") {
		t.Fatal("secret split across a forced flush")
	}
	if !strings.Contains(out.String(), "[redacted]") {
		t.Fatal("secret not masked")
	}
}

func TestRedactWriterEncodedAndShortSecrets(t *testing.T) {
	var out bytes.Buffer
	w := newRedactWriter(&out, proxySecrets("http://bob:p%40ss%2Fw0rd@proxy.lan:3128")...)
	w.Write([]byte("a p@ss/w0rd b p%40ss%2Fw0rd c user bob\n"))
	if got := out.String(); got != "a [redacted] b [redacted] c user [redacted]\n" {
		t.Fatalf("output = %q", got)
	}
	if s := proxySecrets("http://proxy.lan:3128"); len(s) != 0 {
		t.Fatalf("secrets without userinfo = %q", s)
	}
}

func TestRedactWriterShortSecretsWholeToken(t *testing.T) {
	var out bytes.Buffer
	w := newRedactWriter(&out, proxySecrets("http://u:ab@proxy.lan:3128")...)
	w.Write([]byte("abc ab cab u:ab@p user=u ub\n"))
	w.Flush()
	if got := out.String(); got != "abc [redacted] cab [redacted]:[redacted]@p user=[redacted] ub\n" {
		t.Fatalf("output = %q", got)
	}
}

func TestRedactWriterEscapedForms(t *testing.T) {
	secret := "pa\"ss\\w\nord"
	var out bytes.Buffer
	w := newRedactWriter(&out, secret)
	quoted := strconv.Quote(secret)
	js, _ := json.Marshal(secret)
	for _, chunk := range []string{"raw " + secret[:4], secret[4:] + " end\n", "q " + quoted + "\n", "j " + string(js) + "\n"} {
		w.Write([]byte(chunk))
	}
	w.Flush()
	got := out.String()
	for _, part := range []string{"pa\"ss", "ss\\w", `pa\"ss`, "ord"} {
		if strings.Contains(got, part) {
			t.Fatalf("output leaks %q: %q", part, got)
		}
	}
	if strings.Count(got, "[redacted]") != 3 || !strings.HasPrefix(got, "raw [redacted] end\n") {
		t.Fatalf("output = %q", got)
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestFRPCOutputRedacted(t *testing.T) {
	env := map[string]string{"HTTPS_PROXY": "http://alice:Pr0xyPass@proxy.lan:3128"}
	out, logs := &syncBuffer{}, &syncBuffer{}
	h := newHarness(t, pairedStore(t, t.TempDir()), "chatty", func(c *Config) {
		c.Getenv = envOf(env)
		c.Output = out
		c.Logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	eventually(t, "frpc ready", func() bool { return h.status().Running })
	eventually(t, "frpc output", func() bool { return strings.Count(out.String(), "\n") >= 2 })
	pass := confValue(t, h.agent.ConfigPath(), "webServer.password")
	b, err := json.Marshal(h.status())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "Pr0xyPass") {
		t.Fatalf("status leaks the proxy password: %s", b)
	}
	h.stop()
	got := out.String()
	for _, secret := range []string{"Pr0xyPass", "alice", "synthetic-token", strings.Trim(pass, `"`)} {
		if secret == "" {
			t.Fatal("secret missing from the config")
		}
		if strings.Contains(got, secret) {
			t.Fatalf("frpc output leaks %q:\n%s", secret, got)
		}
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("agent log leaks %q:\n%s", secret, logs.String())
		}
	}
	if strings.Count(got, "[redacted]") != 5 || !strings.Contains(got, "proxy.lan:3128") || !strings.Contains(got, "trailing [redacted]") {
		t.Fatalf("frpc output = %q", got)
	}
}

func TestEdgeResolveBounded(t *testing.T) {
	hang := func(ctx context.Context, _ string) ([]netip.Addr, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	start := time.Now()
	h := newHarness(t, pairedStore(t, t.TempDir()), "run", func(c *Config) { c.ResolveEdge = hang })
	deadline := time.Now().Add(edgeResolveTimeout + 5*time.Second)
	for !h.status().Running {
		if time.Now().After(deadline) {
			t.Fatal("a hanging resolver blocked the frpc start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if d := time.Since(start); d > edgeResolveTimeout+2*time.Second {
		t.Fatalf("start took %v", d)
	}
	if got := confValue(t, h.agent.ConfigPath(), "serverAddr"); got != `"frp-1.seawise.dev"` {
		t.Fatalf("serverAddr = %s", got)
	}
}

func TestRedactWriterRandomSplits(t *testing.T) {
	secrets := []string{"multi\nline-secret", "tok-123456", "pw"}
	text := strings.Repeat("start tok-123456 pw x multi\nline-secret end\nab pw: "+strings.Repeat("z", 300)+"\n", 60)
	rng := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 200; i++ {
		var out bytes.Buffer
		w := newRedactWriter(&out, secrets...)
		for rest := text; rest != ""; {
			n := min(len(rest), 1+rng.IntN(40))
			w.Write([]byte(rest[:n]))
			rest = rest[n:]
		}
		w.Flush()
		got := out.String()
		if strings.Contains(got, "tok-1") || strings.Contains(got, "line-secret") || strings.Contains(got, " pw ") || strings.Contains(got, "pw:") {
			t.Fatalf("split %d leaks a secret", i)
		}
		if strings.Count(got, "\n") != strings.Count(text, "\n")-60 {
			t.Fatalf("split %d lost or added lines", i)
		}
	}
}
