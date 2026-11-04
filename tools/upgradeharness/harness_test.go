//go:build upgradeharness

package upgradeharness

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// 1.x images, pinned by digest as in the platform compatibility suite.
const (
	imageA = "ghcr.io/seawise-io/seawise-client@sha256:3583a4c6c395389b69fd5c227a40b7b2582524d657fe85d30af9f4926ad32231" // 1.0.0
	imageE = "ghcr.io/seawise-io/seawise-client@sha256:25599fe34dd95a92f169482d300240042eacd12dfa4b485624ba233e7581df33" // 1.0.12
)

const password = "upgrade-harness-pw"

type harness struct {
	t       *testing.T
	e       *engine
	s       *standin
	net     string
	dir     string
	prefix  string
	agent   string
	clients []string
}

func env(t *testing.T, k string) string {
	v := os.Getenv(k)
	if v == "" {
		t.Skipf("%s not set; run tools/upgradeharness/run.sh", k)
	}
	return v
}

func TestUpgrade(t *testing.T) {
	h := &harness{t: t, net: env(t, "HARNESS_NETWORK"), dir: env(t, "HARNESS_DIR"), agent: env(t, "HARNESS_AGENT_IMAGE"),
		prefix: env(t, "HARNESS_NETWORK"), s: newStandin()}
	sock := os.Getenv("HARNESS_DOCKER_SOCK")
	if sock == "" {
		sock = "/var/run/docker.sock"
	}
	h.e = newEngine(sock)
	caPEM, cert, err := tlsFiles()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.dir, "ca.pem"), caPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	stop, err := h.s.serve(cert)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	t.Run("U", h.scenarioU)
	t.Run("A", func(t *testing.T) { h.scenarioA(t, "a", false) })
	t.Run("AK", func(t *testing.T) { h.scenarioA(t, "ak", true) })
}

func (h *harness) name(s string) string { return h.prefix + "-" + s }

func (h *harness) clientSpec(image, vol string) spec {
	return spec{Image: image, Network: h.net, CPUs: 1, MemoryMB: 512,
		Env:   []string{"SEAWISE_API_URL=" + apiOrigin, "SSL_CERT_FILE=/harness/ca.pem", "TZ=UTC"},
		Binds: []string{vol + ":/config", filepath.Join(h.dir, "ca.pem") + ":/harness/ca.pem:ro"}}
}

func (h *harness) startContainer(t *testing.T, name string, s spec) {
	t.Helper()
	h.e.remove(name)
	if err := h.e.create(name, s); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("%s log:\n%s", name, tail(h.e.logs(name), 80))
		}
		h.e.remove(name)
	})
	if err := h.e.start(name); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) stopContainer(t *testing.T, name string, kill bool) {
	t.Helper()
	var err error
	if kill {
		err = h.e.kill(name)
	} else {
		err = h.e.stop(name, 10)
	}
	if err != nil {
		t.Fatal(err)
	}
	code, err := h.e.wait(name)
	if err != nil {
		t.Fatal(err)
	}
	if !kill && code != 0 {
		t.Errorf("%s exited %d on a clean stop", name, code)
	}
	h.saveLog(name)
}

func (h *harness) saveLog(name string) {
	_ = os.WriteFile(filepath.Join(h.dir, name+".log"), []byte(h.e.logs(name)), 0o644)
}

func tail(s string, n int) string {
	l := strings.Split(s, "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, "\n")
}

func waitFor(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", d, what)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// seen reports whether a request matching f was recorded.
func (h *harness) seen(f func(rec) bool) bool { return slices.ContainsFunc(h.s.records(), f) }

func (h *harness) count(f func(rec) bool) int {
	n := 0
	for _, r := range h.s.records() {
		if f(r) {
			n++
		}
	}
	return n
}

// ui talks to a client's local admin page as a browser on the same
// machine would.
type ui struct {
	base   string
	cookie string
	c      *http.Client
}

func newUI(container string) *ui {
	return &ui{base: "http://" + container + ":8082", c: &http.Client{Timeout: 10 * time.Second}}
}

func (u *ui) do(method, path string, body any) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, u.base+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Host = "127.0.0.1:8082"
	req.Header.Set("Origin", "http://127.0.0.1:8082")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if u.cookie != "" {
		req.Header.Set("Cookie", u.cookie)
	}
	resp, err := u.c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var cs []string
	for _, c := range resp.Cookies() {
		cs = append(cs, c.Name+"="+c.Value)
	}
	if len(cs) > 0 {
		u.cookie = strings.Join(cs, "; ")
	}
	return resp.StatusCode, raw, nil
}

// v1Install runs a 1.x image on a new volume: password, pairing, one app,
// until a heartbeat and a list holding the app; then stops it.
func (h *harness) v1Install(t *testing.T, image, label string, kill bool) (vol string) {
	t.Helper()
	vol = h.name(label + "-config")
	h.e.removeVolume(vol)
	if err := h.e.volume(vol); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.e.removeVolume(vol) })
	name := h.name(label + "-v1")
	h.s.setPhase(label + ":v1")
	h.startContainer(t, name, h.clientSpec(image, vol))
	u := newUI(name)
	waitFor(t, time.Minute, "1.x password setup", func() bool {
		st, _, err := u.do(http.MethodPost, "/api/auth/set-password", map[string]string{"password": password})
		return err == nil && st == 200
	})
	if st, b, err := u.do(http.MethodPost, "/api/pair/start", map[string]string{"server_name": "harness-" + label}); err != nil || st != 200 {
		t.Fatalf("pair start: %d %s %v", st, b, err)
	}
	isV1 := func(method, path string, status int) func(rec) bool {
		return func(r rec) bool { return !r.Agent && r.Method == method && r.Path == path && r.Status == status }
	}
	waitFor(t, 2*time.Minute, "1.x pairing", func() bool { return h.seen(isV1("POST", "/api/servers/pair/complete", 200)) })
	sp := "/api/servers/" + h.s.serverID
	waitFor(t, 2*time.Minute, "1.x heartbeat", func() bool { return h.seen(isV1("POST", sp+"/heartbeat", 200)) })
	waitFor(t, time.Minute, "1.x app added", func() bool {
		st, _, err := u.do(http.MethodPost, "/api/services/add", map[string]any{"name": "mock", "host": "mock", "port": 80})
		return err == nil && st == 200
	})
	var registered time.Time
	waitFor(t, 30*time.Second, "1.x app registered", func() bool {
		for _, r := range h.s.records() {
			if !r.Agent && strings.HasPrefix(r.Path, "/api/services/register") && r.Status == 201 {
				registered = r.At
				return true
			}
		}
		return false
	})
	waitFor(t, 3*time.Minute, "1.x list holding the app", func() bool {
		return h.seen(func(r rec) bool {
			return !r.Agent && r.Method == "GET" && r.Path == sp+"/services" && r.Status == 200 && r.At.After(registered)
		})
	})
	h.s.setPhase(label + ":v1-stop")
	h.stopContainer(t, name, kill)
	return vol
}

// snap is a read-only view of a volume.
type snap struct {
	Files    []string // every file outside v2/: mode size mtime sha256 path
	V2       []string // v2/ entries: mode uid type path
	State    map[string]any
	TokenLen int
	raw      string
}

func (s snap) has(path string) bool {
	return slices.ContainsFunc(s.Files, func(l string) bool { return strings.HasSuffix(l, " "+path) })
}

const probeScript = `set -eu
cd /c
find . -path ./v2 -prune -o -type f -print | sort | while read -r f; do
  echo "F $(stat -c '%a %s %Y' "$f") $(sha256sum "$f" | cut -d' ' -f1) ${f#./}"
done
if [ -d v2 ]; then
  echo "E $(stat -c '%a %u %F' v2 | tr ' ' _) v2"
  find v2 -mindepth 1 | sort | while read -r f; do echo "E $(stat -c '%a %u %F' "$f" | tr ' ' _) $f"; done
  [ -f v2/state.json ] && echo "STATE $(base64 -w0 v2/state.json)"
  if [ -f v2/secrets.json ]; then
    echo "TOKENLEN $(sed -n 's/.*"frp_token": *"\([^"]*\)".*/\1/p' v2/secrets.json | tr -d '\n' | wc -c)"
  fi
fi
`

func (h *harness) probe(t *testing.T, vol string) snap {
	t.Helper()
	out, code, err := h.e.run(h.name("probe"), spec{Image: imageE, Entrypoint: []string{"sh", "-c", probeScript}, User: "0:0",
		Binds: []string{vol + ":/c:ro"}, Network: "none", CPUs: 1, MemoryMB: 128})
	if err != nil || code != 0 {
		t.Fatalf("probe: %v exit %d\n%s", err, code, out)
	}
	s := snap{raw: out}
	for _, l := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(l, "F "):
			s.Files = append(s.Files, l[2:])
		case strings.HasPrefix(l, "E "):
			s.V2 = append(s.V2, l[2:])
		case strings.HasPrefix(l, "STATE "):
			b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(l[6:]))
			if err != nil || json.Unmarshal(b, &s.State) != nil {
				t.Fatalf("probe: state.json unreadable")
			}
		case strings.HasPrefix(l, "TOKENLEN "):
			_, _ = fmt.Sscanf(l, "TOKENLEN %d", &s.TokenLen)
		}
	}
	return s
}

func sameFiles(t *testing.T, step string, want, got snap) {
	t.Helper()
	if !slices.Equal(want.Files, got.Files) {
		t.Errorf("%s: 1.x files changed\nbefore:\n%s\nafter:\n%s", step, strings.Join(want.Files, "\n"), strings.Join(got.Files, "\n"))
	}
}

// field reads a nested member of decoded JSON.
func field(v any, path ...string) any {
	for _, p := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[p]
	}
	return v
}

func str(v any) string { s, _ := v.(string); return s }

// ownerOnly checks v2/ is 0700 and its files 0600, owned by the agent user.
func ownerOnly(t *testing.T, s snap) {
	t.Helper()
	if len(s.V2) == 0 {
		t.Fatal("no v2/ directory")
	}
	for _, l := range s.V2 {
		f := strings.Fields(l)
		if len(f) != 2 {
			continue
		}
		attrs := strings.Split(f[0], "_")
		mode, uid, kind := attrs[0], attrs[1], strings.Join(attrs[2:], " ")
		if uid != "1000" {
			t.Errorf("%s owned by %s", f[1], uid)
		}
		switch {
		case kind == "directory" && mode != "700":
			t.Errorf("%s mode %s, want 700", f[1], mode)
		case kind == "regular file" && mode != "600":
			t.Errorf("%s mode %s, want 600", f[1], mode)
		}
	}
}

// agentLogin logs in to the agent's admin page with the 1.x password and
// returns its status document.
func agentStatus(t *testing.T, container string) any {
	t.Helper()
	u := newUI(container)
	var st int
	var b []byte
	waitFor(t, time.Minute, "agent admin page", func() bool {
		var err error
		st, b, err = u.do(http.MethodPost, "/api/auth/login", map[string]string{"password": password})
		return err == nil && st != 0
	})
	if st != 200 {
		t.Fatalf("login with the 1.x password: %d %s", st, b)
	}
	st, b, err := u.do(http.MethodGet, "/api/status", nil)
	if err != nil || st != 200 {
		t.Fatalf("status: %d %v", st, err)
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if inner := field(v, "status"); inner != nil {
		v = inner
	}
	return v
}

func (h *harness) noFailures(t *testing.T) {
	t.Helper()
	var b strings.Builder
	for _, r := range h.s.records() {
		fmt.Fprintf(&b, "%s %-16s agent=%-5v %s %s %d key=%.8s\n", r.At.Format("15:04:05.000"), r.Phase, r.Agent, r.Method, r.Path, r.Status, r.KeyID)
	}
	_ = os.WriteFile(filepath.Join(h.dir, strings.ReplaceAll(t.Name(), "/", "_")+".records"), []byte(b.String()), 0o644)
	for _, f := range h.s.failures() {
		t.Error("stand-in:", f)
	}
}

func isAgentV1(r rec) bool { return r.Agent && r.v1() }

func enrolPhase(s snap) string { return str(field(s.State, "enrolment", "phase")) }
func enrolKey(s snap) string   { return str(field(s.State, "enrolment", "key_id")) }

func targets(s snap) []map[string]any {
	var out []map[string]any
	ts, _ := field(s.State, "targets").([]any)
	for _, x := range ts {
		if m, ok := x.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}
