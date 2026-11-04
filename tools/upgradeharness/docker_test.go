//go:build upgradeharness

package upgradeharness

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// engine is a minimal Docker Engine API client over the mounted socket.
type engine struct{ c *http.Client }

func newEngine(socket string) *engine {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	return &engine{c: &http.Client{Transport: tr, Timeout: 5 * time.Minute}}
}

func (e *engine) do(method, path string, body any, out any) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://docker"+path, rd)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := e.c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if out != nil && resp.StatusCode/100 == 2 && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, raw, err
		}
	}
	return resp.StatusCode, raw, nil
}

func (e *engine) ok(want []int, method, path string, body any, out any) error {
	st, raw, err := e.do(method, path, body, out)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	for _, w := range want {
		if st == w {
			return nil
		}
	}
	return fmt.Errorf("%s %s: status %d: %s", method, path, st, strings.TrimSpace(string(raw)))
}

type spec struct {
	Image      string
	Env        []string
	Cmd        []string
	Entrypoint []string
	User       string
	Binds      []string
	Network    string
	CPUs       float64
	MemoryMB   int64
	ReadOnly   bool
}

func (e *engine) create(name string, s spec) error {
	mem := s.MemoryMB << 20
	body := map[string]any{
		"Image": s.Image,
		"Env":   s.Env,
		"User":  s.User,
		"HostConfig": map[string]any{
			"Binds":          s.Binds,
			"NetworkMode":    s.Network,
			"NanoCpus":       int64(s.CPUs * 1e9),
			"Memory":         mem,
			"MemorySwap":     mem,
			"ReadonlyRootfs": s.ReadOnly,
		},
	}
	if s.Cmd != nil {
		body["Cmd"] = s.Cmd
	}
	if s.Entrypoint != nil {
		body["Entrypoint"] = s.Entrypoint
	}
	return e.ok([]int{201}, http.MethodPost, "/containers/create?name="+url.QueryEscape(name), body, nil)
}

func (e *engine) start(name string) error {
	return e.ok([]int{204, 304}, http.MethodPost, "/containers/"+name+"/start", nil, nil)
}

func (e *engine) stop(name string, grace int) error {
	return e.ok([]int{204, 304}, http.MethodPost, fmt.Sprintf("/containers/%s/stop?t=%d", name, grace), nil, nil)
}

func (e *engine) kill(name string) error {
	return e.ok([]int{204}, http.MethodPost, "/containers/"+name+"/kill?signal=KILL", nil, nil)
}

func (e *engine) wait(name string) (int, error) {
	var out struct{ StatusCode int }
	err := e.ok([]int{200}, http.MethodPost, "/containers/"+name+"/wait", nil, &out)
	return out.StatusCode, err
}

func (e *engine) remove(name string) {
	_, _, _ = e.do(http.MethodDelete, "/containers/"+name+"?force=1", nil, nil)
}

func (e *engine) running(name string) bool {
	var out struct{ State struct{ Running bool } }
	if err := e.ok([]int{200}, http.MethodGet, "/containers/"+name+"/json", nil, &out); err != nil {
		return false
	}
	return out.State.Running
}

func (e *engine) volume(name string) error {
	return e.ok([]int{201}, http.MethodPost, "/volumes/create", map[string]string{"Name": name}, nil)
}

func (e *engine) removeVolume(name string) {
	_, _, _ = e.do(http.MethodDelete, "/volumes/"+name+"?force=1", nil, nil)
}

// logs returns stdout and stderr of a container without a TTY.
func (e *engine) logs(name string) string {
	_, raw, err := e.do(http.MethodGet, "/containers/"+name+"/logs?stdout=1&stderr=1", nil, nil)
	if err != nil {
		return err.Error()
	}
	var b strings.Builder
	for len(raw) >= 8 {
		n := int(binary.BigEndian.Uint32(raw[4:8]))
		if 8+n > len(raw) {
			break
		}
		b.Write(raw[8 : 8+n])
		raw = raw[8+n:]
	}
	return b.String()
}

// run creates, starts and waits for a short-lived container and returns its
// output.
func (e *engine) run(name string, s spec) (string, int, error) {
	e.remove(name)
	if err := e.create(name, s); err != nil {
		return "", 0, err
	}
	defer e.remove(name)
	if err := e.start(name); err != nil {
		return "", 0, err
	}
	code, err := e.wait(name)
	return e.logs(name), code, err
}
