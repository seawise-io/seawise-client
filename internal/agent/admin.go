package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"time"
)

type ProxyStatus struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Status     string `json:"status"`
	Err        string `json:"err"`
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
}

// adminClient talks to frpc's admin API, which must listen on loopback.
type adminClient struct {
	base       string
	user, pass string
	http       *http.Client
}

func newAdminClient(host string, port int, user, pass string, timeout time.Duration) (*adminClient, error) {
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("admin address %q is not a loopback IP", host)
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("admin port %d out of range", port)
	}
	return &adminClient{
		base: "http://" + net.JoinHostPort(host, strconv.Itoa(port)),
		user: user,
		pass: pass,
		http: &http.Client{
			Timeout:       timeout,
			Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (c *adminClient) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.user, c.pass)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("frpc admin %s: status %d", path, resp.StatusCode)
	}
	return body, nil
}

func (c *adminClient) status(ctx context.Context) ([]ProxyStatus, error) {
	body, err := c.get(ctx, "/api/status")
	if err != nil {
		return nil, err
	}
	var byType map[string][]ProxyStatus
	if err := json.Unmarshal(body, &byType); err != nil {
		return nil, fmt.Errorf("frpc admin status: %w", err)
	}
	if byType == nil {
		return nil, errors.New("frpc admin status: empty body")
	}
	out := []ProxyStatus{}
	for _, list := range byType {
		out = append(out, list...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (c *adminClient) reload(ctx context.Context) error {
	_, err := c.get(ctx, "/api/reload")
	return err
}
