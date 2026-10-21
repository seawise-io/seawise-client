package netproxy

import (
	"errors"
	"net/http"
	"net/url"
	"testing"
)

func env(m map[string]string) Getenv { return func(k string) string { return m[k] } }

func TestForHostOrder(t *testing.T) {
	cases := []struct {
		env  map[string]string
		vars []string
		want string
	}{
		{map[string]string{"HTTPS_PROXY": "http://a:1", "https_proxy": "http://b:1"}, HTTPS, "http://a:1"},
		{map[string]string{"https_proxy": "http://b:1"}, HTTPS, "http://b:1"},
		{map[string]string{"HTTP_PROXY": "http://c:1"}, HTTPS, ""},
		{map[string]string{"HTTP_PROXY": "http://c:1"}, Tunnel, "http://c:1"},
		{map[string]string{"HTTPS_PROXY": "http://a:1", "HTTP_PROXY": "http://c:1"}, Tunnel, "http://a:1"},
		{map[string]string{"HTTPS_PROXY": "proxy.lan:3128"}, HTTPS, "http://proxy.lan:3128"},
		{map[string]string{}, Tunnel, ""},
	}
	for i, c := range cases {
		u, err := ForHost(env(c.env), "frp-1.seawise.dev", 7000, c.vars...)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		got := ""
		if u != nil {
			got = u.String()
		}
		if got != c.want {
			t.Errorf("case %d: got %q want %q", i, got, c.want)
		}
	}
}

func TestNoProxy(t *testing.T) {
	base := map[string]string{"HTTPS_PROXY": "http://p:3128"}
	cases := []struct {
		noProxy string
		host    string
		port    int
		bypass  bool
	}{
		{"*", "frp-1.seawise.dev", 7000, true},
		{"seawise.dev", "frp-1.seawise.dev", 7000, true},
		{".seawise.dev", "frp-1.seawise.dev", 7000, true},
		{".seawise.dev", "seawise.dev", 7000, true},
		{"seawise.dev", "evilseawise.dev", 7000, false},
		{"seawise.dev:443", "frp-1.seawise.dev", 7000, false},
		{"seawise.dev:7000", "frp-1.seawise.dev", 7000, true},
		{"10.0.0.0/8", "10.1.2.3", 7000, true},
		{"10.0.0.0/8", "11.1.2.3", 7000, false},
		{"203.0.113.9", "203.0.113.9", 7000, true},
		{" example.com , FRP-1.SEAWISE.DEV ", "frp-1.seawise.dev", 7000, true},
		{"", "frp-1.seawise.dev", 7000, false},
		{"[::1]", "::1", 7000, true},
	}
	for _, c := range cases {
		m := map[string]string{"NO_PROXY": c.noProxy}
		for k, v := range base {
			m[k] = v
		}
		u, err := ForHost(env(m), c.host, c.port, HTTPS...)
		if err != nil {
			t.Fatal(err)
		}
		if (u == nil) != c.bypass {
			t.Errorf("NO_PROXY=%q host %s:%d: proxy %v", c.noProxy, c.host, c.port, u)
		}
	}
	m := map[string]string{"HTTPS_PROXY": "http://p:3128", "no_proxy": "seawise.dev"}
	if u, _ := ForHost(env(m), "frp-1.seawise.dev", 7000, HTTPS...); u != nil {
		t.Error("lower-case no_proxy ignored")
	}
}

func TestBadProxyURL(t *testing.T) {
	for _, v := range []string{"http://", "://x", "http://[::1", "ftp//x"} {
		if _, err := ForHost(env(map[string]string{"HTTPS_PROXY": v}), "h", 1, HTTPS...); err == nil {
			t.Errorf("%q accepted", v)
		}
	}
}

func TestCheckScheme(t *testing.T) {
	u, _ := url.Parse("https://p:1")
	if err := CheckScheme(u, "http", "socks5"); !errors.Is(err, ErrScheme) {
		t.Fatalf("err = %v", err)
	}
	u, _ = url.Parse("socks5://p:1")
	if err := CheckScheme(u, "http", "socks5"); err != nil {
		t.Fatal(err)
	}
}

func TestTransportFunc(t *testing.T) {
	m := map[string]string{"HTTPS_PROXY": "http://p:3128", "HTTP_PROXY": "http://q:3128", "NO_PROXY": "internal.example"}
	fn := Func(env(m))
	for raw, want := range map[string]string{
		"https://api.seawise.io/x":   "http://p:3128",
		"http://api.seawise.io/x":    "http://q:3128",
		"https://internal.example/x": "",
		"http://localhost:8080/x":    "",
		"http://127.0.0.1:8080/x":    "",
		"https://[::1]:8443/x":       "",
	} {
		req, _ := http.NewRequest("GET", raw, nil)
		u, err := fn(req)
		if err != nil {
			t.Fatal(err)
		}
		got := ""
		if u != nil {
			got = u.String()
		}
		if got != want {
			t.Errorf("%s: got %q want %q", raw, got, want)
		}
	}
	m["HTTPS_PROXY"] = "http://changed:1"
	req, _ := http.NewRequest("GET", "https://api.seawise.io/", nil)
	if u, _ := fn(req); u == nil || u.Host != "changed:1" {
		t.Fatal("environment read once instead of per request")
	}
}
