package agent

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
)

const (
	envFake    = "SEAWISE_FAKE_FRPC"
	envFakeLog = "SEAWISE_FAKE_FRPC_LOG"
	envFakeCtl = "SEAWISE_FAKE_FRPC_MODE"
)

func TestMain(m *testing.M) {
	if os.Getenv(envFake) == "1" {
		fakeFRPC()
		return
	}
	os.Exit(m.Run())
}

func fakeLog(event string) {
	f, err := os.OpenFile(os.Getenv(envFakeLog), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return
	}
	fmt.Fprintf(f, "%s %d\n", event, os.Getpid())
	f.Close()
}

type fakeConf struct {
	port       int
	user, pass string
	proxies    []string
}

func readFakeConf(path string) fakeConf {
	var c fakeConf
	f, err := os.Open(path)
	if err != nil {
		return c
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), " = ")
		if !ok {
			continue
		}
		uq, _ := strconv.Unquote(v)
		switch k {
		case "webServer.port":
			c.port, _ = strconv.Atoi(v)
		case "webServer.user":
			c.user = uq
		case "webServer.password":
			c.pass = uq
		case "name":
			c.proxies = append(c.proxies, uq)
		}
	}
	return c
}

// fakeFRPC behaves enough like frpc for the agent: it reads -c, serves the
// admin API on the configured loopback port and exits on SIGTERM.
func fakeFRPC() {
	if len(os.Args) != 3 || os.Args[1] != "-c" {
		fmt.Fprintln(os.Stderr, "usage: frpc -c <file>")
		os.Exit(2)
	}
	path := os.Args[2]
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	// The kernel drops the lock when the process dies, however it dies, so
	// a second live instance shows up as "overlap".
	lock, err := os.OpenFile(os.Getenv(envFakeLog)+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err == nil && syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		fakeLog("overlap")
	}
	fakeLog("start")
	mode, _ := os.ReadFile(os.Getenv(envFakeCtl))
	if strings.TrimSpace(string(mode)) == "crash" {
		fakeLog("exit")
		os.Exit(1)
	}
	conf := readFakeConf(path)
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(conf.port)))
	if err != nil {
		fakeLog("exit")
		os.Exit(3)
	}
	var mu sync.Mutex
	current := conf
	mux := http.NewServeMux()
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			u, p, ok := r.BasicAuth()
			if !ok || u != conf.user || p != conf.pass {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("/api/status", auth(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var list []ProxyStatus
		for _, n := range current.proxies {
			list = append(list, ProxyStatus{Name: n, Type: "http", Status: "running"})
		}
		json.NewEncoder(w).Encode(map[string][]ProxyStatus{"http": list})
	}))
	mux.HandleFunc("/api/reload", auth(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		current = readFakeConf(path)
		mu.Unlock()
		fakeLog("reload")
	}))
	go http.Serve(ln, mux)
	<-sig
	fakeLog("exit")
	os.Exit(0)
}
