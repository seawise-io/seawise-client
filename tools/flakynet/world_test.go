//go:build flakynet

package flakynet

import (
	"bufio"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seawise/client/internal/session"
	"github.com/seawise/client/internal/store"
	"github.com/seawise/client/internal/testedge"
)

const (
	serverID   = "3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b"
	tunnelName = "tunnel-us-east.seawise.dev"
	apiHost    = "api.flakynet.test"
	apiPort    = "8443"
	appCount   = 10
)

// TestWorld is the world the agent sees: the edge on :443, the device API
// and the update repository on :8443. It prepares FLAKYNET_DIR (agent
// data, test roots, CA), logs every edge event to events.jsonl and follows
// the commands appended to control: "block_raw on|off", "offset <dur>",
// "floor" (write the agent's stored time floor), "drain", "stop". On stop it writes every session's bursts to
// bursts.jsonl.
func TestWorld(t *testing.T) {
	dir := os.Getenv("FLAKYNET_DIR")
	if os.Getenv("FLAKYNET_ROLE") != "world" || dir == "" {
		t.Skip("run by run.sh")
	}
	ca, err := testedge.NewCA()
	if err != nil {
		t.Fatal(err)
	}
	keys := testedge.NewKeys("flakynet", "edge-us-east-0")
	apps := testedge.TestApps(appCount, "127.0.0.1", 9)

	evf, err := os.Create(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer evf.Close()
	var evmu sync.Mutex
	enc := json.NewEncoder(evf)
	var device atomic.Pointer[ed25519.PublicKey]
	edge, err := testedge.New(testedge.Config{Keys: keys, CA: ca, ServerID: serverID, TunnelName: tunnelName, APIHost: apiHost, Apps: apps,
		DeviceKey: func() ed25519.PublicKey {
			if p := device.Load(); p != nil {
				return *p
			}
			return nil
		},
		Events: func(ev testedge.Event) {
			evmu.Lock()
			_ = enc.Encode(ev)
			evmu.Unlock()
		}})
	if err != nil {
		t.Fatal(err)
	}

	repo := filepath.Join(t.TempDir(), "repo")
	data, tuf := filepath.Join(dir, "data"), filepath.Join(dir, "tuf")
	for _, d := range []string{repo, data, tuf} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	apiURL := "https://" + apiHost + ":" + apiPort
	if err := testedge.UpdateRepo(repo, tuf, apiURL+"/tuf", keys, ca, time.Now()); err != nil {
		t.Fatal(err)
	}
	pub, err := testedge.PairedDataDir(data, serverID, apiURL, apps)
	if err != nil {
		t.Fatal(err)
	}
	device.Store(&pub)
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), ca.PEM(), 0o644); err != nil {
		t.Fatal(err)
	}

	// No TCP keepalive on the agent listener: liveness is the stream 0 ping.
	lc := net.ListenConfig{KeepAlive: -1}
	tunnelLn, err := lc.Listen(t.Context(), "tcp", ":443")
	if err != nil {
		t.Fatal(err)
	}
	defer tunnelLn.Close()
	go func() { _ = edge.ServeTunnel(tunnelLn) }()
	apiLn, err := net.Listen("tcp", ":"+apiPort)
	if err != nil {
		t.Fatal(err)
	}
	api := &http.Server{Handler: edge.APIHandler(http.FileServer(http.Dir(repo))), TLSConfig: edge.APITLS(), ReadHeaderTimeout: 10 * time.Second}
	api.TLSConfig.NextProtos = []string{"h2", "http/1.1"}
	go func() { _ = api.ServeTLS(apiLn, "", "") }()
	defer api.Close()

	if err := os.WriteFile(filepath.Join(dir, "ready"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Log("world ready")
	follow(t, filepath.Join(dir, "control"), filepath.Join(data, store.SubDir), edge)

	bf, err := os.Create(filepath.Join(dir, "bursts.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer bf.Close()
	benc := json.NewEncoder(bf)
	for _, s := range edge.All() {
		for _, b := range s.Bursts(time.Time{}, time.Now().Add(time.Second), 300*time.Millisecond) {
			_ = benc.Encode(burstLine{Conn: s.ID, Carriage: s.Carriage, Start: b.Start, End: b.End, Bytes: b.Bytes, Kind: b.Kind()})
		}
	}
}

type burstLine struct {
	Conn     int64     `json:"conn"`
	Carriage string    `json:"carriage"`
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	Bytes    int64     `json:"bytes"`
	Kind     string    `json:"kind"`
}

// follow runs the commands appended to path until "stop".
func follow(t *testing.T, path, floorDir string, edge *testedge.Edge) {
	var off int64
	for {
		time.Sleep(200 * time.Millisecond)
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		_, _ = f.Seek(off, 0)
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			off += int64(len(line)) + 1
			cmd, arg, _ := strings.Cut(strings.TrimSpace(line), " ")
			t.Logf("control: %s", line)
			switch cmd {
			case "block_raw":
				edge.BlockRawTLS(arg == "on")
			case "offset":
				d, err := time.ParseDuration(arg)
				if err != nil {
					t.Errorf("offset %q: %v", arg, err)
					continue
				}
				edge.SetOffset(d)
			case "floor":
				// What an agent that ran before with the right time has
				// stored, in the edge's time.
				b := fmt.Appendf(nil, `{"schema":1,"floor":%d}`, edge.Now().Add(-time.Minute).Unix())
				if err := os.WriteFile(filepath.Join(floorDir, session.TimeFloorFile), b, 0o600); err != nil {
					t.Errorf("floor: %v", err)
				}
			case "drain":
				edge.Drain()
			case "stop":
				f.Close()
				return
			}
		}
		f.Close()
	}
}
