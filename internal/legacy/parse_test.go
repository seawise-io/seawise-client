package legacy

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestParseFRPCEscapes(t *testing.T) {
	src := "serverAddr = \"a\\\\b\"\nserverPort = 443\nmetadatas.server_id = \"sid\"\n" +
		"[[proxies]]\nname = \"sid-x\\\"y\\tz\\n\"\ntype = \"http\"\nlocalIP = \"h\"\nlocalPort = 1\nsubdomain = \"s\"\n"
	cfg, err := parseFRPC([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerAddr != `a\b` || cfg.ServerPort != 443 || cfg.ServerID != "sid" {
		t.Fatalf("cfg = %+v", cfg)
	}
	if len(cfg.Proxies) != 1 || cfg.Proxies[0].Name != "x\"y\tz\n" {
		t.Fatalf("proxies = %+v", cfg.Proxies)
	}
}

func TestParseFRPCRejectsMalformed(t *testing.T) {
	cases := []string{
		"serverAddr = \"unterminated\n",
		"serverPort = notanumber\n",
		"[[proxies]]\nlocalPort = 99999999999999999999\n",
		"[[proxies]]\nname = \"bad \\q escape\"\n",
		"[[proxies]]\n[proxies.plugin]\nlocalAddr = \"nocolon\"\n",
		"[[proxies]]\nlocalPort = 70000\n",
	}
	for i, c := range cases {
		if _, err := parseFRPC([]byte(c)); err == nil {
			t.Errorf("case %d: expected error for %q", i, c)
		}
	}
}

func TestParseFRPCNeverKeepsToken(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "v1", "E", "frpc.toml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parseFRPC(b)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprintf("%+v", cfg), "synthetic-frp-token") {
		t.Fatal("token leaked into parsed frpc config")
	}
}

func TestParseFRPCTooManyProxies(t *testing.T) {
	var b strings.Builder
	for i := 0; i <= MaxServices; i++ {
		b.WriteString("[[proxies]]\n")
	}
	if _, err := parseFRPC([]byte(b.String())); err == nil {
		t.Fatal("expected error")
	}
}

// v1 writes machine.json with json.MarshalIndent of this shape.
type v1Service struct {
	LocalID         string `json:"local_id"`
	Name            string `json:"name"`
	Host            string `json:"host"`
	Port            int    `json:"port"`
	IconURL         string `json:"icon_url,omitempty"`
	ServerServiceID string `json:"server_service_id,omitempty"`
	Subdomain       string `json:"subdomain,omitempty"`
	Disabled        bool   `json:"disabled,omitempty"`
}

type v1Machine struct {
	MachineID   string      `json:"machine_id"`
	MachineName string      `json:"machine_name,omitempty"`
	Services    []v1Service `json:"services"`
}

func randString(r *rand.Rand, n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-._ \"\\é\t"
	rs := []rune(alphabet)
	out := make([]rune, r.Intn(n)+1)
	for i := range out {
		out[i] = rs[r.Intn(len(rs))]
	}
	return string(out)
}

func TestPropertyMachineRoundTrip(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for iter := 0; iter < 300; iter++ {
		m := v1Machine{MachineID: randString(r, 32), MachineName: randString(r, 20)}
		n := r.Intn(20)
		for i := 0; i < n; i++ {
			m.Services = append(m.Services, v1Service{
				LocalID:         strconv.Itoa(i) + randString(r, 10),
				Name:            randString(r, 30),
				Host:            randString(r, 60),
				Port:            1 + r.Intn(65535),
				IconURL:         randString(r, 40),
				ServerServiceID: randString(r, 36),
				Subdomain:       randString(r, 30),
				Disabled:        r.Intn(2) == 0,
			})
		}
		data, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		var warnings []string
		got, err := parseMachine(data, &warnings)
		if err != nil {
			t.Fatalf("iter %d: %v", iter, err)
		}
		if len(warnings) != 0 || got.MachineID != m.MachineID || got.MachineName != m.MachineName || len(got.Services) != len(m.Services) {
			t.Fatalf("iter %d: got %+v warnings %v", iter, got, warnings)
		}
		for i, s := range m.Services {
			if Service(s) != got.Services[i] {
				t.Fatalf("iter %d svc %d: %+v != %+v", iter, i, got.Services[i], s)
			}
		}
	}
}

func TestPropertyFRPCRoundTrip(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "\t", `\t`)
	for iter := 0; iter < 300; iter++ {
		sid := randString(r, 36)
		var b strings.Builder
		fmt.Fprintf(&b, "serverAddr = \"%s\"\nserverPort = %d\nmetadatas.server_id = \"%s\"\n", esc.Replace("frp.example"), 7000, esc.Replace(sid))
		n := r.Intn(10)
		var want []Proxy
		for i := 0; i < n; i++ {
			p := Proxy{Name: randString(r, 20) + "\n", LocalIP: randString(r, 30), LocalPort: 1 + r.Intn(65535), Subdomain: randString(r, 20), E2E: r.Intn(2) == 0}
			fmt.Fprintf(&b, "\n[[proxies]]\nname = \"%s-%s\"\n", esc.Replace(sid), esc.Replace(p.Name))
			if p.E2E {
				p.Type = "https"
				fmt.Fprintf(&b, "type = \"https\"\n[proxies.plugin]\ntype = \"https2http\"\nlocalAddr = \"%s:%d\"\ncrtPath = \"/c\"\nkeyPath = \"/k\"\n", esc.Replace(p.LocalIP), p.LocalPort)
			} else {
				p.Type = "http"
				fmt.Fprintf(&b, "type = \"http\"\nlocalIP = \"%s\"\nlocalPort = %d\n", esc.Replace(p.LocalIP), p.LocalPort)
			}
			fmt.Fprintf(&b, "subdomain = \"%s\"\n", esc.Replace(p.Subdomain))
			want = append(want, p)
		}
		cfg, err := parseFRPC([]byte(b.String()))
		if err != nil {
			t.Fatalf("iter %d: %v\n%s", iter, err, b.String())
		}
		if cfg.ServerID != sid || len(cfg.Proxies) != len(want) {
			t.Fatalf("iter %d: %+v", iter, cfg)
		}
		for i := range want {
			if cfg.Proxies[i] != want[i] {
				t.Fatalf("iter %d proxy %d: %+v != %+v", iter, i, cfg.Proxies[i], want[i])
			}
		}
	}
}

func FuzzParseAccount(f *testing.F) {
	for _, g := range []string{"B", "E"} {
		b, _ := os.ReadFile(filepath.Join("testdata", "v1", g, "account.json"))
		f.Add(b)
	}
	b, _ := os.ReadFile(filepath.Join("testdata", "v1", "A", "config.json"))
	f.Add(b)
	f.Add([]byte(`null`))
	f.Add([]byte(`{"server_id":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		a, err := parseAccount(data)
		if err == nil && (a.ServerID == "" || a.FRPToken == "") {
			t.Fatalf("accepted account without id or token: %+v", a)
		}
	})
}

func FuzzParseMachine(f *testing.F) {
	for _, g := range []string{"B", "E"} {
		b, _ := os.ReadFile(filepath.Join("testdata", "v1", g, "machine.json"))
		f.Add(b)
	}
	f.Add([]byte(`{"services":null}`))
	f.Add([]byte(`{"services":[{"port":-1}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var warnings []string
		m, err := parseMachine(data, &warnings)
		if err != nil {
			return
		}
		if len(m.Services) > MaxServices {
			t.Fatal("service cap exceeded")
		}
		seen := map[string]bool{}
		for _, s := range m.Services {
			if s.Port < 1 || s.Port > 65535 || s.Host == "" || s.LocalID == "" || seen[s.LocalID] {
				t.Fatalf("invalid service accepted: %+v", s)
			}
			seen[s.LocalID] = true
		}
	})
}

func FuzzParseFRPC(f *testing.F) {
	for _, g := range groups {
		b, _ := os.ReadFile(filepath.Join("testdata", "v1", g, "frpc.toml"))
		f.Add(b)
	}
	f.Add([]byte("[[proxies]]\nlocalPort = 1\n[proxies.plugin]\nlocalAddr = \"[::1]:80\"\n"))
	f.Add([]byte("x = \"\\u00e9\\U0001F600\"\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		cfg, err := parseFRPC(data)
		if err != nil {
			return
		}
		if len(cfg.Proxies) > MaxServices {
			t.Fatal("proxy cap exceeded")
		}
		for _, p := range cfg.Proxies {
			if p.LocalPort < 0 || p.LocalPort > 65535 {
				t.Fatalf("port out of range: %+v", p)
			}
		}
	})
}

// The package must stay incapable of modifying v1 files.
func TestPackageHasNoWriteCalls(t *testing.T) {
	forbidden := map[string]bool{
		"os.WriteFile": true, "os.Create": true, "os.CreateTemp": true, "os.Remove": true,
		"os.RemoveAll": true, "os.Rename": true, "os.Mkdir": true, "os.MkdirAll": true,
		"os.MkdirTemp": true, "os.Chmod": true, "os.Chown": true, "os.Lchown": true,
		"os.Chtimes": true, "os.Truncate": true, "os.Symlink": true, "os.Link": true,
		"os.O_WRONLY": true, "os.O_RDWR": true, "os.O_CREATE": true, "os.O_TRUNC": true,
		"os.O_APPEND": true, "syscall.O_WRONLY": true, "syscall.O_RDWR": true,
		"syscall.O_CREAT": true, "syscall.O_TRUNC": true, "syscall.O_APPEND": true,
		"syscall.Unlink": true, "syscall.Rename": true, "syscall.Open": true,
	}
	forbiddenImports := []string{"github.com/seawise/client/internal/config", "github.com/seawise/client/internal/auth", "github.com/seawise/client/internal/frp", "golang.org/x/sys"}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		for _, imp := range file.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			for _, bad := range forbiddenImports {
				if strings.HasPrefix(path, bad) {
					t.Errorf("%s imports %s", name, path)
				}
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && forbidden[id.Name+"."+sel.Sel.Name] {
				t.Errorf("%s: %s uses %s.%s", name, fset.Position(sel.Pos()), id.Name, sel.Sel.Name)
			}
			if sel.Sel.Name == "Write" || sel.Sel.Name == "WriteString" || sel.Sel.Name == "Truncate" || sel.Sel.Name == "Chmod" {
				t.Errorf("%s: %s calls .%s", name, fset.Position(sel.Pos()), sel.Sel.Name)
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("no source files checked")
	}
}
