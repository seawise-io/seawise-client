package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The agent checks for updates only through signed metadata; it must not
// link the current client's server package or the TUF repository tool.
func TestAgentDependencies(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("Go toolchain needed to list the agent dependencies: %v", err)
	}
	out, err := exec.Command(goBin, "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	deps := string(out)
	for _, bad := range []string{"github.com/seawise/client/cmd/seawise/", "github.com/seawise/client/internal/tufrepo", "github.com/seawise/client/tools/", "github.com/seawise/client/internal/api\n"} {
		if strings.Contains(deps, bad) {
			t.Errorf("seawise-agent depends on %s", bad)
		}
	}
	if !strings.Contains(deps, "github.com/seawise/client/internal/updatecheck") {
		t.Error("seawise-agent does not use the signed update check")
	}
}

// The build tag that points update checks at a test repository must never
// reach a release build.
// Release builds take no build tags at all: not seawise_tuftest (test roots
// from the environment) and not dev (local pool and FRP domains).
var buildTagFlag = regexp.MustCompile(`(^|[\s"'=])-tags([\s=]|$)|(^|[^A-Za-z0-9_])tags=`)

func TestReleaseBuildsHaveNoTestTag(t *testing.T) {
	for _, f := range []string{"../../Dockerfile.agent", "../../Dockerfile", "../../Makefile", "../../.github/workflows/release.yml", "../../.github/workflows/promote-stable.yml"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "seawise_tuftest") {
			t.Errorf("%s uses the seawise_tuftest build tag", f)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if buildTagFlag.MatchString(line) {
				t.Errorf("%s:%d sets build tags: %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
	for _, bad := range []string{"-tags dev", "GOFLAGS=-tags=dev", `go build -tags="x"`, "tags=dev"} {
		if !buildTagFlag.MatchString(bad) {
			t.Errorf("tag check misses %q", bad)
		}
	}
	for _, ok := range []string{"git fetch --no-tags origin main", "TAGS: x", "for t in $TAGS; do"} {
		if buildTagFlag.MatchString(ok) {
			t.Errorf("tag check flags %q", ok)
		}
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("Go toolchain needed to list the agent files: %v", err)
	}
	out, err := exec.Command(goBin, "list", "-f", "{{.GoFiles}}", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "tuftest.go") {
		t.Error("the test hook is part of the default build")
	}
	out, err = exec.Command(goBin, "list", "-f", "{{.GoFiles}}", "../../internal/transport").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "pooldomain_dev.go") || !strings.Contains(string(out), "pooldomain_prod.go") {
		t.Errorf("the default build does not take the release pool domain: %s", out)
	}
}

func TestAppSyncNeverCommitsRotations(t *testing.T) {
	b, err := os.ReadFile("appsync.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"CommitRotation", "RecoverRevoked"} {
		if strings.Contains(string(b), bad) {
			t.Fatalf("app sync wiring calls %s; only the session manager's signed proof may commit", bad)
		}
	}
}

// A fresh pairing goes only through the device-key pairing; no other
// package the agent links calls the pairing paths.
func TestPairingOnlyWithTheDeviceKey(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("Go toolchain needed to list the agent dependencies: %v", err)
	}
	out, err := exec.Command(goBin, "list", "-deps", "-f", `{{if not .Standard}}{{.ImportPath}}|{{.Dir}}|{{join .GoFiles ","}}{{end}}`, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	var found []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.SplitN(line, "|", 3)
		if len(f) != 3 || !strings.HasPrefix(f[0], "github.com/seawise/client/") || f[2] == "" {
			continue
		}
		for _, name := range strings.Split(f[2], ",") {
			b, err := os.ReadFile(filepath.Join(f[1], name))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(b), "/servers/pair/") {
				found = append(found, f[0]+"/"+name)
			}
		}
	}
	if len(found) != 1 || found[0] != "github.com/seawise/client/internal/pair/wire.go" {
		t.Fatalf("pairing paths in %v; only internal/pair may call them", found)
	}
	b, err := os.ReadFile("../../internal/pair/pair.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "X-FRP-Token") || strings.Contains(string(b), "frp_token") {
		t.Fatal("device-key pairing handles a 1.x token")
	}
}

// Every device call the agent links is proved by one signer, so one nonce
// cache serves them all; app sync rides the tunnel session when one is up.
func TestDeviceCallsShareOneSigner(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("Go toolchain needed to list the agent dependencies: %v", err)
	}
	out, err := exec.Command(goBin, "list", "-deps", "-f", `{{if not .Standard}}{{.ImportPath}}|{{.Dir}}|{{join .GoFiles ","}}{{end}}`, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	var found []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.SplitN(line, "|", 3)
		if len(f) != 3 || !strings.HasPrefix(f[0], "github.com/seawise/client/") || f[2] == "" {
			continue
		}
		for _, name := range strings.Split(f[2], ",") {
			b, err := os.ReadFile(filepath.Join(f[1], name))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(b), "protocol.NewDPoP(") {
				found = append(found, f[0]+"/"+name)
			}
		}
	}
	if len(found) != 1 || found[0] != "github.com/seawise/client/internal/devicecall/caller.go" {
		t.Fatalf("DPoP proofs built in %v; only internal/devicecall may build them", found)
	}
	for file, want := range map[string]string{"tunnel.go": "Caller: ts.caller", "appsync.go": "Stream0: a,"} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), want) {
			t.Errorf("%s does not wire %q", file, want)
		}
	}
}
