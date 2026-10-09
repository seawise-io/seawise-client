package main

import (
	"os"
	"os/exec"
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
	for _, bad := range []string{"github.com/seawise/client/cmd/seawise/", "github.com/seawise/client/internal/tufrepo", "github.com/seawise/client/tools/"} {
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
func TestReleaseBuildsHaveNoTestTag(t *testing.T) {
	for _, f := range []string{"../../Dockerfile.agent", "../../Makefile", "../../.github/workflows/release.yml", "../../.github/workflows/promote-stable.yml"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "seawise_tuftest") {
			t.Errorf("%s uses the seawise_tuftest build tag", f)
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
}
