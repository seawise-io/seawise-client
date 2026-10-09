package main

import (
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
