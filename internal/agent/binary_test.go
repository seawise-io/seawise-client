package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckBinary(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "frpc")
	if err := os.WriteFile(good, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkBinary(good); err != nil {
		t.Fatalf("good binary refused: %v", err)
	}
	open := filepath.Join(dir, "open")
	if err := os.WriteFile(open, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o757); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"frpc", "./frpc", dir, open, filepath.Join(dir, "missing")} {
		if err := checkBinary(p); err == nil {
			t.Errorf("%q accepted", p)
		}
	}
}

func TestNewRefusesRelativeBinary(t *testing.T) {
	if _, err := New(Config{Store: pairedStore(t, t.TempDir()), FRPCPath: "frpc"}); err == nil {
		t.Fatal("relative frpc path accepted")
	}
}
