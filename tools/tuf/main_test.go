package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOfflineOnlineFlow(t *testing.T) {
	d := t.TempDir()
	repo := filepath.Join(d, "repo")
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	var out strings.Builder
	sh := func(args ...string) {
		t.Helper()
		out.Reset()
		if err := run(args, &out, func(k string) string {
			if k == "TS_KEY" {
				b, _ := os.ReadFile(filepath.Join(d, "timestamp.pem"))
				return string(b)
			}
			return ""
		}, clock); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out.String())
		}
	}
	for _, k := range []string{"root1", "root2", "targets", "snapshot", "timestamp"} {
		sh("keygen", "-out", filepath.Join(d, k+".pem"))
	}
	k := func(n string) string { return filepath.Join(d, n+".pem") }
	sh("init", "-dir", repo, "-root-key", k("root1")+".pub", "-root-key", k("root2")+".pub",
		"-targets-key", k("targets")+".pub", "-snapshot-key", k("snapshot")+".pub", "-timestamp-key", k("timestamp")+".pub",
		"-sign", k("root1"), "-targets-sign", k("targets"))
	ks := filepath.Join(d, "keyset.json")
	if err := os.WriteFile(ks, []byte(`{"keys":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	sh("sign-targets", "-dir", repo, "-key", k("targets"), "-add", "keyset.json="+ks, "-add", "release/stable.json="+ks)
	sh("refresh", "-dir", repo, "-snapshot-key", k("snapshot"), "-timestamp-key", "env:TS_KEY")
	sh("verify", "-dir", repo, "-root", filepath.Join(repo, "metadata", "1.root.json"))
	if !strings.Contains(out.String(), "target release/stable.json") || strings.Contains(out.String(), "TEST") {
		t.Fatalf("verify output:\n%s", out.String())
	}
	// A rotation that replaces the timestamp key, signed by the backup root key.
	sh("keygen", "-out", k("timestamp2"))
	sh("rotate-root", "-dir", repo, "-sign", k("root2"), "-role-key", "timestamp="+k("timestamp2")+".pub")
	sh("refresh", "-dir", repo, "-snapshot-key", k("snapshot"), "-timestamp-key", k("timestamp2"))
	sh("verify", "-dir", repo, "-root", filepath.Join(repo, "metadata", "1.root.json"))
	if !strings.Contains(out.String(), "root      v2") {
		t.Fatalf("verify output:\n%s", out.String())
	}
	// Expired at a later time.
	if err := run([]string{"verify", "-dir", repo, "-root", filepath.Join(repo, "metadata", "1.root.json"), "-at", "2030-02-01T00:00:00Z"}, &out, os.Getenv, clock); err == nil {
		t.Fatal("expired repository verified")
	}
}

func TestInitTestIsMarked(t *testing.T) {
	d := t.TempDir()
	var out strings.Builder
	now := func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) }
	if err := run([]string{"init-test", "-dir", d}, &out, os.Getenv, now); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "TEST ONLY") {
		t.Fatalf("no banner: %s", out.String())
	}
	if err := run([]string{"refresh", "-dir", d, "-snapshot-key", filepath.Join(d, "keys", "snapshot.pem"), "-timestamp-key", filepath.Join(d, "keys", "timestamp.pem")}, &out, os.Getenv, now); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"verify", "-dir", d, "-root", filepath.Join(d, "metadata", "1.root.json")}, &out, os.Getenv, now); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "TEST root") {
		t.Fatalf("no warning: %s", out.String())
	}
}

func TestBadInput(t *testing.T) {
	var out strings.Builder
	now := time.Now
	for _, args := range [][]string{
		nil,
		{"nope"},
		{"keygen"},
		{"init-test"},
		{"sign-targets", "-dir", t.TempDir(), "-key", "env:NOPE"},
		{"rotate-root", "-dir", t.TempDir(), "-threshold", "root"},
		{"verify", "-dir", t.TempDir(), "-root", "/nonexistent"},
		{"pull", "-url", "http://example.invalid", "-dir", t.TempDir()},
	} {
		if err := run(args, &out, os.Getenv, now); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}
