package main

import (
	"os"

	"github.com/seawise/client/internal/tufrepo"
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
	allow := filepath.Join(d, "allowed-keys")
	var ids []string
	for _, n := range []string{"root1", "root2", "root3", "targets", "snapshot", "timestamp"} {
		if n == "root3" {
			sh("keygen", "-out", k(n))
		}
		pk, err := tufrepo.LoadPublicKey(k(n) + ".pub")
		if err != nil {
			t.Fatal(err)
		}
		id, _ := tufrepo.KeyID(pk)
		ids = append(ids, id)
	}
	if err := os.WriteFile(allow, []byte("# allowed\n"+strings.Join(ids, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	initArgs := []string{"init", "-dir", repo, "-root-key", k("root1") + ".pub", "-root-key", k("root2") + ".pub", "-root-key", k("root3") + ".pub",
		"-targets-key", k("targets") + ".pub", "-snapshot-key", k("snapshot") + ".pub", "-timestamp-key", k("timestamp") + ".pub",
		"-sign", k("root1"), "-sign", k("root2"), "-targets-sign", k("targets"), "-allow-keys", allow}
	// Without -production, init refuses.
	if err := run(initArgs, &out, os.Getenv, clock); err == nil || !strings.Contains(err.Error(), "-production") {
		t.Fatalf("init without -production: %v", err)
	}
	sh(append(initArgs, "-production")...)
	rootFile := filepath.Join(repo, "metadata", "1.root.json")
	ks := filepath.Join(d, "keyset.json")
	if err := os.WriteFile(ks, []byte(`{"keys":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	sh("sign-targets", "-dir", repo, "-key", k("targets"), "-add", "keyset.json="+ks, "-add", "release/stable.json="+ks)
	sh("refresh", "-dir", repo, "-root", rootFile, "-snapshot-key", k("snapshot"), "-timestamp-key", "env:TS_KEY")
	sh("verify", "-dir", repo, "-root", rootFile)
	if !strings.Contains(out.String(), "target release/stable.json") || strings.Contains(out.String(), "TEST") {
		t.Fatalf("verify output:\n%s", out.String())
	}
	// Root key 1 is lost: keys 2 and 3 rotate the timestamp key.
	sh("keygen", "-out", k("timestamp2"))
	sh("rotate-root", "-dir", repo, "-sign", k("root2"), "-sign", k("root3"), "-role-key", "timestamp="+k("timestamp2")+".pub")
	sh("refresh", "-dir", repo, "-root", rootFile, "-snapshot-key", k("snapshot"), "-timestamp-key", k("timestamp2"))
	sh("verify", "-dir", repo, "-root", rootFile)
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
	if err := run([]string{"refresh", "-dir", d, "-root", filepath.Join(d, "metadata", "1.root.json"), "-snapshot-key", filepath.Join(d, "keys", "snapshot.pem"), "-timestamp-key", filepath.Join(d, "keys", "timestamp.pem")}, &out, os.Getenv, now); err != nil {
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

func TestInitRefusesTestKeysAndUnlistedKeys(t *testing.T) {
	d := t.TempDir()
	now := func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) }
	var out strings.Builder
	if err := run([]string{"init-test", "-dir", filepath.Join(d, "test")}, &out, os.Getenv, now); err != nil {
		t.Fatal(err)
	}
	tk := func(n string) string { return filepath.Join(d, "test", "keys", n+".pem") }
	allow := filepath.Join(d, "allow")
	var ids []string
	for _, n := range []string{"root-1", "root-2", "root-3", "targets", "snapshot", "timestamp"} {
		pk, _ := tufrepo.LoadPublicKey(tk(n) + ".pub")
		id, _ := tufrepo.KeyID(pk)
		ids = append(ids, id)
	}
	_ = os.WriteFile(allow, []byte(strings.Join(ids, "\n")), 0o600)
	args := []string{"init", "-production", "-dir", filepath.Join(d, "prod"), "-allow-keys", allow,
		"-root-key", tk("root-1") + ".pub", "-root-key", tk("root-2") + ".pub", "-root-key", tk("root-3") + ".pub",
		"-targets-key", tk("targets") + ".pub", "-snapshot-key", tk("snapshot") + ".pub", "-timestamp-key", tk("timestamp") + ".pub",
		"-sign", tk("root-1"), "-sign", tk("root-2"), "-targets-sign", tk("targets")}
	if err := run(args, &out, os.Getenv, now); err == nil || !strings.Contains(err.Error(), "test key") {
		t.Fatalf("test keys accepted: %v", err)
	}
	// Copied out of the test folder, but not on the allowlist.
	for _, n := range []string{"root-1", "root-2", "root-3", "targets", "snapshot", "timestamp"} {
		for _, ext := range []string{"", ".pub"} {
			b, _ := os.ReadFile(tk(n) + ext)
			_ = os.WriteFile(filepath.Join(d, n+".pem"+ext), b, 0o600)
		}
	}
	for i, a := range args {
		args[i] = strings.Replace(a, filepath.Join(d, "test", "keys"), d, 1)
	}
	_ = os.WriteFile(allow, []byte(strings.Join(ids[1:], "\n")), 0o600)
	if err := run(args, &out, os.Getenv, now); err == nil || !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("unlisted key accepted: %v", err)
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
		{"refresh", "-dir", t.TempDir(), "-snapshot-key", "x", "-timestamp-key", "y"},
	} {
		if err := run(args, &out, os.Getenv, now); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}
