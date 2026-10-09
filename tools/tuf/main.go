// Command tuf maintains the static TUF repository that publishes the key
// set and release manifests. It is a maintainer tool and is not part of
// the agent image. See README.md.
package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/seawise/client/internal/tufrepo"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

const usage = `usage: tuf <command> [flags]

offline (root and targets keys):
  keygen        -out FILE
  init          -dir D -root-key P.pub -root-key P.pub -targets-key P.pub -snapshot-key P.pub -timestamp-key P.pub -sign K [-sign K] -targets-sign K
  sign-targets  -dir D -key K [-add NAME=FILE ...] [-remove NAME ...] [-expires 120d]
  rotate-root   -dir D -sign K ... [-role-key ROLE=P.pub ...] [-threshold ROLE=N ...] [-expires 365d]

online (snapshot and timestamp keys):
  pull          -url URL -dir D
  refresh       -dir D -snapshot-key K -timestamp-key K [-expires 14d] [-min-remaining 7d]

anywhere:
  verify        -dir D -root ROOT.json [-at RFC3339] [-metadata-only]
  init-test     -dir D       TEST ONLY: throwaway keys in D/keys, root marked test-only

K is a key file or env:NAME (PEM in an environment variable).
`

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Getenv, time.Now); err != nil {
		fmt.Fprintln(os.Stderr, "tuf:", err)
		os.Exit(1)
	}
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func run(args []string, out io.Writer, getenv func(string) string, now func() time.Time) error {
	if len(args) == 0 {
		fmt.Fprint(out, usage)
		return errors.New("no command")
	}
	cmd, args := args[0], args[1:]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(out)
	dir := fs.String("dir", "", "repository directory")
	switch cmd {
	case "keygen":
		path := fs.String("out", "", "private key file to create")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if *path == "" {
			return errors.New("-out is required")
		}
		id, err := tufrepo.Keygen(*path)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "key %s\nprivate %s (keep offline)\npublic %s.pub\n", id, *path, *path)
		return nil

	case "init-test":
		if err := fs.Parse(args); err != nil {
			return err
		}
		if *dir == "" {
			return errors.New("-dir is required")
		}
		if _, err := tufrepo.InitTest(*dir, now()); err != nil {
			return err
		}
		fmt.Fprintf(out, "TEST ONLY repository in %s. Its root is marked test-only and its keys are in %s/keys.\nNever publish it or pin it in a release.\n", *dir, *dir)
		return nil

	case "init":
		var rootKeys, signers multi
		fs.Var(&rootKeys, "root-key", "root public key (at least two)")
		targets := fs.String("targets-key", "", "targets public key")
		snapshot := fs.String("snapshot-key", "", "snapshot public key")
		timestamp := fs.String("timestamp-key", "", "timestamp public key")
		targetsSigner := fs.String("targets-sign", "", "targets private key")
		fs.Var(&signers, "sign", "root private key")
		rootExp := fs.String("root-expires", "365d", "root lifetime")
		targetsExp := fs.String("targets-expires", "120d", "targets lifetime")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if *dir == "" {
			return errors.New("-dir is required")
		}
		re, err := tufrepo.ParseDuration(*rootExp)
		if err != nil {
			return err
		}
		te, err := tufrepo.ParseDuration(*targetsExp)
		if err != nil {
			return err
		}
		opts := tufrepo.InitOptions{Now: now(), RootExpires: re, TargetsExpires: te}
		if opts.Root.Keys, err = loadPublics(rootKeys); err != nil {
			return err
		}
		opts.Root.Threshold = 1
		for _, r := range []struct {
			path string
			dst  *tufrepo.RoleKeys
		}{{*targets, &opts.Targets}, {*snapshot, &opts.Snapshot}, {*timestamp, &opts.Timestamp}} {
			k, err := tufrepo.LoadPublicKey(r.path)
			if err != nil {
				return err
			}
			*r.dst = tufrepo.RoleKeys{Keys: []ed25519.PublicKey{k}, Threshold: 1}
		}
		if opts.RootSigners, err = loadPrivates(signers, getenv); err != nil {
			return err
		}
		if opts.TargetsSigner, err = tufrepo.LoadPrivateKey(*targetsSigner, getenv); err != nil {
			return err
		}
		if err := tufrepo.Init(*dir, opts); err != nil {
			return err
		}
		fmt.Fprintf(out, "wrote %s/metadata/1.root.json and 1.targets.json; run refresh online next\n", *dir)
		return nil

	case "sign-targets":
		var adds, removes multi
		key := fs.String("key", "", "targets private key")
		fs.Var(&adds, "add", "NAME=FILE to add or replace")
		fs.Var(&removes, "remove", "NAME to remove")
		exp := fs.String("expires", "120d", "targets lifetime")
		if err := fs.Parse(args); err != nil {
			return err
		}
		d, err := tufrepo.ParseDuration(*exp)
		if err != nil {
			return err
		}
		k, err := tufrepo.LoadPrivateKey(*key, getenv)
		if err != nil {
			return err
		}
		files := map[string][]byte{}
		for _, a := range adds {
			name, path, ok := strings.Cut(a, "=")
			if !ok {
				return fmt.Errorf("-add %q: want NAME=FILE", a)
			}
			b, err := readCapped(path, tufrepo.MaxTargetSize)
			if err != nil {
				return err
			}
			files[name] = b
		}
		v, err := tufrepo.SignTargets(*dir, k, files, removes, now(), d)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "wrote %s/metadata/%d.targets.json; publish it with the target files, then run refresh\n", *dir, v)
		return nil

	case "rotate-root":
		var signers, roleKeys, thresholds multi
		fs.Var(&signers, "sign", "private key (old and new root keys)")
		fs.Var(&roleKeys, "role-key", "ROLE=PUBLIC.pub, repeat for several keys; replaces the role's keys")
		fs.Var(&thresholds, "threshold", "ROLE=N")
		exp := fs.String("expires", "365d", "root lifetime")
		if err := fs.Parse(args); err != nil {
			return err
		}
		d, err := tufrepo.ParseDuration(*exp)
		if err != nil {
			return err
		}
		ch := tufrepo.RootChange{Roles: map[string]tufrepo.RoleKeys{}, Now: now(), Expires: d}
		for _, rk := range roleKeys {
			role, path, ok := strings.Cut(rk, "=")
			if !ok {
				return fmt.Errorf("-role-key %q: want ROLE=FILE", rk)
			}
			k, err := tufrepo.LoadPublicKey(path)
			if err != nil {
				return err
			}
			r := ch.Roles[role]
			r.Keys = append(r.Keys, k)
			ch.Roles[role] = r
		}
		cur, _, err := tufrepo.LatestRoot(*dir)
		if err != nil {
			return err
		}
		for role, r := range ch.Roles {
			r.Threshold = 1
			if old := cur.Signed.Roles[role]; old != nil && old.Threshold <= len(r.Keys) {
				r.Threshold = old.Threshold
			}
			ch.Roles[role] = r
		}
		for _, th := range thresholds {
			role, n, ok := strings.Cut(th, "=")
			v, err := strconv.Atoi(n)
			if !ok || err != nil {
				return fmt.Errorf("-threshold %q: want ROLE=N", th)
			}
			r, present := ch.Roles[role]
			if !present {
				return fmt.Errorf("-threshold %s needs -role-key %s=...", role, role)
			}
			r.Threshold = v
			ch.Roles[role] = r
		}
		if ch.Signers, err = loadPrivates(signers, getenv); err != nil {
			return err
		}
		v, err := tufrepo.RotateRoot(*dir, ch)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "wrote %s/metadata/%d.root.json\n", *dir, v)
		return nil

	case "refresh":
		snapKey := fs.String("snapshot-key", "", "snapshot private key")
		tsKey := fs.String("timestamp-key", "", "timestamp private key")
		exp := fs.String("expires", "14d", "snapshot and timestamp lifetime")
		minRem := fs.String("min-remaining", "7d", "renew the snapshot when less than this is left")
		if err := fs.Parse(args); err != nil {
			return err
		}
		d, err := tufrepo.ParseDuration(*exp)
		if err != nil {
			return err
		}
		m, err := tufrepo.ParseDuration(*minRem)
		if err != nil {
			return err
		}
		sk, err := tufrepo.LoadPrivateKey(*snapKey, getenv)
		if err != nil {
			return err
		}
		tk, err := tufrepo.LoadPrivateKey(*tsKey, getenv)
		if err != nil {
			return err
		}
		res, err := tufrepo.Refresh(*dir, sk, tk, now(), d, m)
		if err != nil {
			return err
		}
		if res.NewSnapshot {
			fmt.Fprintf(out, "wrote metadata/%d.snapshot.json\n", res.SnapshotVersion)
		}
		fmt.Fprintf(out, "wrote metadata/timestamp.json version %d; upload it after every other file\n", res.TimestampVersion)
		return nil

	case "pull":
		u := fs.String("url", "", "https base URL of the published repository")
		if err := fs.Parse(args); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		hc := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		return tufrepo.Pull(ctx, hc, *u, *dir)

	case "verify":
		rootPath := fs.String("root", "", "trusted root metadata to start from")
		at := fs.String("at", "", "check expiry at this RFC 3339 time instead of now")
		metaOnly := fs.Bool("metadata-only", false, "do not check target files (after pull)")
		if err := fs.Parse(args); err != nil {
			return err
		}
		root, err := readCapped(*rootPath, 1<<20)
		if err != nil {
			return err
		}
		if len(root) == 0 {
			return errors.New("trusted root is empty")
		}
		t := now()
		if *at != "" {
			if t, err = time.Parse(time.RFC3339, *at); err != nil {
				return err
			}
		}
		rep, err := tufrepo.Verify(*dir, root, t, !*metaOnly)
		if err != nil {
			return err
		}
		if tufrepo.IsTestRoot(root) {
			fmt.Fprintln(out, "WARNING: trusted root is a TEST root")
		}
		rows := []struct {
			role string
			v    int64
			exp  time.Time
		}{{metadata.ROOT, rep.RootVersion, rep.RootExpires}, {metadata.TARGETS, rep.TargetsVersion, rep.TargetsExpires},
			{metadata.SNAPSHOT, rep.SnapshotVersion, rep.SnapshotExpires}, {metadata.TIMESTAMP, rep.TimestampVersion, rep.TimestampExpires}}
		for _, r := range rows {
			fmt.Fprintf(out, "%-9s v%-4d expires %s (in %s)\n", r.role, r.v, r.exp.Format(time.RFC3339), r.exp.Sub(t).Round(time.Hour))
		}
		sort.Strings(rep.Targets)
		for _, n := range rep.Targets {
			fmt.Fprintf(out, "target %s\n", n)
		}
		return nil
	}
	fmt.Fprint(out, usage)
	return fmt.Errorf("unknown command %q", cmd)
}

func loadPublics(paths []string) ([]ed25519.PublicKey, error) {
	var ks []ed25519.PublicKey
	for _, p := range paths {
		k, err := tufrepo.LoadPublicKey(p)
		if err != nil {
			return nil, err
		}
		ks = append(ks, k)
	}
	return ks, nil
}

func loadPrivates(refs []string, getenv func(string) string) ([]ed25519.PrivateKey, error) {
	var ks []ed25519.PrivateKey
	for _, r := range refs {
		k, err := tufrepo.LoadPrivateKey(r, getenv)
		if err != nil {
			return nil, err
		}
		ks = append(ks, k)
	}
	return ks, nil
}

func readCapped(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, max)
	}
	return b, nil
}
