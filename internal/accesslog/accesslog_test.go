package accesslog

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seawise/client/internal/store"
)

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func ownerDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "v2")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func entry(i int, at time.Time) Entry {
	return Entry{
		Time: at, App: fmt.Sprintf("app%d", i%3), Peer: "127.0.0.1:40000", Target: "192.168.1.20:8096",
		BytesIn: int64(i), BytesOut: int64(2 * i), DurationMS: 5, Result: ResultOK,
	}
}

func open(t *testing.T, dir string, c *clock, tweak func(*Config)) *Log {
	t.Helper()
	cfg := Config{Dir: dir, Now: c.Now}
	if tweak != nil {
		tweak(&cfg)
	}
	l, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func all(t *testing.T, l *Log) []Entry {
	t.Helper()
	var out []Entry
	cursor := ""
	for i := 0; i < 10000; i++ {
		p, err := l.Page(cursor, MaxPage)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p.Entries...)
		if p.Next == "" {
			return out
		}
		cursor = p.Next
	}
	t.Fatal("pagination did not end")
	return nil
}

func TestRecordAndPageNewestFirst(t *testing.T) {
	c := &clock{now: t0}
	l := open(t, ownerDir(t), c, nil)
	for i := 0; i < 120; i++ {
		l.Record(entry(i, t0.Add(time.Duration(i)*time.Second)))
	}
	l.Flush()
	p, err := l.Page("", 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Entries) != 50 || p.Next == "" {
		t.Fatalf("first page: %d entries, next %q", len(p.Entries), p.Next)
	}
	if p.Entries[0].BytesIn != 119 || p.Entries[49].BytesIn != 70 {
		t.Fatalf("not newest first: %d .. %d", p.Entries[0].BytesIn, p.Entries[49].BytesIn)
	}
	got := all(t, l)
	if len(got) != 120 {
		t.Fatalf("all pages: %d entries", len(got))
	}
	for i, e := range got {
		if want := entry(119-i, t0.Add(time.Duration(119-i)*time.Second)); !reflect.DeepEqual(e, want) {
			t.Fatalf("entry %d = %+v, want %+v", i, e, want)
		}
	}
}

func TestFilesOwnerOnly(t *testing.T) {
	c := &clock{now: t0}
	dir := ownerDir(t)
	l := open(t, dir, c, nil)
	l.Record(entry(1, t0))
	l.Flush()
	files, _ := filepath.Glob(filepath.Join(dir, "access-*.log"))
	if len(files) != 1 {
		t.Fatalf("files = %v", files)
	}
	info, err := os.Stat(files[0])
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, %v", info, err)
	}
}

func TestRefusesSymlinkedLog(t *testing.T) {
	c := &clock{now: t0}
	dir := ownerDir(t)
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(dir, fileName(t0.Add(-time.Hour)))
	if err := os.Symlink(victim, name); err != nil {
		t.Fatal(err)
	}
	l := open(t, dir, c, nil)
	l.Record(entry(1, t0))
	l.Flush()
	if b, _ := os.ReadFile(victim); len(b) != 0 {
		t.Fatal("wrote through a symlink")
	}
	if l.Status().WriteErrors == 0 && len(all(t, l)) == 0 {
		t.Fatal("entry neither written to a new file nor counted as an error")
	}
}

func TestLooseModeFileNotAppended(t *testing.T) {
	c := &clock{now: t0}
	dir := ownerDir(t)
	name := filepath.Join(dir, fileName(t0.Add(-time.Hour)))
	if err := os.WriteFile(name, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, 0o644); err != nil {
		t.Fatal(err)
	}
	l := open(t, dir, c, nil)
	l.Record(entry(1, t0))
	l.Flush()
	if b, _ := os.ReadFile(name); len(b) != 0 {
		t.Fatal("appended to a file readable by others")
	}
}

func TestRotationBySizeAndAge(t *testing.T) {
	c := &clock{now: t0}
	dir := ownerDir(t)
	l := open(t, dir, c, func(cfg *Config) { cfg.MaxFileBytes = 1000; cfg.MaxTotalBytes = 1 << 20 })
	for i := 0; i < 20; i++ {
		l.Record(entry(i, c.Now()))
	}
	l.Flush()
	files, _ := filepath.Glob(filepath.Join(dir, "access-*.log"))
	if len(files) < 3 {
		t.Fatalf("size rotation: %d files", len(files))
	}
	for _, f := range files {
		if info, _ := os.Stat(f); info.Size() > 1000 {
			t.Fatalf("%s is %d bytes", f, info.Size())
		}
	}
	before := len(files)
	c.add(25 * time.Hour)
	l.Record(entry(99, c.Now()))
	l.Flush()
	files, _ = filepath.Glob(filepath.Join(dir, "access-*.log"))
	if len(files) != before+1 {
		t.Fatalf("age rotation: %d files, want %d", len(files), before+1)
	}
	if got := all(t, l); len(got) != 21 || got[0].BytesIn != 99 {
		t.Fatalf("entries across files: %d", len(got))
	}
}

func TestRetention(t *testing.T) {
	c := &clock{now: t0}
	dir := ownerDir(t)
	l := open(t, dir, c, nil)
	for day := 0; day < 40; day++ {
		l.Record(entry(day, c.Now()))
		l.Flush()
		c.add(24*time.Hour + time.Minute)
	}
	l.Prune()
	got := all(t, l)
	oldest := c.Now().Add(-DefaultRetention)
	for _, e := range got {
		if e.Time.Before(oldest) {
			t.Fatalf("entry from %v kept past retention (now %v)", e.Time, c.Now())
		}
	}
	if len(got) < 28 {
		t.Fatalf("retention removed too much: %d entries", len(got))
	}
}

func TestRetentionAppliesAtOpen(t *testing.T) {
	c := &clock{now: t0}
	dir := ownerDir(t)
	l := open(t, dir, c, nil)
	l.Record(entry(1, t0))
	l.Close()
	c.add(31 * 24 * time.Hour)
	l = open(t, dir, c, nil)
	if got := all(t, l); len(got) != 0 {
		t.Fatalf("old entries survived reopen: %d", len(got))
	}
}

func TestSizeCap(t *testing.T) {
	c := &clock{now: t0}
	dir := ownerDir(t)
	l := open(t, dir, c, func(cfg *Config) { cfg.MaxFileBytes = 2000; cfg.MaxTotalBytes = 6000 })
	for i := 0; i < 500; i++ {
		l.Record(entry(i, c.Now()))
		if i%50 == 0 {
			l.Flush()
		}
	}
	l.Flush()
	var total int64
	files, _ := filepath.Glob(filepath.Join(dir, "access-*.log"))
	for _, f := range files {
		info, _ := os.Stat(f)
		total += info.Size()
	}
	if total > 6000 {
		t.Fatalf("total %d bytes over cap", total)
	}
	got := all(t, l)
	if len(got) == 0 || got[0].BytesIn != 499 {
		t.Fatal("newest entries must survive the size cap")
	}
}

func TestRecordNeverBlocks(t *testing.T) {
	c := &clock{now: t0}
	l := open(t, ownerDir(t), c, func(cfg *Config) { cfg.QueueSize = 4 })
	l.pause()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			l.Record(entry(i, t0))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Record blocked on a stalled writer")
	}
	l.resume()
	l.Flush()
	if s := l.Status(); s.Dropped == 0 {
		t.Fatal("drops not counted")
	}
}

func TestRecordAfterCloseIsDropped(t *testing.T) {
	c := &clock{now: t0}
	l := open(t, ownerDir(t), c, nil)
	l.Close()
	l.Record(entry(1, t0))
	l.Close()
}

func TestEntryHasOnlyMetadata(t *testing.T) {
	want := []string{"app", "bytes_in", "bytes_out", "duration_ms", "peer", "result", "target", "time"}
	var got []string
	ty := reflect.TypeOf(Entry{})
	for i := 0; i < ty.NumField(); i++ {
		tag, _, _ := strings.Cut(ty.Field(i).Tag.Get("json"), ",")
		got = append(got, tag)
	}
	if fmt.Sprint(sorted(got)) != fmt.Sprint(want) {
		t.Fatalf("entry fields = %v; adding a field needs a privacy review", got)
	}
}

func sorted(s []string) []string {
	out := append([]string(nil), s...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func TestParseLineStrict(t *testing.T) {
	good := `{"time":"2026-10-01T12:00:00Z","app":"a1","peer":"127.0.0.1:1","target":"10.0.0.2:80","bytes_in":1,"bytes_out":2,"duration_ms":3,"result":"ok"}`
	if _, err := ParseLine([]byte(good)); err != nil {
		t.Fatalf("good line: %v", err)
	}
	bad := []string{
		``,
		`null`,
		`[]`,
		strings.Replace(good, `"ok"`, `"maybe"`, 1),
		strings.Replace(good, `"bytes_in":1`, `"bytes_in":-1`, 1),
		strings.Replace(good, `"app":"a1"`, `"app":"<script>\u0007"`, 1),
		strings.Replace(good, `"app":"a1"`, `"app":"`+strings.Repeat("x", 200)+`"`, 1),
		strings.Replace(good, `}`, `,"headers":"x"}`, 1),
		good + good,
		strings.Replace(good, `"time":"2026-10-01T12:00:00Z",`, ``, 1),
	}
	for _, b := range bad {
		if _, err := ParseLine([]byte(b)); err == nil {
			t.Errorf("accepted %q", b)
		}
	}
}

func TestPageSkipsGarbageAndLongLines(t *testing.T) {
	c := &clock{now: t0}
	dir := ownerDir(t)
	l := open(t, dir, c, nil)
	l.Record(entry(1, t0))
	l.Flush()
	files, _ := filepath.Glob(filepath.Join(dir, "access-*.log"))
	f, err := os.OpenFile(files[0], os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("garbage\n" + strings.Repeat("y", 200000) + "\n{\"time\":1}\n")
	b, _ := json.Marshal(entry(2, t0))
	f.Write(append(b, '\n'))
	f.WriteString(`{"partial":`)
	f.Close()
	got := all(t, l)
	if len(got) != 2 || got[0].BytesIn != 2 || got[1].BytesIn != 1 {
		t.Fatalf("got %+v", got)
	}
}

func TestBadCursor(t *testing.T) {
	c := &clock{now: t0}
	l := open(t, ownerDir(t), c, nil)
	for _, cur := range []string{"x", "../../etc/passwd:0", "1:-1", "1:abc", "-5:3", "1:2:3"} {
		if _, err := l.Page(cur, 10); !errors.Is(err, ErrCursor) {
			t.Errorf("cursor %q: err = %v", cur, err)
		}
	}
	if p, err := l.Page("", 0); err != nil || len(p.Entries) != 0 {
		t.Fatalf("empty log: %v %v", p, err)
	}
}

func TestDirMustBeOwnerOnly(t *testing.T) {
	d := filepath.Join(t.TempDir(), "v2")
	if err := os.Mkdir(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Config{Dir: d}); !errors.Is(err, store.ErrUnsafePath) {
		t.Fatalf("err = %v", err)
	}
}

func TestPruneCountsOnlyDeletedFiles(t *testing.T) {
	c := &clock{now: t0}
	dir := ownerDir(t)
	l := open(t, dir, c, func(cfg *Config) { cfg.MaxFileBytes = 2000; cfg.MaxTotalBytes = 6000 })
	files := func() []string { f, _ := filepath.Glob(filepath.Join(dir, "access-*.log")); return f }
	for len(files()) < 3 {
		l.Record(entry(1, c.Now()))
		l.Flush()
	}
	stuck := files()[0]
	removeFile = func(p string) error {
		if p == stuck {
			return errors.New("permission denied")
		}
		return os.Remove(p)
	}
	defer func() { removeFile = os.Remove }()
	for i := 0; i < 200; i++ {
		l.Record(entry(i, c.Now()))
	}
	l.Flush()
	l.Prune()
	var others int64
	cur := files()
	for _, f := range cur[:len(cur)-1] {
		info, _ := os.Stat(f)
		others += info.Size()
	}
	if others > 6000-2000 {
		t.Fatalf("older files hold %d bytes: a failed delete was counted as freed", others)
	}
	if l.Status().DeleteErrors == 0 {
		t.Fatal("delete failures not counted")
	}
}

func TestPageBoundsScannedLines(t *testing.T) {
	c := &clock{now: t0}
	dir := ownerDir(t)
	l := open(t, dir, c, nil)
	l.Record(entry(7, t0))
	l.Flush()
	files, _ := filepath.Glob(filepath.Join(dir, "access-*.log"))
	f, err := os.OpenFile(files[0], os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(strings.Repeat("x\n", 3*maxScanLines))
	f.Close()
	p, err := l.Page("", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Entries) != 0 || p.Next == "" {
		t.Fatalf("first page scanned everything: %d entries, next %q", len(p.Entries), p.Next)
	}
	if got := all(t, l); len(got) != 1 || got[0].BytesIn != 7 {
		t.Fatalf("entry not reached by paging: %+v", got)
	}
}
