package accesslog

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf8"
)

func FuzzParseLine(f *testing.F) {
	f.Add([]byte(`{"time":"2026-10-01T12:00:00Z","app":"a1","peer":"127.0.0.1:1","target":"10.0.0.2:80","bytes_in":1,"bytes_out":2,"duration_ms":3,"result":"ok"}`))
	f.Add([]byte(`{"time":"2026-10-01T12:00:00Z","app":"<b>","peer":"","target":"","bytes_in":0,"bytes_out":0,"duration_ms":0,"result":"busy"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`garbage`))
	f.Fuzz(func(t *testing.T, line []byte) {
		e, err := ParseLine(line)
		if err != nil {
			return
		}
		for _, s := range []string{e.App, e.Peer, e.Target, e.Result} {
			if len(s) > maxField || !utf8.ValidString(s) {
				t.Fatalf("unsafe field %q", s)
			}
			for _, r := range s {
				if r < 0x20 || r > 0x7e {
					t.Fatalf("non-printable field %q", s)
				}
			}
		}
		if e.BytesIn < 0 || e.BytesOut < 0 || e.DurationMS < 0 || !knownResult[e.Result] {
			t.Fatalf("invalid entry accepted: %+v", e)
		}
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		again, err := ParseLine(b)
		if err != nil || again != e {
			t.Fatalf("round trip: %+v vs %+v (%v)", again, e, err)
		}
	})
}

func FuzzPage(f *testing.F) {
	good, _ := json.Marshal(entry(1, t0))
	f.Add(append(append([]byte{}, good...), '\n'), 3)
	f.Add([]byte("x\n\n\n"+string(good)+"\n"+string(good)), 1)
	f.Add(bytes.Repeat([]byte("a"), 70000), 7)
	f.Add(append(bytes.Repeat(append(append([]byte{}, good...), '\n'), 50), []byte("\n\n")...), 13)
	f.Fuzz(func(t *testing.T, data []byte, limit int) {
		dir := filepath.Join(t.TempDir(), "v2")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, fileName(t0)), data, 0o600); err != nil {
			t.Fatal(err)
		}
		c := &clock{now: t0}
		l, err := Open(Config{Dir: dir, Now: c.Now})
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		lines := bytes.Count(data, []byte("\n"))
		cursor, seen := "", 0
		for pages := 0; ; pages++ {
			if pages > lines+2 {
				t.Fatal("pagination does not terminate")
			}
			p, err := l.Page(cursor, limit)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range p.Entries {
				b, _ := json.Marshal(e)
				if _, err := ParseLine(b); err != nil {
					t.Fatalf("page returned an invalid entry: %v", err)
				}
			}
			seen += len(p.Entries)
			if p.Next == "" {
				break
			}
			if p.Next == cursor {
				t.Fatal("cursor did not advance")
			}
			cursor = p.Next
		}
		if seen > lines {
			t.Fatalf("%d entries from %d lines", seen, lines)
		}
	})
}
