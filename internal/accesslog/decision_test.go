package accesslog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecisionFieldsRoundTrip(t *testing.T) {
	c := &clock{now: t0}
	l := open(t, ownerDir(t), c, nil)
	e := entry(1, t0)
	e.Decision, e.Session, e.Peer = "valid", "sid:0123456789ab", "203.0.113.9"
	d := entry(2, t0.Add(1))
	d.Decision, d.Result = "expired", ResultDenied
	m := entry(3, t0.Add(2))
	m.Decision, m.Result = "public", ResultMalformed
	l.Record(e)
	l.Record(d)
	l.Record(m)
	l.Flush()
	got := all(t, l)
	if len(got) != 3 || got[2] != e.normal() || got[1] != d.normal() || got[0] != m.normal() {
		t.Fatalf("%+v", got)
	}
}

func (e Entry) normal() Entry {
	e.Time = e.Time.UTC().Truncate(1e6)
	return e
}

func TestOldLinesStillParse(t *testing.T) {
	old := `{"time":"2026-10-01T12:00:00Z","app":"a1","peer":"127.0.0.1:1","target":"10.0.0.2:80","bytes_in":1,"bytes_out":2,"duration_ms":3,"result":"ok"}`
	e, err := ParseLine([]byte(old))
	if err != nil || e.Decision != "" || e.Session != "" {
		t.Fatal(e, err)
	}
}

func TestDecisionFieldsValidated(t *testing.T) {
	good := `{"time":"2026-10-01T12:00:00Z","app":"a1","peer":"127.0.0.1:1","target":"10.0.0.2:80","bytes_in":1,"bytes_out":2,"duration_ms":3,"result":"denied","decision":"wrong_app","session":"sid:0123456789ab"}`
	if _, err := ParseLine([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{
		strings.Replace(good, `"wrong_app"`, `"\u0007"`, 1),
		strings.Replace(good, `"sid:0123456789ab"`, `"`+strings.Repeat("x", 200)+`"`, 1),
		strings.Replace(good, `"wrong_app"`, `1`, 1),
		strings.Replace(good, `"denied"`, `"denied2"`, 1),
	} {
		if _, err := ParseLine([]byte(b)); err == nil {
			t.Errorf("accepted %s", b)
		}
	}
}

func TestEmptyDecisionFieldsOmitted(t *testing.T) {
	c := &clock{now: t0}
	dir := ownerDir(t)
	l := open(t, dir, c, nil)
	l.Record(entry(1, t0))
	l.Flush()
	files, _ := filepath.Glob(filepath.Join(dir, "access-*.log"))
	if len(files) != 1 {
		t.Fatal(files)
	}
	b, _ := os.ReadFile(files[0])
	if strings.Contains(string(b), "decision") || strings.Contains(string(b), "session") {
		t.Fatalf("%s", b)
	}
}

func TestDecisionFieldsCleaned(t *testing.T) {
	c := &clock{now: t0}
	l := open(t, ownerDir(t), c, nil)
	e := entry(1, t0)
	e.Decision, e.Session = "a\x00b", strings.Repeat("y", 300)
	l.Record(e)
	l.Flush()
	got := all(t, l)
	if len(got) != 1 || got[0].Decision != "a?b" || len(got[0].Session) != maxField {
		t.Fatalf("%+v", got)
	}
}

func TestZeroCountsParse(t *testing.T) {
	line := `{"time":"2026-10-01T12:00:00Z","app":"a1","peer":"203.0.113.9","target":"","bytes_in":0,"bytes_out":0,"duration_ms":0,"result":"denied","decision":"missing"}`
	if e, err := ParseLine([]byte(line)); err != nil || e.Decision != "missing" {
		t.Fatal(e, err)
	}
}
