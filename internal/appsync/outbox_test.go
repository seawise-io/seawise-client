package appsync

import (
	"strings"
	"testing"
	"time"
)

func validFile() File {
	lid := "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	return File{
		Schema: 1, ServerID: testServer, Adopted: true,
		Calls: []Call{{
			Key: strings.Repeat("0f", 16), Op: OpRegister, LocalIDs: []string{lid},
			Body:      []byte(`{"apps":[{"local_id":"` + lid + `","name":"A","host":"h","port":1,"public_local":true}]}`),
			CreatedAt: time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC),
		}},
		Registered: []string{lid},
		Deleted:    []string{"bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee"},
	}
}

func TestParseFileRoundTrip(t *testing.T) {
	f := validFile()
	raw, err := f.marshal()
	if err != nil {
		t.Fatal(err)
	}
	g, err := ParseFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if g.ServerID != f.ServerID || len(g.Calls) != 1 || string(g.Calls[0].Body) != string(f.Calls[0].Body) || !g.Adopted {
		t.Fatalf("%+v", g)
	}
}

func TestParseFileRefuses(t *testing.T) {
	mut := []func(*File){
		func(f *File) { f.Schema = 2 },
		func(f *File) { f.ServerID = "not-a-uuid" },
		func(f *File) { f.Calls[0].Key = "short" },
		func(f *File) { f.Calls[0].Key = strings.Repeat("AB", 16) },
		func(f *File) { f.Calls[0].Op = "patch" },
		func(f *File) { f.Calls[0].Body = []byte(`{"apps":[]}x`) },
		func(f *File) { f.Calls[0].Body = []byte(strings.Repeat(" ", MaxBody+1)) },
		func(f *File) { f.Calls[0].LocalIDs = []string{"bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee"} },
		func(f *File) { f.Calls[0].LocalIDs = nil },
		func(f *File) { f.Calls = append(f.Calls, f.Calls[0]) },
		func(f *File) { f.Registered = append(f.Registered, f.Registered[0]) },
		func(f *File) { f.Registered = []string{"X"} },
		func(f *File) { f.Deleted = []string{"aaaaaaaa-bbbb-4ccc-8ddd-EEEEEEEEEEEE"} },
		func(f *File) { f.Calls[0].Op = OpDelete },
		func(f *File) {
			f.Calls[0].Op = OpDelete
			f.Calls[0].Body = []byte(`{"local_ids":["aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"]}`)
			f.Calls[0].LocalIDs = []string{"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"}
		},
		func(f *File) {
			for i := 0; i <= MaxCalls; i++ {
				c := f.Calls[0]
				c.Key = strings.Repeat("0", 28) + string("0123456789abcdef"[i%16]) + string("0123456789abcdef"[(i/16)%16]) + string("0123456789abcdef"[(i/256)%16]) + "0"
				f.Calls = append(f.Calls, c)
			}
		},
	}
	for i, m := range mut {
		f := validFile()
		m(&f)
		raw, _ := f.marshal()
		if _, err := ParseFile(raw); err == nil {
			t.Fatalf("mutation %d accepted", i)
		}
	}
	for _, raw := range []string{``, `null`, `[]`, `{}`, `{"schema":1,"server_id":"","adopted":false,"calls":null,"registered":[],"deleted":[]}`,
		`{"schema":1,"server_id":"","adopted":false,"calls":[],"registered":[],"deleted":[],"extra":1}`,
		`{"schema":1,"server_id":"","adopted":false,"calls":[],"registered":[],"deleted":[]} {}`} {
		if _, err := ParseFile([]byte(raw)); err == nil {
			t.Fatalf("%q accepted", raw)
		}
	}
	if _, err := ParseFile([]byte(`{"schema":1,"server_id":"","adopted":false,"calls":[],"registered":[],"deleted":[]}`)); err != nil {
		t.Fatal(err)
	}
}

func TestLocalIDs(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id := NewLocalID()
		if !ValidLocalID(id) || seen[id] || id[14] != '4' || !strings.ContainsRune("89ab", rune(id[19])) {
			t.Fatalf("bad id %q", id)
		}
		seen[id] = true
	}
	for _, bad := range []string{"", "0123456789abcdef0123456789abcdef", "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE", "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeee"} {
		if ValidLocalID(bad) {
			t.Fatalf("%q valid", bad)
		}
	}
	k := newKey()
	if !keyRe.MatchString(k) || k == newKey() {
		t.Fatal(k)
	}
}
