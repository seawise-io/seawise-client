package appsync

import (
	"bytes"
	"log/slog"
	"strconv"
	"testing"
)

func testLogger(w *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func itoa(i int) string { return strconv.Itoa(i) }

func FuzzParseFile(f *testing.F) {
	raw, _ := func() ([]byte, error) { v := validFile(); return v.marshal() }()
	f.Add(raw)
	f.Add([]byte(`{"schema":1,"server_id":"","adopted":false,"calls":[],"registered":[],"deleted":[]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := ParseFile(b)
		if err != nil {
			return
		}
		again, err := got.marshal()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseFile(again); err != nil {
			t.Fatalf("accepted file does not round trip: %v", err)
		}
	})
}

func FuzzParseRegisterAnswer(f *testing.F) {
	lid := "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	f.Add([]byte(`{"items":[{"local_id":"` + lid + `","id":"` + lid + `","result":"created","subdomain":"a"}]}`))
	f.Add([]byte(`{"items":[{"local_id":"` + lid + `","id":null,"result":"deleted","subdomain":null}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		res, err := parseRegisterAnswer(b, []string{lid})
		if err != nil {
			return
		}
		if len(res) != 1 || res[0].LocalID != lid {
			t.Fatalf("%+v", res)
		}
	})
}

func FuzzParseList(f *testing.F) {
	f.Add([]byte(`{"apps":[],"deleted":[]}`))
	f.Add([]byte(`{"apps":[{"id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","local_id":null,"name":"A","subdomain":"a","host":"h","port":1,"public_requested":false}],"deleted":["aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		l, err := parseList(b)
		if err != nil {
			return
		}
		for _, a := range l.Apps {
			if !ValidLocalID(a.ID) || (a.LocalID != "" && !ValidLocalID(a.LocalID)) || a.Port < 1 || a.Port > 65535 {
				t.Fatalf("%+v", a)
			}
		}
	})
}

func FuzzParseDeleteAnswer(f *testing.F) {
	lid := "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	f.Add([]byte(`{"results":[{"local_id":"` + lid + `","id":null,"result":"absent"}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if err := parseDeleteAnswer(b, []string{lid}); err != nil {
			return
		}
	})
}
