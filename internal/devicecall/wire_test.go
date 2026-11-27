package devicecall

import (
	"strings"
	"testing"
)

func TestSafeCode(t *testing.T) {
	for in, want := range map[string]string{"replayed": "replayed", "a_z": "a_z", "{": "unknown", "`": "unknown", "": "unknown", "Bad": "unknown", "a\nb": "unknown", strings.Repeat("a", 33): "unknown", strings.Repeat("a", 32): strings.Repeat("a", 32)} {
		if got := SafeCode(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}

func TestStrictStrings(t *testing.T) {
	ok := []string{
		`{"result":"switched"}`,
		` {"result" : "switched"} `,
		`{"result":"switched","code":"x"}`,
	}
	for _, s := range ok {
		if m, err := StrictStrings([]byte(s), []string{"result"}, "code"); err != nil || m["result"] != "switched" {
			t.Errorf("%s refused", s)
		}
	}
	bad := []string{
		``, `null`, `[]`, `"x"`, `{}`, `{"result":1}`, `{"result":null}`, `{"result":"a","result":"a"}`,
		`{"result":"a","extra":"b"}`, `{"Result":"a"}`, `{"result":"a"} x`, `{"result":"a"}{}`, `{"result":{"a":"b"}}`,
		"{\"result\":\"\xff\"}", `{"result":"a"`, `{"result":["a"]}`,
	}
	for _, s := range bad {
		if _, err := StrictStrings([]byte(s), []string{"result"}, "code"); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func FuzzStrictStrings(f *testing.F) {
	for _, s := range []string{`{"result":"enrolled","server_id":"a","device_id":"b","key_id":"c"}`, `{"a":"b","a":"c"}`, `{"result":"switched"}`, `{`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := StrictStrings(b, []string{"result"}, "server_id", "device_id", "key_id")
		if err != nil {
			return
		}
		if _, ok := m["result"]; !ok || len(m) > 4 {
			t.Fatal("accepted object breaks the member rules")
		}
		again, err := StrictStrings(b, []string{"result"}, "server_id", "device_id", "key_id")
		if err != nil || len(again) != len(m) {
			t.Fatal("not deterministic")
		}
	})
}

func TestStrictStringsOptional(t *testing.T) {
	m, err := StrictStrings([]byte(`{"result":"a","code":"b"}`), []string{"result"}, "code")
	if err != nil || m["code"] != "b" || len(m) != 2 {
		t.Fatalf("%v %v", m, err)
	}
	m, err = StrictStrings([]byte(`{"result":"a","code":null}`), []string{"result"}, "code")
	if _, has := m["code"]; err != nil || has || len(m) != 1 {
		t.Fatalf("null optional: %v %v", m, err)
	}
	if _, err := StrictStrings([]byte(`{"result":"a","code":null,"code":"b"}`), []string{"result"}, "code"); err == nil {
		t.Fatal("repeated optional accepted")
	}
	if _, err := StrictStrings([]byte(`{"result":"a","code":1}`), []string{"result"}, "code"); err == nil {
		t.Fatal("number accepted")
	}
}
