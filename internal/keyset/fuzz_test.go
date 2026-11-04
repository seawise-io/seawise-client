package keyset

import (
	"testing"
)

func FuzzParseRoots(f *testing.F) {
	f.Add([]byte(`{"roots":["CYWnmZi2eWis-zhCFko0gGak6MNBi7t154txTVEJziE"]}`))
	f.Add([]byte(`{"roots":[]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		rs, err := ParseRoots(b)
		if err == nil && len(rs) > maxRoots {
			t.Fatalf("%d roots", len(rs))
		}
	})
}

func FuzzParseStored(f *testing.F) {
	f.Add([]byte(`{"schema":1,"token":"a.b.c","version":2,"digest":"` + string(make([]byte, 0)) + `","verified_at":"2026-01-01T00:00:00Z"}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := parseStored(b)
		if err == nil && (s.Version < 1 || len(s.Digest) != 64) {
			t.Fatalf("accepted %+v", s)
		}
	})
}
