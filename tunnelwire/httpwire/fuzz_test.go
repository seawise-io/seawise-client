package httpwire

import (
	"testing"
)

func FuzzRequestBytes(f *testing.F) {
	for _, c := range genRequestBytes().Cases {
		if c.Kind == "request" {
			f.Add([]byte(c.Input))
		}
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		s, err := CheckExchange(in)
		if err != nil {
			if CodeOf(err) == "" {
				t.Fatalf("uncoded: %v", err)
			}
			return
		}
		for k := range s.Header {
			if isSeaWise(k) {
				t.Fatal("SeaWise header kept")
			}
		}
		for k := range s.Trailer {
			if isSeaWise(k) {
				t.Fatal("SeaWise trailer kept")
			}
		}
	})
}

func FuzzH2Field(f *testing.F) {
	f.Add("accept", "text/html")
	f.Add("x", "a\r\nb")
	f.Fuzz(func(t *testing.T, name, value string) {
		if CheckH2Field(name, value) != nil {
			return
		}
		for _, s := range []string{name, value} {
			for i := 0; i < len(s); i++ {
				if s[i] == 0 || s[i] == '\r' || s[i] == '\n' {
					t.Fatal("accepted CR, LF or NUL")
				}
			}
		}
	})
}
