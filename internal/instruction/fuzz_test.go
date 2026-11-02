package instruction

import "testing"

func FuzzParseState(f *testing.F) {
	f.Add([]byte(`{"schema":1,"floor":5,"records":{"a":{"op":"unpair","args":{},"iats":[1,2],"exp":3,"state":"pending"}}}`))
	f.Add([]byte(`{"schema":1,"records":{"a":null}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := parseState(b)
		if err != nil {
			return
		}
		if s.Records == nil || len(s.Records) > MaxOpen {
			t.Fatalf("records %v", s.Records)
		}
		for _, r := range s.Records {
			if r == nil || len(r.IATs) > MaxCopies {
				t.Fatalf("record %+v", r)
			}
		}
	})
}
