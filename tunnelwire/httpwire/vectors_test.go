package httpwire

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/seawise-io/seawise-client/tunnelwire/internal/vkeys"
)

func TestVectorsUpToDate(t *testing.T) {
	ok, err := vkeys.Sync("request_bytes.json", vkeys.Pretty(genRequestBytes()), os.Getenv("UPDATE_VECTORS") == "1")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("request_bytes.json is out of date; run with UPDATE_VECTORS=1")
	}
}

func codeStr(err error) string {
	if err == nil {
		return "ok"
	}
	if c := CodeOf(err); c != "" {
		return string(c)
	}
	return "uncoded: " + err.Error()
}

func TestRequestBytesVectors(t *testing.T) {
	b, err := vkeys.Load("request_bytes.json")
	if err != nil {
		t.Fatal(err)
	}
	var f vfile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Cases {
		var got string
		var res any
		switch c.Kind {
		case "request":
			s, err := CheckExchange([]byte(c.Input))
			got = codeStr(err)
			if err == nil {
				res = s
				for k := range s.Header {
					if isSeaWise(k) {
						t.Errorf("%s: %s reached the target", c.Name, k)
					}
				}
				for k := range s.Trailer {
					if isSeaWise(k) {
						t.Errorf("%s: %s reached the target in the trailer", c.Name, k)
					}
				}
			}
		case "h2_field":
			got = codeStr(CheckH2Field(c.Context["name"].(string), c.Context["value"].(string)))
		case "upgrade":
			req, err := ReadRequest(bufio.NewReader(strings.NewReader(c.Input)))
			if err != nil {
				t.Fatal(c.Name, err)
			}
			got = codeStr(RawAfter(req, int(c.Context["status"].(float64))))
		default:
			t.Fatalf("%s: unknown kind", c.Name)
		}
		if got != c.Expect {
			t.Errorf("%s: got %s, want %s", c.Name, got, c.Expect)
			continue
		}
		if c.Result != nil {
			w, _ := json.Marshal(c.Result)
			g, _ := json.Marshal(res)
			var wv, gv any
			json.Unmarshal(w, &wv)
			json.Unmarshal(g, &gv)
			w, _ = json.Marshal(wv)
			g, _ = json.Marshal(gv)
			if !bytes.Equal(w, g) {
				t.Errorf("%s: result %s, want %s", c.Name, g, w)
			}
		}
	}
}
