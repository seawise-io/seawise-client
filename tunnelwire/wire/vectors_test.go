package wire

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/seawise-io/seawise-client/tunnelwire/internal/vkeys"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
)

func TestVectorsUpToDate(t *testing.T) {
	update := os.Getenv("UPDATE_VECTORS") == "1"
	for name, f := range map[string]vfile{"control_frames.json": genControlFrames(), "stream_header.json": genStreamHeader()} {
		ok, err := vkeys.Sync(name, vkeys.Pretty(f), update)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Errorf("%s is out of date; run with UPDATE_VECTORS=1", name)
		}
	}
}

func loadVectors(t *testing.T, name string) vfile {
	t.Helper()
	b, err := vkeys.Load(name)
	if err != nil {
		t.Fatal(err)
	}
	var f vfile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) == 0 {
		t.Fatal("no cases")
	}
	return f
}

func codeString(err error) string {
	if err == nil {
		return "ok"
	}
	if c := CodeOf(err); c != "" {
		return string(c)
	}
	return "uncoded: " + err.Error()
}

// runControl reads every frame of in and decodes it as the vectors
// describe, returning the steps and the first error.
func runControl(in []byte, from Peer, layer string) ([]step, error) {
	r := NewControlReader(bytes.NewReader(in), nil)
	var seq SeqIn
	var steps []step
	for {
		b, err := r.Next()
		if err == io.EOF {
			return steps, nil
		}
		if err != nil {
			return steps, err
		}
		if layer == "frame" {
			continue
		}
		m, err := DecodeControl(b, from)
		if err != nil && CodeOf(err) != CodeUnsupported {
			return steps, err
		}
		if serr := seq.Accept(m.Seq); serr != nil {
			return steps, serr
		}
		if err != nil {
			return append(steps, step{Seq: m.Seq}), err
		}
		steps = append(steps, step{Kind: protoKind(m.Body), Seq: m.Seq})
	}
}

func TestControlFrameVectors(t *testing.T) {
	for _, c := range loadVectors(t, "control_frames.json").Cases {
		in, err := base64.StdEncoding.DecodeString(c.Input)
		if err != nil {
			t.Fatal(err)
		}
		from := FromAgent
		if c.Context["from"] == "edge" {
			from = FromEdge
		}
		steps, err := runControl(in, from, c.Context["layer"].(string))
		if got := codeString(err); got != c.Expect {
			t.Errorf("%s: got %s, want %s", c.Name, got, c.Expect)
			continue
		}
		if c.Result != nil {
			if want, got := normJSON(c.Result), normJSON(steps); want != got {
				t.Errorf("%s: steps %s, want %s", c.Name, got, want)
			}
		}
	}
}

func TestStreamHeaderVectors(t *testing.T) {
	for _, c := range loadVectors(t, "stream_header.json").Cases {
		in, err := base64.StdEncoding.DecodeString(c.Input)
		if err != nil {
			t.Fatal(err)
		}
		var result any
		switch {
		case c.Context["kind"] == "reply":
			var code pb.ReplyCode
			code, err = ReadStreamReply(bytes.NewReader(in))
			if err == nil {
				result = code.String()
			}
		case c.Context["layer"] == "frame":
			_, err = readFrame16(bytes.NewReader(in), MaxHeader, "header")
		default:
			var caps []string
			for _, v := range c.Context["capabilities"].([]any) {
				caps = append(caps, v.(string))
			}
			var h *pb.StreamHeader
			h, err = ReadStreamHeader(bytes.NewReader(in), caps)
			if err == nil {
				result = headerResultOf(h)
			}
		}
		if got := codeString(err); got != c.Expect {
			t.Errorf("%s: got %s, want %s", c.Name, got, c.Expect)
			continue
		}
		if c.Result != nil {
			if want, got := normJSON(c.Result), normJSON(result); want != got {
				t.Errorf("%s: result %s, want %s", c.Name, got, want)
			}
		}
	}
}

// normJSON renders v with object members sorted.
func normJSON(v any) string {
	b, _ := json.Marshal(v)
	var x any
	_ = json.Unmarshal(b, &x)
	out, _ := json.Marshal(x)
	return string(out)
}
