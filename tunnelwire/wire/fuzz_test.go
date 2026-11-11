package wire

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"testing"

	"google.golang.org/protobuf/proto"

	fx "github.com/seawise-io/seawise-client/tunnelwire/internal/fixtures"
	"github.com/seawise-io/seawise-client/tunnelwire/internal/vkeys"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
)

func seed(f *testing.F, name string) {
	for _, c := range loadVectorsF(f, name).Cases {
		b, err := base64.StdEncoding.DecodeString(c.Input)
		if err != nil {
			f.Fatal(err)
		}
		if len(b) < 70000 {
			f.Add(b)
		}
	}
}

func loadVectorsF(f *testing.F, name string) vfile {
	var out vfile
	b, err := vkeys.Load(name)
	if err != nil {
		f.Fatal(err)
	}
	if err := json.Unmarshal(b, &out); err != nil {
		f.Fatal(err)
	}
	return out
}

func coded(t *testing.T, err error) {
	t.Helper()
	if err != nil && CodeOf(err) == "" {
		t.Fatalf("uncoded error %v", err)
	}
}

func FuzzControlFrame(f *testing.F) {
	seed(f, "control_frames.json")
	f.Fuzz(func(t *testing.T, in []byte) {
		r := NewControlReader(bytes.NewReader(in), nil)
		for {
			b, err := r.Next()
			if err == io.EOF {
				return
			}
			if err != nil {
				coded(t, err)
				return
			}
			if len(b) == 0 || len(b) > MaxControlMessage {
				t.Fatalf("frame of %d bytes", len(b))
			}
			for _, from := range []Peer{FromAgent, FromEdge} {
				m, err := DecodeControl(b, from)
				coded(t, err)
				if err != nil {
					continue
				}
				std := &pb.ControlMessage{}
				if proto.Unmarshal(b, std) != nil || !proto.Equal(std, m) {
					t.Fatal("strict and standard decoding differ")
				}
				re, err := EncodeControl(m, from)
				if err != nil {
					t.Fatalf("accepted message does not re-encode: %v", err)
				}
				m2, err := DecodeControl(re, from)
				if err != nil || !proto.Equal(m, m2) {
					t.Fatal("round trip changed the message")
				}
			}
		}
	})
}

func FuzzHelloBody(f *testing.F) {
	f.Add(mustMarshal(fx.HelloBody()))
	f.Add(mustMarshal(fx.HelloAckBody([]byte("x"))))
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := DecodeHelloBody(b)
		coded(t, err)
		if err == nil {
			if re, err := EncodeHelloBody(h); err != nil || !bytes.Equal(re, mustMarshal(h)) {
				t.Fatal("accepted body does not re-encode")
			}
		}
		a, err := DecodeHelloAckBody(b)
		coded(t, err)
		if err == nil {
			if _, err := EncodeHelloAckBody(a); err != nil {
				t.Fatal("accepted ack body does not re-encode")
			}
		}
	})
}

func FuzzStreamHeader(f *testing.F) {
	seed(f, "stream_header.json")
	f.Fuzz(func(t *testing.T, in []byte) {
		for _, caps := range [][]string{nil, {CapRawTCP}} {
			h, err := ReadStreamHeader(bytes.NewReader(in), caps)
			coded(t, err)
			if err != nil {
				continue
			}
			if len(h.ClientIp) != 4 && len(h.ClientIp) != 16 || len(h.AppId) != 16 || len(h.VisitorToken) > MaxVisitorToken {
				t.Fatal("accepted header breaks a cap")
			}
			if h.Type == pb.StreamType_RAW_TCP && caps == nil {
				t.Fatal("RAW_TCP accepted without the capability")
			}
			f, err := AppendStreamHeader(nil, h, caps)
			if err != nil {
				t.Fatalf("accepted header does not re-encode: %v", err)
			}
			h2, err := ReadStreamHeader(bytes.NewReader(f), caps)
			if err != nil || !proto.Equal(h, h2) {
				t.Fatal("round trip changed the header")
			}
		}
	})
}

func FuzzStreamReply(f *testing.F) {
	seed(f, "stream_header.json")
	f.Fuzz(func(t *testing.T, in []byte) {
		c, err := ReadStreamReply(bytes.NewReader(in))
		coded(t, err)
		if err == nil {
			if c < pb.ReplyCode_ACCEPTED || c > pb.ReplyCode_BAD_HEADER {
				t.Fatalf("accepted code %d", c)
			}
			if _, err := AppendStreamReply(nil, c); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func FuzzRelayPrefix(f *testing.F) {
	ok, _ := AppendRelayPrefix(nil, &pb.RelayPrefix{Version: 1, ServerId: fx.UUID(fx.Server1), ExpectedEpoch: 3, IngressEdgeId: fx.EdgeA, Hop: 1})
	f.Add(ok)
	f.Add([]byte{0, 0})
	f.Fuzz(func(t *testing.T, in []byte) {
		p, err := ReadRelayPrefix(bytes.NewReader(in), fx.EdgeA)
		coded(t, err)
		if err == nil {
			if p.Hop != 1 || p.IngressEdgeId != fx.EdgeA || p.Version != 1 || len(p.ServerId) != 16 {
				t.Fatal("accepted a bad prefix")
			}
			if _, err := AppendRelayPrefix(nil, p); err != nil {
				t.Fatal(err)
			}
		}
	})
}
