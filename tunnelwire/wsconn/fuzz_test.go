package wsconn

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// FuzzWebSocketFraming feeds a message sequence encoded as
// type byte (odd = binary) || uint16 length || payload, repeated.
func FuzzWebSocketFraming(f *testing.F) {
	f.Add([]byte{1, 0, 2, 'a', 'b', 0, 0, 1, 'x'})
	f.Add([]byte{1, 0, 0})
	f.Fuzz(func(t *testing.T, in []byte) {
		var msgs []msg
		var want []byte
		text := false
		for len(in) >= 3 {
			n := int(in[1])<<8 | int(in[2])
			typ := in[0]
			in = in[3:]
			n = min(n, len(in))
			msgs = append(msgs, msg{binary: typ%2 == 1, data: in[:n]})
			if !text {
				if typ%2 == 1 {
					want = append(want, in[:n]...)
				} else {
					text = true
				}
			}
			in = in[n:]
		}
		got, err := io.ReadAll(New(&fakeWS{in: msgs}))
		if !bytes.Equal(got, want) {
			t.Fatal("stream differs from the binary payloads")
		}
		if text != errors.Is(err, ErrTextMessage) {
			t.Fatalf("text %v err %v", text, err)
		}
		if !text && err != nil {
			t.Fatal(err)
		}
	})
}
