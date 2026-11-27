package testedge

import (
	"bufio"
	"bytes"
	"crypto/sha1" //nolint:gosec // G505: RFC 6455 fixes SHA-1 for the accept value
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/seawise-io/seawise-client/tunnelwire/wire"
)

const (
	opBinary = 0x2
	opClose  = 0x8
)

func acceptValue(key string) string {
	h := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")) //nolint:gosec // G401: RFC 6455
	return base64.StdEncoding.EncodeToString(h[:])
}

// readUpgrade reads the one upgrade request of the carriage.
func readUpgrade(br *bufio.Reader) (string, bool) {
	var key string
	path := false
	for i := 0; ; i++ {
		l, err := br.ReadString('\n')
		if err != nil || i > 32 {
			return "", false
		}
		if i == 0 {
			path = strings.HasPrefix(l, "GET "+wire.WebSocketPath+" HTTP/1.1")
		}
		if l == "\r\n" {
			break
		}
		if k, ok := strings.CutPrefix(l, "Sec-WebSocket-Key: "); ok {
			key = strings.TrimSuffix(k, "\r\n")
		}
	}
	return key, path && key != ""
}

// serverWS is the edge end of the carriage: masked frames in, unmasked
// out, one message per write.
type serverWS struct {
	c   net.Conn
	br  *bufio.Reader
	wmu sync.Mutex
}

func (s *serverWS) NextReader() (bool, io.Reader, error) {
	var h [2]byte
	if _, err := io.ReadFull(s.br, h[:]); err != nil {
		return false, nil, err
	}
	if h[0]&0x0f == opClose {
		return false, nil, io.EOF
	}
	if h[1]&0x80 == 0 || h[0]&0x0f != opBinary || h[0]&0x80 == 0 {
		return false, nil, errors.New("testedge: unexpected WebSocket frame")
	}
	n := uint64(h[1] & 0x7f)
	switch n {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(s.br, b[:]); err != nil {
			return false, nil, err
		}
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(s.br, b[:]); err != nil {
			return false, nil, err
		}
		n = binary.BigEndian.Uint64(b[:])
	}
	if n > wire.MaxWebSocketMsg {
		return false, nil, errors.New("testedge: WebSocket message too large")
	}
	var k [4]byte
	if _, err := io.ReadFull(s.br, k[:]); err != nil {
		return false, nil, err
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(s.br, p); err != nil {
		return false, nil, err
	}
	for i := range p {
		p[i] ^= k[i&3]
	}
	return true, bytes.NewReader(p), nil
}

func (s *serverWS) WriteBinary(p []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	hdr := []byte{0x80 | opBinary}
	switch n := len(p); {
	case n < 126:
		hdr = append(hdr, byte(n))
	case n < 1<<16:
		hdr = append(hdr, 126)
		hdr = binary.BigEndian.AppendUint16(hdr, uint16(n)) //nolint:gosec // G115: checked above
	default:
		hdr = append(hdr, 127)
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(n))
	}
	_, err := s.c.Write(append(hdr, p...))
	return err
}

func (s *serverWS) Close() error { return s.c.Close() }
